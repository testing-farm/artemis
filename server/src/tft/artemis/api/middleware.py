# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import json
import os
import re
import time
from typing import Awaitable, Callable, Optional, Tuple

import sentry_sdk
from fastapi import FastAPI, HTTPException, Request, Response, status as http_status
from gluetool.utils import normalize_bool_option
from starlette.middleware.base import BaseHTTPMiddleware as FastAPIBaseHTTPMiddleware

from .. import Failure, RSSWatcher, Sentry, TracingOp
from ..db import DB
from ..knobs import Knob
from ..metrics import APIMetrics
from ..profile import Profiler
from . import errors
from .dependencies import get_db, get_logger
from .models import AuthContext

GUEST_ROUTE_PATTERN = re.compile(
    r'^/(?P<version>(?:current|v\d+\.\d+\.\d+)/)?guests/[a-z0-9-]+(?P<url_rest>/(events|snapshots|logs/.+))?$'
)
SNAPSHOT_ROUTE_PATTERN = re.compile(
    r'^/(?P<version>(?:current|v\d+\.\d+\.\d+)/)?guests/[a-z0-9-]+/snapshots/[a-z0-9-]+(?P<url_rest>/.+)?$'
)


# A feature switches for authentication and authorization, disabled by default.
# The problem is, we don't have all the pieces for people to setup their users
# and tokens, yet, therefore it'd be hard to request they start using it right
# now. These knobs will change, eventually, to "enabled by default", as soon
# as we implement all the steps.

KNOB_API_ENABLE_AUTHENTICATION: Knob[bool] = Knob(
    'api.enable-authentication',
    'If enabled, API requests must pass authentication by providing proper username and token.',
    has_db=False,
    envvar='ARTEMIS_ENABLE_AUTHENTICATION',
    cast_from_str=normalize_bool_option,
    default=False
)

KNOB_API_ENABLE_AUTHORIZATION: Knob[bool] = Knob(
    'api.enable-authorization',
    """
    If enabled, API requests must pass authorization by providing username with privileges high enough
    for the requested action.
    """,
    has_db=False,
    envvar='ARTEMIS_ENABLE_AUTHORIZATION',
    cast_from_str=normalize_bool_option,
    default=False
)


class BaseHTTPMiddleware(FastAPIBaseHTTPMiddleware):
    def get_request_info(self, request: Request) -> Tuple[str, str]:
        client = request.scope.get('client')

        return (
            f'{request.method} {request.scope["path"]} HTTP/{request.scope["http_version"]}',
            f'{client[0] if client else "<unknown>"}:{client[1] if client else "<unknown>"}'
        )

    def get_request_label(self, request: Request) -> str:
        request_info, client_info = self.get_request_info(request)

        return f'[{os.getpid()}] [{client_info}] [{request_info}]'

    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        return await call_next(request)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        with Sentry.start_span(
            TracingOp.HTTP_SERVER,
            'api-request.middleware',
            tags={
                'midleware': self.__class__.__name__
            }
        ):
            return await self.do_dispatch(request, call_next)


# NOTE(ivasilev) As middlewares are handled at starlette level there is no way to use dependency injection at the
# moment https://github.com/tiangolo/fastapi/issues/402. This approach kinda works, although sneaking in db object this
# way is far from perfect that's the best we can get at the moment as to keep the old logic we absolutely rely on
# Authorization middleware to be called before actual routing as we expect context injection taking place at a certain
# moment and this can't be guaranteed with converting authorization middleware to a router-level dependency.
# However as siwalter has noticed if we require more than 1 parameter to be sneaked in this way current approach should
# be reconsidered towards passing a state object with db as one of the parameters.
class AuthorizationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, db: Optional[DB] = None) -> None:
        super().__init__(app)

        self.db = db or get_db(logger=get_logger())

    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        logger = get_logger()

        # We need context even when authentication and authorization are disabled: handlers request it,
        # and dependency injection must have something to give them.
        #
        # Once we make auth mandatory, it should be possible to initialize context after we realize
        # we're dealing with protected endpoint.
        ctx = AuthContext(
            request=request,
            is_authentication_enabled=KNOB_API_ENABLE_AUTHENTICATION.value,
            is_authorization_enabled=KNOB_API_ENABLE_AUTHORIZATION.value
        )

        ctx.inject()

        if not ctx.is_authentication_enabled:
            return await call_next(request)

        ctx.verify_auth(logger, self.db)

        # Refresh stored state, to capture changes made by verification.
        ctx.inject()

        if ctx.is_invalid_request:
            raise errors.BadRequestError

        # Enable this once all pieces are merged and authentication/authorization becomes mandatory.
        # if not ctx.is_authenticated:
        #     raise errors.UnauthorizedError()

        if not ctx.is_authorization_enabled:
            return await call_next(request)

        if not ctx.is_authorized:
            raise errors.UnauthorizedError

        return await call_next(request)


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        try:
            return await call_next(request)

        except errors.ArtemisHTTPError as error:
            return Response(
                status_code=error.status_code,
                content=json.dumps(error.detail),
                headers=error.headers)


def rewrite_request_path(path: str) -> str:
    """
    Rewrite given request path to replace all guest and snapshot names with ``GUESTNAME`` and ``SNAPSHOTNAME``
    strings. This is designed to avoid generating HTTP metrics per guest and per snapshot.

    :param str: request path to rewrite.
    """

    match = GUEST_ROUTE_PATTERN.match(path)
    if match is not None:
        groups = match.groupdict()

        return f'/{groups.get("version") or ""}guests/GUESTNAME{groups.get("url_rest") or ""}'

    match = SNAPSHOT_ROUTE_PATTERN.match(path)
    if match is not None:
        groups = match.groupdict()

        return f'/{groups.get("version") or ""}guests/GUESTNAME/snapshots/SNAPSHOTNAME{groups.get("url_rest") or ""}'

    return path


class PrometheusMiddleware(BaseHTTPMiddleware):
    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        status = "500 Internal Server Error"

        start_time = time.monotonic()

        path = rewrite_request_path(request.url.path)

        APIMetrics.inc_requests_in_progress(request.method, path)

        try:
            response = await call_next(request)

            if isinstance(response, tuple):
                status = response[0]

            elif isinstance(response, Response):
                status = str(response.status_code)

            # For JSON-like responses, use 200 because handler did not bother to provide better response,
            # like `DELETE` with its `204 No Content`.
            # FIXME XXX(ivasilev) Might need some attention
            elif dataclasses.is_dataclass(response):
                status = str(http_status.HTTP_200_OK)

            return response

        except HTTPException as exc:
            status = str(exc.status_code)

            raise

        finally:
            end_time = time.monotonic()

            APIMetrics.dec_requests_in_progress(request.method, path)
            APIMetrics.inc_requests(request.method, path, status)

            # Convert the difference from fractional seconds to milliseconds
            APIMetrics.inc_request_durations(request.method, path, (end_time - start_time) * 1000.0)


class RSSWatcherMiddleware(BaseHTTPMiddleware):
    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        logger = get_logger()

        request_label = self.get_request_label(request)

        rss = RSSWatcher()

        logger.info(f'{request_label} {rss.format()}')  # noqa: FS002

        try:
            return await call_next(request)

        finally:
            rss.snapshot()
            logger.info(f'{request_label} {rss.format()}')  # noqa: FS002


class ProfileMiddleware(BaseHTTPMiddleware):
    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        from . import API_PROFILE_PATH_PATTERN, KNOB_API_PROFILING_LIMIT, KNOB_API_VERBOSE_PROFILING

        if not API_PROFILE_PATH_PATTERN.match(request.scope["path"]):
            return await call_next(request)

        logger = get_logger()

        request_label = self.get_request_label(request)

        profiler = Profiler(verbose=KNOB_API_VERBOSE_PROFILING.value)
        profiler.start()

        logger.info(f'{request_label} profiling started')  # noqa: FS002

        try:
            return await call_next(request)

        finally:
            profiler.stop()

            logger.info(f'{request_label} profiling ended')  # noqa: FS002

            profiler.log(logger, f'{request_label} profiling report', limit=KNOB_API_PROFILING_LIMIT.value)


class TracingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        client = request.scope.get('client')

        with sentry_sdk.isolation_scope() as scope, Sentry.start_transaction(
            TracingOp.HTTP_SERVER,
            'api-request',
            scope=scope,
            data={
                'http.request.client':
                    f'{client[0] if client else "<unknown>"}:{client[1] if client else "<unknown>"}',
                'http.request.method': request.method,
                'http.request.path': request.scope['path']
            }
        ) as tracing_transaction:
            request.state.tracing_trace = tracing_transaction.trace_id
            request.state.tracing_scope = scope
            request.state.tracing_transaction = tracing_transaction

            return await super().dispatch(request, call_next)


class RequestCancelledMiddleware(BaseHTTPMiddleware):
    async def do_dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        _, client = self.get_request_info(request)

        logger = get_logger()

        start = datetime.datetime.utcnow()

        try:
            return await call_next(request)

        finally:
            if await request.is_disconnected():
                end = datetime.datetime.utcnow()

                Failure(
                    'client disconnected from API',
                    delay=str(end - start),
                    client=client,
                    path=request.scope['path']
                ).handle(logger)


MIDDLEWARE = {
    'request-cancelled': RequestCancelledMiddleware,
    'authorization': AuthorizationMiddleware,
    'prometheus': PrometheusMiddleware,
    'rss-watcher': RSSWatcherMiddleware
}
