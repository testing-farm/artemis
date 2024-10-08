# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
import os
import re
import time
from typing import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi import status as http_status
from gluetool.utils import normalize_bool_option
from starlette.middleware.base import BaseHTTPMiddleware

from .. import RSSWatcher
from ..db import DB
from ..knobs import Knob
from ..metrics import APIMetrics
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


# NOTE(ivasilev) As middlewares are handled at starlette level there is no way to use dependency injection at the
# moment https://github.com/tiangolo/fastapi/issues/402. This approach kinda works, although sneaking in db object this
# way is far from perfect that's the best we can get at the moment as to keep the old logic we absolutely rely on
# Authorization middleware to be called before actual routing as we expect context injection taking place at a certain
# moment and this can't be guaranteed with converting authorization middleware to a router-level dependency.
# However as siwalter has noticed if we require more than 1 parameter to be sneaked in this way current approach should
# be reconsidered towards passing a state object with db as one of the parameters.
class AuthorizationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI, db: DB = get_db(logger=get_logger())):
        super().__init__(app)
        self.db = db

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
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
            response = await call_next(request)
            return response

        ctx.verify_auth(logger, self.db)

        # Refresh stored state, to capture changes made by verification.
        ctx.inject()

        if ctx.is_invalid_request:
            raise errors.BadRequestError()

        # Enable this once all pieces are merged and authentication/authorization becomes mandatory.
        # if not ctx.is_authenticated:
        #     raise errors.UnauthorizedError()

        if not ctx.is_authorization_enabled:
            response = await call_next(request)
            return response

        if not ctx.is_authorized:
            raise errors.UnauthorizedError()

        response = await call_next(request)
        return response


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        try:
            response = await call_next(request)
            return response
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
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
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
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        logger = get_logger()

        request_info = f'{request.method} {request.scope["path"]} HTTP/{request.scope["http_version"]}'
        client_info = f'{request.scope["client"][0]}:{request.scope["client"][1]}'

        rss = RSSWatcher()

        logger.info(f'[{os.getpid()}] [{client_info}] [{request_info}] {rss.format()}')  # noqa: FS002

        try:
            return await call_next(request)

        finally:
            rss.snapshot()
            logger.info(f'[{os.getpid()}] [{client_info}] [{request_info}] {rss.format()}')  # noqa: FS002
