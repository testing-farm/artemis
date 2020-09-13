import base64
import json
import re
import urllib.parse

import sqlalchemy.orm.session
from molten import Request, Response
from molten.contrib.prometheus import REQUEST_COUNT, REQUESTS_INPROGRESS

from . import errors
from .. import get_logger, get_db
from ..db import User, UserRoles

from typing import Any, Callable, List, Optional, Pattern, Tuple


NO_AUTH = [
    re.compile(r'/_docs(?:/.+)?'),
    re.compile(r'/_schema(?:/.+)?'),
    re.compile(r'/metrics')
]

PROVISIONING_AUTH = [
    re.compile(r'/guests(?:/.+)?')
]

ADMIN_AUTH = [
    re.compile(r'/users')
]


def matches_path(request: Request, patterns: List[Pattern[str]]) -> bool:
    return any((pattern.match(request.path) for pattern in patterns))


def _extract_credentials_basic(request: Request) -> Tuple[str, str]:
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        raise errors.NotAuthorizedError()

    if not auth_header.startswith('Basic'):
        raise errors.NotAuthorizedError()

    header_split = auth_header.strip().split(' ')

    def _decode(payload: str) -> Tuple[str, str]:
        username, password = base64.b64decode(payload).decode().split(':', 1)

        return username, password

    if len(header_split) == 1:
        try:
            username, password = _decode(header_split[0])

        except Exception:
            raise errors.BadRequestError()

    elif len(header_split) == 2:
        if header_split[0].strip().lower() != 'basic':
            raise errors.BadRequestError()

        try:
            username, password = _decode(header_split[1])

        except Exception:
            raise errors.BadRequestError()

    else:
        raise errors.BadRequestError()

    return urllib.parse.unquote(username), urllib.parse.unquote(password)


def verify_basic(
    session: sqlalchemy.orm.session.Session,
    request: Request,
    token_type: str
) -> Optional[User]:
    username, token = _extract_credentials_basic(request)

    query = session \
        .query(User) \
        .filter(User.username == username)

    if token_type == 'provisioning':
        query = query.filter(User.provisioning_token == User.hash_token(token))

    elif token_type == 'admin':
        query = query.filter(User.admin_token == User.hash_token(token))

    else:
        assert False, 'unreachable'

    return query.one_or_none()


def authorization_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def middleware(request: Request) -> Any:
        if matches_path(request, NO_AUTH):
            return handler()

        with get_db(get_logger()).get_session() as session:
            if matches_path(request, PROVISIONING_AUTH) and verify_basic(session, request, 'provisioning'):
                return handler()

            if matches_path(request, ADMIN_AUTH):
                user = verify_basic(session, request, 'admin')

                if not user:
                    raise errors.NotAuthorizedError()

                if user.role != UserRoles.ADMIN:
                    raise errors.NotAuthorizedError()

                return handler()

            raise errors.NotAuthorizedError()

    return middleware


def error_handler_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def middleware() -> Any:
        try:
            return handler()
        except errors.ArtemisHTTPError as error:
            return Response(
                status=error.status,
                content=json.dumps(error.response),
                headers=error.headers)
    return middleware


def prometheus_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    guest_route_pattern = re.compile(r'(/guests/)[a-z0-9-]*(/events)?')

    def middleware(request: Request) -> Any:
        status = "500 Internal Server Error"
        # this is needed so that metrics for each guestname route won't clog up metrics page
        # let's treat all /guest/<guestname> routes as the single one
        path = guest_route_pattern.sub(r'\1GUEST\2', request.path)
        requests_inprogress = REQUESTS_INPROGRESS.labels(request.method, path)
        requests_inprogress.inc()

        try:
            response = handler()
            status = response.status
            return response
        finally:
            requests_inprogress.dec()
            REQUEST_COUNT.labels(request.method, path, status).inc()
    return middleware
