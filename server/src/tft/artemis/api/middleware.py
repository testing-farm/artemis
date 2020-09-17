import base64
import dataclasses
import json
import re
import urllib.parse

from gluetool.utils import normalize_bool_option
import sqlalchemy.orm.session
from molten import Request, Response
# To make mypy happy when others try `from api.middleware import REQUEST_COUNT`, explicit re-export is needed.
# See https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from molten.contrib.prometheus import REQUEST_COUNT as REQUEST_COUNT, REQUESTS_INPROGRESS as REQUESTS_INPROGRESS

from . import errors
from .. import get_logger, get_db, Knob
from ..db import User, UserRoles

from typing import Any, Callable, List, Optional, Pattern


NO_AUTH = [
    re.compile(r'/_docs(?:/.+)?'),
    re.compile(r'/_schema(?:/.+)?'),
    re.compile(r'/metrics')
]

PROVISIONING_AUTH = [
    re.compile(r'/guests(?:/.+)?')
]

ADMIN_AUTH: List[Pattern[str]] = []


# A feature switches for authentication and authorization, disabled by default.
# The problem is, we don't have all the pieces for people to setup their users
# and tokens, yet, therefore it'd be hard to request they start using it right
# now. These knobs will change, eventually, to "enabled by default", as soon
# as we implement all the steps.
KNOB_API_ENABLE_AUTHENTICATION: Knob[bool] = Knob(
    'api.enable-authentication',
    has_db=False,
    envvar='ARTEMIS_ENABLE_AUTHENTICATION',
    envvar_cast=normalize_bool_option,
    default=False
)

KNOB_API_ENABLE_AUTHORIZATION: Knob[bool] = Knob(
    'api.enable-authorization',
    has_db=False,
    envvar='ARTEMIS_ENABLE_AUTHORIZATION',
    envvar_cast=normalize_bool_option,
    default=False
)


def matches_path(request: Request, patterns: List[Pattern[str]]) -> bool:
    return any((pattern.match(request.path) for pattern in patterns))


@dataclasses.dataclass
class AuthVerification:
    request: Request

    is_empty: bool = True
    is_invalid_request: bool = False
    is_authenticated: bool = False
    is_authorized: bool = False

    username: Optional[str] = None
    token: Optional[str] = None

    user: Optional[User] = None

    def _extract_credentials_basic(self) -> None:
        # HTTP header looks like this: `Authorization: Basic credentials`, where `credentials
        # is base64 encoded username and password, joined by a colon (`username:password`).

        auth_header = self.request.headers.get('Authorization')

        if not auth_header:
            return

        self.is_empty = False

        header_split = auth_header.strip().split(' ', 1)

        if len(header_split) != 2:
            self.is_invalid_request = True
            return

        if header_split[0].strip().lower() != 'basic':
            self.is_invalid_request = True
            return

        try:
            username, password = base64.b64decode(header_split[1]).decode().split(':', 1)

        except Exception:
            self.is_invalid_request = True
            return

        try:
            self.username, self.token = urllib.parse.unquote(username), urllib.parse.unquote(password)

        except Exception:
            self.is_invalid_request = True

    def verify_auth_basic(
        self,
        session: sqlalchemy.orm.session.Session,
        token_type: str
    ) -> None:
        self._extract_credentials_basic()

        if self.is_empty:
            return

        if self.is_invalid_request:
            return

        assert self.username is not None

        user = User.fetch_by_username(session, self.username)

        if not user:
            return

        if token_type == 'provisioning' and user.provisioning_token == self.token:
            self.user = user
            self.is_authenticated = True
            return

        if token_type == 'admin' and user.admin_token == self.token:
            self.user = user
            self.is_authenticated = True

    def verify_auth(self) -> None:
        if matches_path(self.request, NO_AUTH):
            self.is_authorized = True
            return

        with get_db(get_logger()).get_session() as session:
            if matches_path(self.request, PROVISIONING_AUTH):
                self.verify_auth_basic(session, 'provisioning')

                if self.user and self.is_authenticated:
                    self.is_authorized = True
                    return

            if matches_path(self.request, ADMIN_AUTH):
                self.verify_auth_basic(session, 'admin')

                if self.user and self.is_authenticated and self.user.role == UserRoles.ADMIN:
                    self.is_authorized = True
                    return


def authorization_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def _authorization_middleware(request: Request) -> Any:
        if not KNOB_API_ENABLE_AUTHENTICATION.value:
            return handler()

        state = AuthVerification(request=request)
        state.verify_auth()

        if state.is_invalid_request:
            raise errors.BadRequestError()

        # We somehow need to pass `state.user` to those handling the request. No idea
        # how, but e.g. `POST /guests/` needs to know who's requesting the new guest.

        if not KNOB_API_ENABLE_AUTHORIZATION.value:
            return handler()

        if not state.is_authorized:
            raise errors.NotAuthorizedError()

        return handler()

    return _authorization_middleware


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
