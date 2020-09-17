import base64
import dataclasses
import json
import re
import time
import urllib.parse
from typing import Any, Callable, List, Optional, Pattern

import molten.validation.common
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from gluetool.utils import normalize_bool_option
from molten import Request, Response
from molten.errors import HTTPError
from molten.http.status_codes import HTTP_200

from .. import Failure, Knob
from ..db import DB, SafeQuery, User, UserRoles
from ..metrics import APIMetrics
from . import errors

GUEST_ROUTE_PATTERN = re.compile(
    r'^/(?P<version>(?:current|v\d+\.\d+\.\d+)/)?guests/[a-z0-9-]+(?P<url_rest>/(events|snapshots))?$'
)
SNAPSHOT_ROUTE_PATTERN = re.compile(
    r'^/(?P<version>(?:current|v\d+\.\d+\.\d+)/)?guests/[a-z0-9-]+/snapshots/[a-z0-9-]+(?P<url_rest>/.+)?$'
)


NO_AUTH = [
    re.compile(r'/_docs(?:/.+)?'),
    re.compile(r'/_schema(?:/.+)?'),
    re.compile(r'/metrics')
]

PROVISIONING_AUTH = [
    re.compile(r'/guests(?:/.+)?')
]

ADMIN_AUTH = [
    re.compile(r'/users(?:/.+)?')
]


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

#: This header is added by our authorization middleware, to transport an auth context to route handlers.
#:
#: Note that user may specify its own value, but that shouldn't matter, because our middleware
#: overwrites the provided value with our own string, throwing whatever user tried to sneak in away.
#: Before every request, the middleware does its own tests, based entirely on provided credentials.
#:
#: This solution is far from being perfect, but I do not know how to transport the auth context
#: down to handlers, in a Molten way, e.g. using dependency injection. Looking at things, I always
#: get down to the fact that I need to attach something to a request, and ``Request`` class is using
#: ``__slots__`` which means I cannot add any new attributes.
AUTH_CTX_HEADER = 'x-auth-ctx'


def matches_path(request: Request, patterns: List[Pattern[str]]) -> bool:
    return any((pattern.match(request.path) for pattern in patterns))


@dataclasses.dataclass
class AuthContext:
    request: Request

    is_authentication_enabled: bool
    is_authorization_enabled: bool

    is_empty: bool = True
    is_invalid_request: bool = False
    is_authenticated: bool = False
    is_authorized: bool = False

    username: Optional[str] = None
    token: Optional[str] = None

    user: Optional[User] = None

    _serialized_fields = (
        'is_authentication_enabled',
        'is_authorization_enabled',
        'is_empty',
        'is_invalid_request',
        'is_authenticated',
        'is_authorized',
        'username'
    )

    def serialize(self) -> str:
        return json.dumps({
            field: getattr(self, field)
            for field in self._serialized_fields
        })

    @classmethod
    def unserialize(cls, serialized: str, request: Request) -> 'AuthContext':
        unserialized = json.loads(serialized)

        ctx = AuthContext(
            request=request,
            is_authentication_enabled=unserialized['is_authentication_enabled'],
            is_authorization_enabled=unserialized['is_authorization_enabled']
        )

        for field in AuthContext._serialized_fields:
            setattr(ctx, field, unserialized[field])

        return ctx

    def inject(self) -> None:
        """
        Inject the context into a request, i.e. serialize the context, and store it in request headers.
        """

        # By this, we throw away whatever user might have tried to sneak in.
        self.request.headers.add(AUTH_CTX_HEADER, self.serialize())

    @classmethod
    def extract(cls, request: Request) -> Result['AuthContext', Failure]:
        """
        Extract the context from a requst, i.e. find the corresponding header, and unserialize its content.
        """

        serialized_ctx = request.headers.get(AUTH_CTX_HEADER)

        if serialized_ctx is None:
            return Error(Failure(
                'undefined auth context',
                request_path=request.path
            ))

        return Ok(AuthContext.unserialize(serialized_ctx, request))

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

        if not username or not password:
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
        assert self.token is not None

        r_user = SafeQuery.from_session(session, User) \
            .filter(User.username == self.username) \
            .one_or_none()

        if r_user.is_error:
            raise errors.InternalServerError(caused_by=r_user.unwrap_error())

        user = r_user.unwrap()

        if not user:
            return

        if token_type == 'provisioning' and user.provisioning_token == User.hash_token(self.token):
            self.user = user
            self.is_authenticated = True
            return

        if token_type == 'admin' and user.admin_token == User.hash_token(self.token):
            self.user = user
            self.is_authenticated = True
            return

    def verify_auth(self, db: DB) -> None:
        if matches_path(self.request, NO_AUTH):
            self.is_authorized = True
            return

        with db.get_session() as session:
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
    def _authorization_middleware(request: Request, db: DB) -> Any:
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
            return handler()

        ctx.verify_auth(db)

        # Refresh stored state, to capture changes made by verification.
        ctx.inject()

        if ctx.is_invalid_request:
            raise errors.BadRequestError()

        # Enable this once all pieces are merged and authentication/authorization becomes mandatory.
        # if not ctx.is_authenticated:
        #     raise errors.UnauthorizedError()

        if not ctx.is_authorization_enabled:
            return handler()

        if not ctx.is_authorized:
            raise errors.UnauthorizedError()

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


def rewrite_request_path(path: str) -> str:
    """
    Rewrite given request path to replace all guest and snapshot names with ``GUESTNAME`` and ``SNAPSHOTNAME``
    strings. This is designed to avoid generating HTTP metrics per guest and per snapshot.

    :param str: request path to rewrite.
    """

    match = GUEST_ROUTE_PATTERN.match(path)
    if match is not None:
        groups = match.groupdict()

        return '/{}guests/GUESTNAME{}'.format(
            groups.get('version') or '',
            groups.get('url_rest') or ''
        )

    match = SNAPSHOT_ROUTE_PATTERN.match(path)
    if match is not None:
        groups = match.groupdict()

        return '/{}guests/GUESTNAME/snapshots/SNAPSHOTNAME{}'.format(
            groups.get('version') or '',
            groups.get('url_rest') or ''
        )

    return path


def prometheus_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def middleware(request: Request) -> Any:
        status = "500 Internal Server Error"

        start_time = time.monotonic()

        path = rewrite_request_path(request.path)

        APIMetrics.inc_requests_in_progress(request.method, path)

        try:
            response = handler()

            if isinstance(response, tuple):
                status = response[0]

            elif isinstance(response, Response):
                status = response.status

            # For JSON-like responses, use 200 because handler did not bother to provide better response,
            # like `DELETE` with its `204 No Content`.
            elif dataclasses.is_dataclass(response) or molten.validation.common.is_schema(response):
                status = HTTP_200

            return response

        except HTTPError as exc:
            status = exc.status

            raise

        finally:
            end_time = time.monotonic()

            APIMetrics.dec_requests_in_progress(request.method, path)
            APIMetrics.inc_requests(request.method, path, status)

            # Convert the difference from fractional seconds to milliseconds
            APIMetrics.inc_request_durations(request.method, path, (end_time - start_time) * 1000.0)

    return middleware
