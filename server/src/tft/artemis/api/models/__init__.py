# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import base64
import dataclasses
import datetime
import enum
import json
import re
import urllib.parse
from re import Pattern
from typing import Any, Optional

import gluetool.log
import sqlalchemy.orm.session
from fastapi import Request
from gluetool.result import Error, Ok, Result
from pydantic import BaseModel

from ... import Failure, db as artemis_db
from ...guest import GuestState
from ...security_group_rules import SecurityGroupRulesInput
from .. import errors

DEFAULT_EVENTS_PAGE = 1
DEFAULT_EVENTS_PAGE_SIZE = 20
DEFAULT_EVENTS_SORT_FIELD = 'updated'
DEFAULT_EVENTS_SORT_ORDER = 'desc'


NO_AUTH = [
    re.compile(r'(?:/v\d+\.\d+\.\d+)?/_docs(?:/.+)?'),
    re.compile(r'(?:/v\d+\.\d+\.\d+)?/_schema(?:/.+)?'),
    re.compile(r'(?:/v\d+\.\d+\.\d+)?/metrics'),
]

PROVISIONING_AUTH = [re.compile(r'(?:/v\d+\.\d+\.\d+)?/guests(?:/.+)?')]

ADMIN_AUTH = [re.compile(r'(?:/v\d+\.\d+\.\d+)?/users(?:/.+)?'), re.compile(r'(?:/v\d+\.\d+\.\d+)?/_status(?:/.+)?')]

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


def matches_path(request: Request, patterns: list[Pattern[str]]) -> bool:
    return any(pattern.match(request.url.path) for pattern in patterns)


def _add_to_headers(request: Request, new_data_tuple: tuple[str, Any]) -> None:
    # NOTE(ivasilev) fastapi's Request headers are immutable by default so copy -> add -> set & update scope
    key, value = new_data_tuple
    new_headers = request.headers.mutablecopy()
    new_headers[key] = value
    request._headers = new_headers
    request.scope.update(headers=request.headers.raw)


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

    user: Optional[artemis_db.User] = None

    _serialized_fields = (
        'is_authentication_enabled',
        'is_authorization_enabled',
        'is_empty',
        'is_invalid_request',
        'is_authenticated',
        'is_authorized',
        'username',
    )

    def serialize(self) -> str:
        return json.dumps({field: getattr(self, field) for field in self._serialized_fields})

    @classmethod
    def unserialize(cls, serialized: str, request: Request) -> 'AuthContext':
        unserialized = json.loads(serialized)

        ctx = AuthContext(
            request=request,
            is_authentication_enabled=unserialized['is_authentication_enabled'],
            is_authorization_enabled=unserialized['is_authorization_enabled'],
        )

        for field in AuthContext._serialized_fields:
            setattr(ctx, field, unserialized[field])

        return ctx

    def inject(self) -> None:
        """
        Inject the context into a request, i.e. serialize the context, and store it in request headers.
        """

        # By this, we throw away whatever user might have tried to sneak in.
        _add_to_headers(self.request, (AUTH_CTX_HEADER, self.serialize()))

    @classmethod
    def extract(cls, request: Request) -> Result['AuthContext', Failure]:
        """
        Extract the context from a requst, i.e. find the corresponding header, and unserialize its content.
        """

        serialized_ctx = request.headers.get(AUTH_CTX_HEADER)

        if serialized_ctx is None:
            return Error(Failure('undefined auth context', request_path=request.url.path))

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

    def verify_auth_basic(self, session: sqlalchemy.orm.session.Session, token_type: str) -> None:
        self._extract_credentials_basic()

        if self.is_empty:
            return

        if self.is_invalid_request:
            return

        assert self.username is not None
        assert self.token is not None

        r_user = (
            artemis_db.SafeQuery.from_session(session, artemis_db.User)
            .filter(artemis_db.User.username == self.username)
            .one_or_none()
        )

        if r_user.is_error:
            raise errors.InternalServerError(caused_by=r_user.unwrap_error())

        user = r_user.unwrap()

        if not user:
            return

        if token_type == 'provisioning' and user.provisioning_token == artemis_db.User.hash_token(self.token):
            self.user = user
            self.is_authenticated = True
            return

        if token_type == 'admin' and user.admin_token == artemis_db.User.hash_token(self.token):
            self.user = user
            self.is_authenticated = True
            return

    def verify_auth(self, logger: gluetool.log.ContextAdapter, db: artemis_db.DB) -> None:
        if matches_path(self.request, NO_AUTH):
            self.is_authorized = True
            return

        from ..routers import get_session

        with get_session(logger, db, read_only=True) as (session, _):
            if matches_path(self.request, PROVISIONING_AUTH):
                self.verify_auth_basic(session, 'provisioning')

                if self.user and self.is_authenticated:
                    self.is_authorized = True
                    return

            if matches_path(self.request, ADMIN_AUTH):
                self.verify_auth_basic(session, 'admin')

                if self.user and self.is_authenticated and self.user.is_admin:
                    self.is_authorized = True
                    return


@dataclasses.dataclass
class GuestRequest:
    keyname: str
    environment: dict[str, Optional[Any]]
    priority_group: Optional[str] = None
    shelfname: Optional[str] = None
    user_data: Optional[artemis_db.UserDataType] = None
    post_install_script: Optional[str] = None
    # NOTE(ivasilev) Putting Any there instead of Tuple[str, str] as otherwise hitting
    # TypeError: Subscripted generics cannot be used with class and instance checks
    log_types: Optional[list[Any]] = None
    watchdog_dispatch_delay: Optional[int] = None
    watchdog_period_delay: Optional[int] = None
    bypass_shelf_lookup: bool = False
    skip_prepare_verify_ssh: bool = False
    security_group_rules_ingress: SecurityGroupRulesInput = None
    security_group_rules_egress: SecurityGroupRulesInput = None


class GuestSSHInfo(BaseModel):
    username: str
    port: int
    keyname: str


class GuestResponse(BaseModel):
    guestname: str
    owner: str
    shelf: Optional[str]
    environment: dict[str, Any]
    address: Optional[str]
    ssh: GuestSSHInfo
    state: GuestState
    state_mtime: Optional[datetime.datetime]
    mtime: datetime.datetime
    user_data: artemis_db.UserDataType
    skip_prepare_verify_ssh: Optional[bool]
    post_install_script: Optional[str]
    ctime: datetime.datetime
    console_url: Optional[str]
    console_url_expires: Optional[datetime.datetime]
    log_types: list[tuple[str, artemis_db.GuestLogContentType]]
    watchdog_dispatch_delay: Optional[int]
    watchdog_period_delay: Optional[int]

    poolname: Optional[str]
    last_poolname: Optional[str]

    @classmethod
    def from_db(cls, guest: artemis_db.GuestRequest) -> 'GuestResponse':
        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            shelf=guest.shelfname,
            environment=guest.environment.serialize(),
            address=guest.address,
            ssh=GuestSSHInfo(username=guest.ssh_username, port=guest.ssh_port, keyname=guest.ssh_keyname),
            state=GuestState(guest.state),
            state_mtime=guest.state_mtime,
            mtime=guest.mtime,
            user_data=guest.user_data,
            skip_prepare_verify_ssh=guest.skip_prepare_verify_ssh,
            post_install_script=guest.post_install_script,
            ctime=guest.ctime,
            console_url=guest.console_url,
            console_url_expires=guest.console_url_expires,
            log_types=guest.log_types,
            watchdog_dispatch_delay=guest.watchdog_dispatch_delay,
            watchdog_period_delay=guest.watchdog_period_delay,
            poolname=guest.poolname,
            last_poolname=guest.last_poolname,
        )


class GuestEvent(BaseModel):
    eventname: str
    guestname: str
    details: dict[str, Any]
    updated: datetime.datetime

    @classmethod
    def from_db(cls, event: artemis_db.GuestEvent) -> 'GuestEvent':
        return cls(eventname=event.eventname, guestname=event.guestname, details=event.details, updated=event.updated)


@dataclasses.dataclass
class GuestShelfResponse:
    shelfname: str
    owner: str

    @classmethod
    def from_db(cls, shelf: artemis_db.GuestShelf) -> 'GuestShelfResponse':
        return cls(shelfname=shelf.shelfname, owner=shelf.ownername)


@dataclasses.dataclass
class ConsoleUrlResponse:
    url: Optional[str]
    expires: Optional[datetime.datetime]


@dataclasses.dataclass
class KnobUpdateRequest:
    value: str


@dataclasses.dataclass
class KnobResponse:
    name: str
    value: Any
    help: str
    editable: bool
    cast: Optional[str]


class TokenTypes(enum.Enum):
    PROVISIONING = 'provisioning'
    ADMIN = 'admin'


@dataclasses.dataclass
class AboutResponse:
    package_version: str
    image_digest: Optional[str]
    image_url: Optional[str]
    artemis_deployment: Optional[str]
    artemis_deployment_environment: Optional[str]
    api_versions: list[str]


@dataclasses.dataclass
class EventSearchParameters:
    page: int = DEFAULT_EVENTS_PAGE
    page_size: int = DEFAULT_EVENTS_PAGE_SIZE
    sort_field: str = DEFAULT_EVENTS_SORT_FIELD
    sort_order: str = DEFAULT_EVENTS_SORT_ORDER
    since: Optional[str] = None
    until: Optional[str] = None

    @classmethod
    def from_request(cls, request: Request) -> 'EventSearchParameters':
        req_params = request.query_params
        params = EventSearchParameters()

        try:
            # req_params does not support `in` :/

            if req_params.get('page') is not None:
                params.page = int(req_params['page'])

            if req_params.get('page_size') is not None:
                params.page_size = int(req_params['page_size'])

            if req_params.get('sort_field') is not None:
                params.sort_field = req_params['sort_field']

                if params.sort_field not in filter(lambda x: not x.startswith('_'), artemis_db.GuestEvent.__dict__):
                    raise errors.BadRequestError(request=request)

            if req_params.get('sort_by') is not None:
                params.sort_order = req_params['sort_by']

                if params.sort_order not in ('asc', 'desc'):
                    raise errors.BadRequestError(request=request)

            # TODO: parse the value to proper date/time
            if req_params.get('since') is not None:
                params.since = req_params['since']

            if req_params.get('until') is not None:
                params.since = req_params['until']

        except (ValueError, AttributeError):
            raise errors.BadRequestError(request=request)

        return params


@dataclasses.dataclass
class CreateUserRequest:
    """
    Schema describing a request to create a new user account.
    """

    role: str


@dataclasses.dataclass
class UserResponse:
    """
    Schema describing a response to "inspect user" queries.
    """

    username: str
    role: artemis_db.UserRoles

    @classmethod
    def from_db(cls, user: artemis_db.User) -> 'UserResponse':
        return cls(
            username=user.username,
            role=artemis_db.UserRoles(user.role),
        )


@dataclasses.dataclass
class TokenResetResponse:
    """
    Schema describing a response to "reset token" requests.
    """

    tokentype: TokenTypes
    token: str


@dataclasses.dataclass
class GuestLogBlobResponse:
    ctime: datetime.datetime
    content: str


@dataclasses.dataclass
class GuestLogResponse:
    state: artemis_db.GuestLogState
    contenttype: artemis_db.GuestLogContentType

    url: Optional[str]
    blobs: list[GuestLogBlobResponse]

    updated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, log: artemis_db.GuestLog) -> 'GuestLogResponse':
        return cls(
            state=artemis_db.GuestLogState(log.state),
            contenttype=artemis_db.GuestLogContentType(log.contenttype),
            url=log.url,
            blobs=[GuestLogBlobResponse(ctime=blob.ctime, content=blob.content) for blob in log.blobs],
            updated=log.updated,
            expires=log.expires,
        )


class PreprovisioningRequest(BaseModel):
    count: int
    guest: GuestRequest
