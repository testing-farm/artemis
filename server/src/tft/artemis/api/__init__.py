# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import enum
import functools
import inspect
import json
import os
import platform
import shutil
import sys
import threading
import uuid
from inspect import Parameter
from typing import Any, Callable, Dict, List, NoReturn, Optional, Tuple, Type, Union

import gluetool.log
import gluetool.utils
import molten
import molten.components
import molten.dependency_injection
import molten.openapi
import molten.typing
import redis
import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.orm.exc
from gluetool.result import Ok
from molten import HTTP_200, HTTP_201, HTTP_202, HTTP_204, Include, Request, Response, Route
from molten.app import BaseApp
# from molten.contrib.prometheus import prometheus_middleware
from molten.middleware import ResponseRendererMiddleware
from molten.openapi.handlers import OpenAPIHandler as _OpenAPIHandler
from molten.openapi.handlers import OpenAPIUIHandler
from molten.typing import Middleware
from prometheus_client import CollectorRegistry
from typing_extensions import Protocol

from .. import __VERSION__, Failure, FailureDetailsType, JSONSchemaType
from .. import db as artemis_db
from .. import get_cache, get_db, get_logger, load_validation_schema, log_dict_yaml, metrics, validate_data
from ..cache import get_cache_value, iter_cache_keys
from ..context import DATABASE, LOGGER, SESSION
from ..drivers import PoolDriver
from ..environment import Environment
from ..guest import GuestState
from ..knobs import KNOB_DEPLOYMENT, KNOB_DEPLOYMENT_ENVIRONMENT, KNOB_LOGGING_JSON, \
    KNOB_WORKER_PROCESS_METRICS_ENABLED, KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK, Knob
from ..script import hook_engine
from ..tasks import Actor, TaskCall, _get_ssh_key, get_snapshot_logger
from . import errors
from .middleware import AuthContext, authorization_middleware, error_handler_middleware, prometheus_middleware

DEFAULT_GUEST_REQUEST_OWNER = 'artemis'

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USERNAME = 'root'

DEFAULT_EVENTS_PAGE = 1
DEFAULT_EVENTS_PAGE_SIZE = 20
DEFAULT_EVENTS_SORT_FIELD = 'updated'
DEFAULT_EVENTS_SORT_ORDER = 'desc'


KNOB_API_PROCESSES: Knob[int] = Knob(
    'api.processes',
    'Number of processes to spawn for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_PROCESSES',
    cast_from_str=int,
    default=1
)

KNOB_API_THREADS: Knob[int] = Knob(
    'api.threads',
    'Number of threads to spawn in each process for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_THREADS',
    cast_from_str=int,
    default=1
)

KNOB_API_ENABLE_PROFILING: Knob[bool] = Knob(
    'api.profiling.enabled',
    'If enabled, API server will profile handling of each request, emitting a summary into log.',
    has_db=False,
    envvar='ARTEMIS_API_ENABLE_PROFILING',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_PROFILE_LIMIT: Knob[int] = Knob(
    'api.profiling.limit',
    'How many functions should be included in the summary.',
    has_db=False,
    envvar='ARTEMIS_API_PROFILING_LIMIT',
    cast_from_str=int,
    default=20
)

KNOB_API_ENGINE_RELOAD_ON_CHANGE: Knob[bool] = Knob(
    'api.engine.reload-on-change',
    'Reload API server when its code changes.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_ON_CHANGE',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_ENGINE_DEBUG: Knob[bool] = Knob(
    'api.engine.debug',
    'Run engine with a debugging enabled.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_DEBUG',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS: Knob[int] = Knob(
    'api.engine.reload.request-limit',
    'Reload a worker process after serving this number of requests.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT',
    cast_from_str=int,
    default=0
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD: Knob[int] = Knob(
    'api.engine.reload.request-limit.spread',
    'A range by which is number of requests randomized.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT_SPREAD',
    cast_from_str=int,
    default=0
)

#: Protects our metrics tree when updating & rendering to user.
METRICS_LOCK = threading.Lock()


# Will be filled with the actual schema during API server bootstrap.
ENVIRONMENT_SCHEMAS: Dict[str, JSONSchemaType] = {}


def _validate_environment(
    logger: gluetool.log.ContextAdapter,
    environment: Any,
    schema: JSONSchemaType,
    failure_details: FailureDetailsType
) -> Environment:
    r_validation = validate_data(environment, schema)

    if r_validation.is_error:
        raise errors.InternalServerError(
            logger=logger,
            caused_by=r_validation.unwrap_error(),
            failure_details=failure_details
        )

    validation_errors = r_validation.unwrap()

    if validation_errors:
        failure_details['api_request_validation_errors'] = json.dumps(validation_errors)

        raise errors.BadRequestError(
            response={
                'message': 'Bad request',
                'errors': validation_errors
            },
            logger=logger,
            failure_details=failure_details
        )

    try:
        return Environment.unserialize(environment)

    except Exception as exc:
        raise errors.BadRequestError(
            response={
                'message': 'Bad request'
            },
            logger=logger,
            caused_by=Failure.from_exc('failed to parse environment', exc),
            failure_details=failure_details
        )


class JSONRenderer(molten.JSONRenderer):
    """
    Custom renderer, capable of handling :py:class:`datetime.datetime` and :py:class:`enum.Enum` instances
    we use frequently in our responses.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime.datetime):
            return str(obj)

        if isinstance(obj, enum.Enum):
            return obj.value

        return super().default(obj)


class SchemaComponent(molten.components.SchemaComponent):
    """
    A component that validates request data according to a schema.

    Derived from Molten's class, so we could raise our custom exception with our custom logging.
    """

    def resolve(
        self,
        parameter: inspect.Parameter,
        data: molten.typing.RequestData
    ) -> Any:
        try:
            return super().resolve(parameter, data)

        except molten.errors.HTTPError as exc:
            raise errors.BadRequestError(
                response={
                    'message': 'Bad request',
                    'errors': exc.response
                }
            )


class LoggerComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, logger: gluetool.log.ContextAdapter) -> None:
        self.logger = logger

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is gluetool.log.ContextAdapter

    def resolve(self) -> gluetool.log.ContextAdapter:
        return self.logger


class TokenTypes(enum.Enum):
    PROVISIONING = 'provisioning'
    ADMIN = 'admin'


class DBComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is artemis_db.DB

    def resolve(self) -> artemis_db.DB:
        return self.db


class MetricsComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, metrics_tree: 'metrics.Metrics') -> None:
        self.metrics_tree = metrics_tree

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is metrics.Metrics or parameter.annotation == 'metrics.Metrics'

    def resolve(self) -> 'metrics.Metrics':
        return self.metrics_tree


class CacheComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, cache: redis.Redis) -> None:
        self.cache = cache

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is redis.Redis

    def resolve(self) -> redis.Redis:
        return self.cache


class AuthContextComponent:
    """
    Makes auth context accessible to request handlers.

    WARNING: given that authentication and authorization are TEMPORARILY optional, and disabled by default,
    each handler that requires auth context MUST test the state of authentication/authorization, and deal
    appropriately when any of them is disabled. This may require using default usernames or allow access
    to everyone, but that is acceptable - once all pieces are merged, this optionality will be removed, and
    the mere fact the handler is running would mean the auth middleware succeeded - otherwise, auth middleware
    would have interrupted the chain, e.g. by returning HTTP 401.
    """

    is_cacheable = True
    is_singleton = False

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is AuthContext

    def resolve(self, request: Request, logger: gluetool.log.ContextAdapter) -> AuthContext:
        r_ctx = AuthContext.extract(request)

        # If the context does not exist, it means we have a handler that requests it, by adding
        # corresponding parameter, but auth middleware did not create it - the most likely chance
        # is the handler takes care of path that is marked as "auth not needed".
        if r_ctx.is_error:
            failure = r_ctx.unwrap_error()

            failure.handle(logger)

            # We cannot continue: handler requires auth context, and we don't have any. It's not possible to
            # recover.
            raise Exception(failure.message)

        return r_ctx.unwrap()


def perform_safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    conflict_error: Union[
        Type[errors.ConflictError],
        Type[errors.NoSuchEntityError],
        Type[errors.InternalServerError]
    ] = errors.ConflictError,
    failure_details: Optional[FailureDetailsType] = None
) -> None:
    """
    Helper for handling :py:func:`safe_db_change` in the same manner. Performs the query and tests the result:

    * raise ``500 Internal Server Error`` if the change failed,
    * raise ``conflict_error`` if the query didn't fail but changed no records,
    * do nothing and return when the query didn't fail and changed expected number of records.
    """

    r_change = artemis_db.safe_db_change(logger, session, query)

    if r_change.is_error:
        raise errors.InternalServerError(
            logger=logger,
            caused_by=r_change.unwrap_error(),
            failure_details=failure_details
        )

    if not r_change.unwrap():
        raise conflict_error(logger=logger, failure_details=failure_details)


@molten.schema
class GuestRequest:
    keyname: str
    environment: Dict[str, Optional[Any]]
    priority_group: Optional[str]
    user_data: Optional[artemis_db.UserDataType]
    post_install_script: Optional[str]
    # NOTE(ivasilev) Putting Any there instead of Tuple[str, str] as otherwise hitting
    # TypeError: Subscripted generics cannot be used with class and instance checks
    log_types: Optional[List[Any]]
    skip_prepare_verify_ssh: bool = False


@molten.schema
class GuestSSHInfo:
    username: str
    port: int
    keyname: str

    def __init__(
        self,
        username: str,
        port: int,
        keyname: str
    ) -> None:
        self.username = username
        self.port = port
        self.keyname = keyname


@molten.schema
@dataclasses.dataclass
class GuestResponse:
    guestname: str
    owner: str
    environment: Dict[str, Any]
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
    log_types: List[Tuple[str, artemis_db.GuestLogContentType]]

    @classmethod
    def from_db(cls, guest: artemis_db.GuestRequest) -> 'GuestResponse':
        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            environment=guest.environment.serialize(),
            address=guest.address,
            ssh=GuestSSHInfo(
                guest.ssh_username,
                guest.ssh_port,
                guest.ssh_keyname
            ),
            state=GuestState(guest.state),
            state_mtime=guest.state_mtime,
            mtime=guest.mtime,
            user_data=guest.user_data,
            skip_prepare_verify_ssh=guest.skip_prepare_verify_ssh,
            post_install_script=guest.post_install_script,
            ctime=guest.ctime,
            console_url=guest.console_url,
            console_url_expires=guest.console_url_expires,
            log_types=guest.log_types
        )


@molten.schema
class GuestEvent:
    eventname: str
    guestname: str
    details: Dict[str, Any]
    updated: datetime.datetime

    def __init__(
        self,
        eventname: str,
        guestname: str,
        updated: datetime.datetime,
        details: Any
    ) -> None:
        self.eventname = eventname
        self.guestname = guestname
        self.details = details
        self.updated = updated

    @classmethod
    def from_db(cls, event: artemis_db.GuestEvent) -> 'GuestEvent':
        return cls(
            eventname=event.eventname,
            guestname=event.guestname,
            details=event.details,
            updated=event.updated
        )


@molten.schema
class SnapshotRequest:
    start_again: bool

    def __init__(
        self,
        start_again: bool,
    ) -> None:
        self.start_again = start_again


@molten.schema
@dataclasses.dataclass
class SnapshotResponse:
    snapshotname: str
    guestname: str
    state: GuestState

    @classmethod
    def from_db(cls, snapshot_request: artemis_db.SnapshotRequest) -> 'SnapshotResponse':
        return cls(
            snapshotname=snapshot_request.snapshotname,
            guestname=snapshot_request.guestname,
            state=GuestState(snapshot_request.state)
        )


@molten.schema
@dataclasses.dataclass
class ConsoleUrlResponse:
    url: Optional[str]
    expires: Optional[datetime.datetime]


@molten.schema
@dataclasses.dataclass
class KnobUpdateRequest:
    value: str


@molten.schema
@dataclasses.dataclass
class KnobResponse:
    name: str
    value: Any
    help: str
    editable: bool
    cast: Optional[str]


@molten.schema
@dataclasses.dataclass
class AboutResponse:
    package_version: str
    image_digest: Optional[str]
    image_url: Optional[str]
    artemis_deployment: Optional[str]
    artemis_deployment_environment: Optional[str]


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
        req_params = request.params
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


@molten.schema
@dataclasses.dataclass
class CreateUserRequest:
    """
    Schema describing a request to create a new user account.
    """

    role: str


@molten.schema
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


@molten.schema
@dataclasses.dataclass
class TokenResetResponse:
    """
    Schema describing a response to "reset token" requests.
    """

    tokentype: TokenTypes
    token: str


class GuestRequestManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    def get_guest_requests(self) -> List[GuestResponse]:
        with self.db.get_session() as session:
            r_guests = artemis_db.SafeQuery.from_session(session, artemis_db.GuestRequest).all()

            if r_guests.is_error:
                raise errors.InternalServerError(caused_by=r_guests.unwrap_error())

            return [
                GuestResponse.from_db(guest)
                for guest in r_guests.unwrap()
            ]

    def create(
        self,
        guest_request: GuestRequest,
        ownername: str,
        logger: gluetool.log.ContextAdapter,
        environment_schema: JSONSchemaType
    ) -> GuestResponse:
        from ..tasks import get_guest_logger
        from ..tasks.route_guest_request import route_guest_request

        guestname = str(uuid.uuid4())

        failure_details = {
            'guestname': guestname,
            'keyname': guest_request.keyname,
            'raw_environment': guest_request.environment
        }

        guest_logger = get_guest_logger('create-guest-request', logger, guestname)

        # Validate given environment specification
        environment = _validate_environment(
            guest_logger,
            guest_request.environment,
            environment_schema,
            failure_details
        )

        # COMPAT: v0.0.17, v0.0.18: `environment.arch` belongs to `environment.hw.arch`
        if 'arch' in guest_request.environment:
            guest_request.environment['hw'] = {
                'arch': guest_request.environment.pop('arch')
            }

        # Validate log_types
        log_types: List[Tuple[str, artemis_db.GuestLogContentType]] = []
        if guest_request.log_types:
            try:
                log_types = [(logtype, artemis_db.GuestLogContentType(contenttype))
                             for (logtype, contenttype) in guest_request.log_types]
            except Exception as exc:
                raise errors.BadRequestError(
                    message='Got an unsupported log type',
                    logger=logger,
                    caused_by=Failure.from_exc('cannot convert log type to GuestLogContentType object', exc),
                    failure_details=failure_details
                )

        with self.db.get_session(transactional=True) as session:
            SESSION.set(session)

            # Check whether key exists - still open to race condition, but the window is quite short,
            # and don't rely on this test when we actually create request. All we need here is a better
            # error message for user when they enter invalid key name.
            r_key = _get_ssh_key(ownername, guest_request.keyname)

            if r_key.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_key.unwrap_error(),
                    failure_details=failure_details
                )

            if r_key.unwrap() is None:
                raise errors.BadRequestError(
                    message='No such SSH key exists',
                    logger=guest_logger,
                    failure_details=failure_details
                )

            # Check whether pool exists - still open to race condition, but the window is quite short,
            # and we don't rely on this test when we actually create request. All we need here is a better
            # error message for user when they enter invalid pool name.
            if environment.pool is not None:
                r_pool = PoolDriver.load_or_none(guest_logger, session, environment.pool)

                if r_pool.is_error:
                    raise errors.InternalServerError(
                        logger=guest_logger,
                        caused_by=r_key.unwrap_error(),
                        failure_details=failure_details
                    )

                if r_pool.unwrap() is None:
                    raise errors.BadRequestError(
                        message='No such pool exists',
                        logger=guest_logger,
                        failure_details=failure_details
                    )

            create_guest_stmt = artemis_db.GuestRequest.create_query(
                guestname=guestname,
                environment=environment,
                ownername=DEFAULT_GUEST_REQUEST_OWNER,
                ssh_keyname=guest_request.keyname,
                ssh_port=DEFAULT_SSH_PORT,
                ssh_username=DEFAULT_SSH_USERNAME,
                priorityname=guest_request.priority_group,
                user_data=guest_request.user_data,
                skip_prepare_verify_ssh=guest_request.skip_prepare_verify_ssh,
                post_install_script=guest_request.post_install_script,
                log_types=log_types
            )

            r_create = artemis_db.execute_db_statement(guest_logger, session, create_guest_stmt)

            if r_create.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_create.unwrap_error(),
                    failure_details=failure_details
                )

            artemis_db.GuestRequest.log_event_by_guestname(
                guest_logger,
                session,
                guestname,
                'created',
                **{
                    'environment': environment.serialize(),
                    'user_data': guest_request.user_data
                }
            )

            r_task = artemis_db.TaskRequest.create(guest_logger, session, route_guest_request, guestname)

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            guest_logger.info('created')
            log_dict_yaml(
                guest_logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(route_guest_request, guestname, task_request_id=task_request_id).serialize()
            )

            # Everything went well, update our accounting.
            metrics.ProvisioningMetrics.inc_requested()

        gr = self.get_by_guestname(guestname)

        if gr is None:
            # Now isn't this just funny... We just created the record, how could it be missing? There's probably
            # no point in trying to clean up what we started - if the guest is missing, right after we created it,
            # then things went south. At least it would get logged.
            raise errors.InternalServerError(
                logger=guest_logger,
                failure_details=failure_details
            )

        return gr

    def get_by_guestname(self, guestname: str) -> Optional[GuestResponse]:
        with self.db.get_session() as session:
            r_guest_request_record = artemis_db.SafeQuery.from_session(session, artemis_db.GuestRequest) \
                .filter(artemis_db.GuestRequest.guestname == guestname) \
                .one_or_none()

            if r_guest_request_record.is_error:
                raise errors.InternalServerError(caused_by=r_guest_request_record.unwrap_error())

            guest_request_record = r_guest_request_record.unwrap()

            if guest_request_record is None:
                return None

            return GuestResponse.from_db(guest_request_record)

    def delete_by_guestname(self, guestname: str, request: Request, logger: gluetool.log.ContextAdapter) -> None:
        from ..tasks import get_guest_logger
        from ..tasks.release_guest_request import release_guest_request

        failure_details = {
            'guestname': guestname
        }

        guest_logger = get_guest_logger('delete-guest-request', logger, guestname)

        with self.db.get_session() as session:
            r_guest_request = artemis_db.SafeQuery \
                .from_session(session, artemis_db.GuestRequest) \
                .filter(artemis_db.GuestRequest.guestname == guestname) \
                .one_or_none()

            if r_guest_request.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_guest_request.unwrap_error(),
                    failure_details=failure_details
                )

            # Once condemned, the request cannot change its state to anything else. It can only disappear.
            guest_request = r_guest_request.unwrap()

            if guest_request is None:
                raise errors.NoSuchEntityError(
                    logger=guest_logger,
                    failure_details=failure_details
                )

            if guest_request.state != GuestState.CONDEMNED:  # type: ignore[comparison-overlap]
                snapshot_count_subquery = session.query(  # type: ignore[no-untyped-call] # untyped function "query"
                    sqlalchemy.func.count(artemis_db.SnapshotRequest.snapshotname).label('snapshot_count')
                ).filter(
                    artemis_db.SnapshotRequest.guestname == guestname
                ).subquery('t')

                query = sqlalchemy \
                    .update(artemis_db.GuestRequest.__table__) \
                    .where(artemis_db.GuestRequest.guestname == guestname) \
                    .where(snapshot_count_subquery.c.snapshot_count == 0) \
                    .values(state=GuestState.CONDEMNED)

                r_state = artemis_db.execute_db_statement(guest_logger, session, query)

                # The query can miss either with existing snapshots, or when the guest request has been
                # removed from DB already. The "gone already" situation could be better expressed by
                # returning "404 Not Found", but we can't tell which of these two situations caused the
                # change to go vain, therefore returning general "409 Conflict", expressing our believe
                # user should resolve the conflict and try again.
                if r_state.is_error:
                    failure = r_state.unwrap_error()

                    if failure.details.get('serialization_failure', False):
                        raise errors.ConflictError(
                            logger=guest_logger,
                            caused_by=failure,
                            failure_details=failure_details
                        )

                    raise errors.InternalServerError(
                        logger=guest_logger,
                        caused_by=failure,
                        failure_details=failure_details
                    )

                artemis_db.GuestRequest.log_event_by_guestname(
                    guest_logger,
                    session,
                    guestname,
                    'condemned'
                )

                guest_logger.info('condemned')

            r_task = artemis_db.TaskRequest.create(guest_logger, session, release_guest_request, guestname)

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            log_dict_yaml(
                guest_logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(release_guest_request, guestname, task_request_id=task_request_id).serialize()
            )

    def acquire_guest_console_url(
        self,
        guestname: str,
        logger: gluetool.log.ContextAdapter
    ) -> ConsoleUrlResponse:
        from ..tasks import acquire_guest_console_url as task_acquire_guest_console_url
        from ..tasks import dispatch_task

        r_dispatch = dispatch_task(logger, task_acquire_guest_console_url, guestname)
        if r_dispatch.is_error:
            raise errors.InternalServerError(caused_by=r_dispatch.unwrap_error(), logger=logger)

        return ConsoleUrlResponse(url=None, expires=None)


class GuestEventManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    def get_events(
        self,
        search_params: EventSearchParameters
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                page=search_params.page,
                page_size=search_params.page_size,
                sort_field=search_params.sort_field,
                sort_order=search_params.sort_order,
                since=search_params.since,
                until=search_params.until
            )

            if r_events.is_error:
                raise errors.InternalServerError(caused_by=r_events.unwrap_error())

            return [
                GuestEvent.from_db(event_record)
                for event_record in r_events.unwrap()
            ]

    def get_events_by_guestname(
        self,
        guestname: str,
        search_params: EventSearchParameters
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                guestname=guestname,
                page=search_params.page,
                page_size=search_params.page_size,
                sort_field=search_params.sort_field,
                sort_order=search_params.sort_order,
                since=search_params.since,
                until=search_params.until
            )

            if r_events.is_error:
                raise errors.InternalServerError(caused_by=r_events.unwrap_error())

            return [
                GuestEvent.from_db(event_record)
                for event_record in r_events.unwrap()
            ]


class GuestRequestManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is GuestRequestManager

    def resolve(self, db: artemis_db.DB) -> GuestRequestManager:
        return GuestRequestManager(db)


class GuestEventManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is GuestEventManager

    def resolve(self, db: artemis_db.DB) -> GuestEventManager:
        return GuestEventManager(db)


class SnapshotRequestManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    def get_snapshot(self, guestname: str, snapshotname: str) -> Optional[SnapshotResponse]:
        with self.db.get_session() as session:
            r_snapshot_request_record = artemis_db.SafeQuery.from_session(session, artemis_db.SnapshotRequest) \
                .filter(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .filter(artemis_db.SnapshotRequest.guestname == guestname) \
                .one_or_none()

            if r_snapshot_request_record.is_error:
                raise errors.InternalServerError(caused_by=r_snapshot_request_record.unwrap_error())

            snapshot_request_record = r_snapshot_request_record.unwrap()

            if snapshot_request_record is None:
                return None

            return SnapshotResponse.from_db(snapshot_request_record)

    def create_snapshot(
        self,
        guestname: str,
        snapshot_request: SnapshotRequest,
        logger: gluetool.log.ContextAdapter
    ) -> SnapshotResponse:
        snapshotname = str(uuid.uuid4())

        failure_details = {
            'guestname': guestname,
            'snapshotname': snapshotname
        }

        snapshot_logger = get_snapshot_logger('create-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            perform_safe_db_change(
                snapshot_logger,
                session,
                sqlalchemy.insert(artemis_db.SnapshotRequest.__table__).values(
                    snapshotname=snapshotname,
                    guestname=guestname,
                    poolname=None,
                    state=GuestState.PENDING,
                    start_again=snapshot_request.start_again
                ),
                conflict_error=errors.InternalServerError,
                failure_details=failure_details
            )

            artemis_db.GuestRequest.log_event_by_guestname(
                snapshot_logger,
                session,
                guestname,
                'created',
                snapshotname=snapshotname
            )

        sr = self.get_snapshot(guestname, snapshotname)

        if sr is None:
            # Now isn't this just funny... We just created the record, how could it be missing? There's probably
            # no point in trying to clean up what we started - if the guest is missing, right after we created it,
            # then things went south. At least it would get logged.
            raise errors.InternalServerError(
                logger=snapshot_logger,
                failure_details=failure_details
            )

        return sr

    def delete_snapshot(self, guestname: str, snapshotname: str, logger: gluetool.log.ContextAdapter) -> None:
        from ..tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            query = sqlalchemy \
                .update(artemis_db.SnapshotRequest.__table__) \
                .where(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .where(artemis_db.SnapshotRequest.guestname == guestname) \
                .values(state=GuestState.CONDEMNED)

            # Unline guest requests, here seem to be no possibility of conflict or relationships we must
            # preserve. Given the query, snapshot request already being removed seems to be the only option
            # here - what else could cause the query *not* marking the record as condemned?
            perform_safe_db_change(snapshot_logger, session, query, conflict_error=errors.NoSuchEntityError)

            artemis_db.GuestRequest.log_event_by_guestname(
                snapshot_logger,
                session,
                guestname,
                'snapshot-condemned'
            )

    def restore_snapshot(
        self,
        guestname: str,
        snapshotname: str,
        logger: gluetool.log.ContextAdapter
    ) -> SnapshotResponse:
        from ..tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            query = sqlalchemy \
                .update(artemis_db.SnapshotRequest.__table__) \
                .where(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .where(artemis_db.SnapshotRequest.guestname == guestname) \
                .where(artemis_db.SnapshotRequest.state != GuestState.CONDEMNED) \
                .values(state=GuestState.RESTORING)

            # Similarly to guest request removal, two options exist: either the snapshot is already gone,
            # or it's marked as condemned. Again, we cannot tell which of these happened. "404 Not Found"
            # would better express the former, but sticking with "409 Conflict" to signal user there's a
            # conflict of some kind, and after resolving it - e.g. by inspecting the snapshot request - user
            # should decide how to proceed.
            perform_safe_db_change(snapshot_logger, session, query)

            snapshot_response = self.get_snapshot(guestname, snapshotname)

            assert snapshot_response is not None

            return snapshot_response


class SnapshotRequestManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is SnapshotRequestManager

    def resolve(self, db: artemis_db.DB) -> SnapshotRequestManager:
        return SnapshotRequestManager(db)


class KnobManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_get_knobs(
        manager: 'KnobManager',
        logger: gluetool.log.ContextAdapter
    ) -> Tuple[str, List[KnobResponse]]:
        return HTTP_200, manager.get_knobs(logger)

    @staticmethod
    def entry_get_knob(
        manager: 'KnobManager',
        knobname: str,
        logger: gluetool.log.ContextAdapter
    ) -> KnobResponse:
        response = manager.get_knob(logger, knobname)

        if response is None:
            raise errors.NoSuchEntityError()

        return response

    @staticmethod
    def entry_set_knob(
        manager: 'KnobManager',
        knobname: str,
        payload: KnobUpdateRequest,
        logger: gluetool.log.ContextAdapter
    ) -> KnobResponse:
        manager.set_knob(knobname, payload.value, logger)

        response = manager.get_knob(logger, knobname)

        if response is None:
            raise errors.NoSuchEntityError()

        return response

    @staticmethod
    def entry_delete_knob(
        manager: 'KnobManager',
        logger: gluetool.log.ContextAdapter,
        knobname: str
    ) -> Tuple[str, None]:
        manager.delete_knob(logger, knobname)

        return HTTP_204, None

    def get_knobs(self, logger: gluetool.log.ContextAdapter) -> List[KnobResponse]:
        knobs: Dict[str, KnobResponse] = {}

        # First, collect all known knobs.
        for knobname, knob in Knob.ALL_KNOBS.items():
            knobs[knobname] = KnobResponse(
                name=knobname,
                value=knob.static_value,
                cast=knob.cast_name,
                help=knob.help,
                editable=False
            )

        # Second, update editable knobs.
        for knobname, knob in Knob.DB_BACKED_KNOBS.items():
            assert knobname in knobs

            knobs[knobname].editable = True

        # Then, get the actual DB records, and update what we collected in the previous step:
        #
        # * knobs we already saw may need a value update since the DB record is the source with higher priority;
        # * knobs we haven't seen yet shall be added to the list. These are the per-pool knobs - each per-pool DB
        #   record does not have its own knob variable - the knob name in the record does not match any existing
        #   static knob, since `$poolname` placeholder in the name is replaced with the actual pool name. For these
        #   records, we must find their "parent" knob, because we need to know its casting function (which applies
        #   to all "child" records of the given per-pool-capable knob).
        with self.db.get_session() as session:
            r_knobs = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .all()

            if r_knobs.is_error:
                raise errors.InternalServerError(caused_by=r_knobs.unwrap_error())

            for record in r_knobs.unwrap():
                if record.knobname not in knobs:
                    parent_knob = Knob.get_per_pool_parent(logger, record.knobname)

                    if parent_knob is None:
                        raise errors.InternalServerError(
                            message='cannot find parent knob',
                            failure_details={
                                'knobname': record.knobname
                            }
                        )

                    knobs[record.knobname] = KnobResponse(
                        name=record.knobname,
                        value=record.value,
                        cast=parent_knob.cast_name,
                        help=knob.help,
                        editable=True
                    )

                else:
                    knobs[record.knobname].value = record.value

        return list(knobs.values())

    def get_knob(self, logger: gluetool.log.ContextAdapter, knobname: str) -> Optional[KnobResponse]:
        with self.db.get_session() as session:
            r_knob = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .filter(artemis_db.Knob.knobname == knobname) \
                .one_or_none()

            if r_knob.is_error:
                raise errors.InternalServerError(caused_by=r_knob.unwrap_error())

            knob_record = r_knob.unwrap()

            if knob_record is None:
                value = None

            else:
                value = knob_record.value

            if knobname in Knob.DB_BACKED_KNOBS:
                knob = Knob.DB_BACKED_KNOBS[knobname]

                return KnobResponse(
                    name=knobname,
                    value=value,
                    help=knob.help,
                    editable=True,
                    cast=knob.cast_name
                )

            if knobname in Knob.ALL_KNOBS:
                knob = Knob.ALL_KNOBS[knobname]

                return KnobResponse(
                    name=knobname,
                    value=value,
                    help=knob.help,
                    editable=False,
                    cast=knob.cast_name
                )

            parent_knob = Knob.get_per_pool_parent(logger, knobname)

            if parent_knob is None:
                raise errors.InternalServerError(
                    message='cannot find parent knob',
                    failure_details={
                        'knobname': knobname
                    }
                )

            return KnobResponse(
                name=knobname,
                value=value,
                cast=parent_knob.cast_name,
                help=parent_knob.help,
                editable=True
            )

    def set_knob(self, knobname: str, value: str, logger: gluetool.log.ContextAdapter) -> None:
        failure_details = {
            'knobname': knobname
        }

        with self.db.get_session() as session:
            knob = Knob.DB_BACKED_KNOBS.get(knobname)

            if knob is None:
                # If the knob is not backed by DB but it's in the list of all knobs, then it must be a knob
                # that's not editable.
                if knobname in Knob.ALL_KNOBS:
                    raise errors.MethodNotAllowedError(
                        message='Cannot modify non-editable knob',
                        failure_details=failure_details
                    )

                # Try to find the parent knob for this one which is apparently a per-pool knob.
                knob = Knob.get_per_pool_parent(logger, knobname)

            if knob is None:
                raise errors.NoSuchEntityError(logger=logger)

            assert knob is not None
            assert knob.cast_from_str is not None

            try:
                casted_value = knob.cast_from_str(value)

            except Exception as exc:
                raise errors.BadRequestError(
                    message='Cannot convert value to type expected by the knob',
                    logger=logger,
                    caused_by=Failure.from_exc('cannot cast knob value', exc),
                    failure_details=failure_details
                )

            artemis_db.upsert(
                logger,
                session,
                artemis_db.Knob,
                {
                    # using `knobname`, i.e. changing the original knob, not the parent
                    artemis_db.Knob.knobname: knobname
                },
                insert_data={
                    artemis_db.Knob.value: casted_value
                },
                update_data={
                    'value': casted_value
                }
            )

        logger.info(f'knob changed: {knobname} = {casted_value}')

    def delete_knob(self, logger: gluetool.log.ContextAdapter, knobname: str) -> None:
        with self.db.get_session() as session:
            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.delete(artemis_db.Knob.__table__).where(artemis_db.Knob.knobname == knobname)
            )


class KnobManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is KnobManager or parameter.annotation == 'KnobManager'

    def resolve(self, db: artemis_db.DB) -> KnobManager:
        return KnobManager(db)


class CacheManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    def refresh_pool_object_infos(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        actor: Actor
    ) -> Tuple[str, None]:
        # We don't really need the pool object, but we'd like to avoid triggering tasks for pools that don't exist.
        # The race condition still exists though, because we don't try too hard :) The pool may be gone after our
        # check and before the dispatch, but we don't aim for consistency here, rather the user experience. The task
        # is safe: if the pool is gone in that sensitive period of time, task will report an error and won't ask for
        # reschedule. If we can avoid some of the errors with a trivial DB query, let's do so.
        with self.db.get_session() as session:
            _ = self._get_pool(logger, session, poolname)

        from ..tasks import dispatch_task

        r_dispatch = dispatch_task(logger, actor, poolname)

        if r_dispatch.is_error:
            raise errors.InternalServerError(caused_by=r_dispatch.unwrap_error(), logger=logger)

        return HTTP_202, None

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_pool_image_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Response:
        return manager.get_pool_image_info(logger, poolname)

    @staticmethod
    def entry_pool_flavor_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Response:
        return manager.get_pool_flavor_info(logger, poolname)

    @staticmethod
    def entry_refresh_pool_image_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Tuple[str, None]:
        from ..tasks import refresh_pool_image_info

        return manager.refresh_pool_object_infos(logger, poolname, refresh_pool_image_info)

    @staticmethod
    def entry_refresh_pool_flavor_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Tuple[str, None]:
        from ..tasks import refresh_pool_flavor_info

        return manager.refresh_pool_object_infos(logger, poolname, refresh_pool_flavor_info)

    def _get_pool(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> PoolDriver:
        r_pool = PoolDriver.load_or_none(logger, session, poolname)

        if r_pool.is_error:
            raise errors.InternalServerError(
                logger=logger,
                caused_by=r_pool.unwrap_error(),
                failure_details={
                    'poolname': poolname
                }
            )

        pool = r_pool.unwrap()

        if pool is None:
            raise errors.NoSuchEntityError(
                logger=logger,
                failure_details={
                    'poolname': poolname
                }
            )

        return pool

    def _get_pool_object_infos(self, logger: gluetool.log.ContextAdapter, poolname: str, method_name: str) -> Response:
        with self.db.get_session() as session:
            pool = self._get_pool(logger, session, poolname)

            method = getattr(pool, method_name, None)

            if method is None:
                raise errors.NoSuchEntityError(message='Pool does not support this type of information')

            r_infos = method()

            if r_infos.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_infos.unwrap_error(),
                    failure_details={
                        'poolname': poolname
                    }
                )

            return Response(
                status=HTTP_200,
                content=gluetool.log.format_dict({
                    info.name: info.serialize()
                    for info in r_infos.unwrap()
                }),
                headers={'Content-Type': 'application/json'}
            )

    def get_pool_image_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_image_infos')

    def get_pool_flavor_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_flavor_infos')


class UserManager:
    """
    Manager class for operations involving management of user accounts.
    """

    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    @staticmethod
    def entry_get_users(manager: 'UserManager') -> List[UserResponse]:
        with manager.db.get_session() as session:
            return [
                UserResponse.from_db(user)
                for user in manager.get_users(session)
            ]

    @staticmethod
    def entry_get_user(manager: 'UserManager', username: str) -> UserResponse:
        with manager.db.get_session() as session:
            return UserResponse.from_db(manager.get_user(session, username))

    @staticmethod
    def entry_create_user(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str,
        user_request: CreateUserRequest
    ) -> Tuple[str, UserResponse]:
        try:
            actual_role = artemis_db.UserRoles(user_request.role)

        except ValueError:
            raise errors.BadRequestError(
                failure_details={
                    'username': username,
                    'role': user_request.role
                }
            )

        manager.create_user(logger, username, actual_role)

        with manager.db.get_session() as session:
            return HTTP_201, UserResponse.from_db(manager.get_user(session, username))

    @staticmethod
    def entry_delete_user(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str
    ) -> Tuple[str, None]:
        manager.delete_user(logger, username)

        return HTTP_204, None

    @staticmethod
    def entry_reset_token(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str,
        tokentype: str
    ) -> Tuple[str, TokenResetResponse]:
        try:
            actual_tokentype = TokenTypes(tokentype)

        except ValueError:
            raise errors.BadRequestError(
                failure_details={
                    'username': username,
                    'tokentype': tokentype
                }
            )

        return HTTP_201, manager.reset_token(logger, username, actual_tokentype)

    #
    # Actual API workers
    #
    def get_users(self, session: sqlalchemy.orm.session.Session) -> List[artemis_db.User]:
        r_users = artemis_db.SafeQuery.from_session(session, artemis_db.User).all()

        if r_users.is_error:
            raise errors.InternalServerError(caused_by=r_users.unwrap_error())

        return r_users.unwrap()

    def get_user(
        self,
        session: sqlalchemy.orm.session.Session,
        username: str,
    ) -> artemis_db.User:
        r_user = artemis_db.SafeQuery.from_session(session, artemis_db.User) \
            .filter(artemis_db.User.username == username) \
            .one_or_none()

        if r_user.is_error:
            raise errors.InternalServerError(caused_by=r_user.unwrap_error())

        user = r_user.unwrap()

        if not user:
            raise errors.NoSuchEntityError()

        return user

    def create_user(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str,
        role: artemis_db.UserRoles
    ) -> None:
        with self.db.get_session() as session:
            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.insert(artemis_db.User.__table__).values(
                    username=username,
                    role=role.value
                )
            )

    def delete_user(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str
    ) -> None:
        with self.db.get_session() as session:
            # Provides nicer error when the user does not exist
            _ = self.get_user(session, username)

            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.delete(artemis_db.User.__table__).where(
                    artemis_db.User.username == username
                ),
                failure_details={
                    'username': username
                }
            )

    def reset_token(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str,
        tokentype: TokenTypes
    ) -> TokenResetResponse:
        with self.db.get_session() as session:
            # Provides nicer error when the user does not exist
            user = self.get_user(session, username)

            token, token_hash = artemis_db.User.generate_token()

            query = sqlalchemy.update(artemis_db.User.__table__) \
                .where(artemis_db.User.username == username)

            if tokentype == TokenTypes.ADMIN:
                query = query \
                    .where(artemis_db.User.admin_token == user.admin_token) \
                    .values(admin_token=token_hash)

            elif tokentype == TokenTypes.PROVISIONING:
                query = query \
                    .where(artemis_db.User.provisioning_token == user.provisioning_token) \
                    .values(provisioning_token=token_hash)

            else:
                assert False, 'Unreachable'

            perform_safe_db_change(
                logger,
                session,
                query,
                failure_details={
                    'username': username,
                    'tokentype': tokentype.value
                }
            )

        return TokenResetResponse(
            tokentype=tokentype,
            token=token
        )


class CacheManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is CacheManager or parameter.annotation == 'CacheManager'

    def resolve(self, db: artemis_db.DB) -> CacheManager:
        return CacheManager(db)


class UserManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is UserManager or parameter.annotation == 'UserManager'

    def resolve(self, db: artemis_db.DB) -> UserManager:
        return UserManager(db)


class StatusManager:
    def __init__(self, db: artemis_db.DB) -> None:
        self.db = db

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_workers_traffic(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Response:
        from ..middleware import WorkerTraffic

        tasks: List[Dict[str, Any]] = []

        for task_key in iter_cache_keys(logger, cache, WorkerTraffic.KEY_WORKER_TASK_PATTERN):
            value = get_cache_value(logger, cache, task_key.decode())

            if not value:
                continue

            tasks.append(json.loads(value.decode()))

        return Response(
            status=HTTP_200,
            content=gluetool.log.format_dict(tasks),
            headers={'Content-Type': 'application/json'}
        )


class StatusManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is StatusManager or parameter.annotation == 'StatusManager'

    def resolve(self, db: artemis_db.DB) -> StatusManager:
        return StatusManager(db)


#
# Routes
#
def get_guest_requests(manager: GuestRequestManager, request: Request) -> Tuple[str, List[GuestResponse]]:
    return HTTP_200, manager.get_guest_requests()


def create_guest_request_v0_0_38(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.38'])


def create_guest_request_v0_0_37(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.37'])


def create_guest_request_v0_0_32(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.32'])


def create_guest_request_v0_0_28(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.28'])


def create_guest_request_v0_0_27(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.27'])


def create_guest_request_v0_0_26(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.26'])


def create_guest_request_v0_0_24(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.24'])


def create_guest_request_v0_0_20(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.20'])


def create_guest_request_v0_0_19(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.19'])


def create_guest_request_v0_0_18(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.18'])


def create_guest_request_v0_0_17(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, GuestResponse]:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return HTTP_201, manager.create(guest_request, ownername, logger, ENVIRONMENT_SCHEMAS['v0.0.17'])


def get_guest_request(guestname: str, manager: GuestRequestManager, request: Request) -> GuestResponse:
    guest_response = manager.get_by_guestname(guestname)

    if guest_response is None:
        raise errors.NoSuchEntityError(request=request)

    return guest_response


def delete_guest(
    guestname: str,
    request: Request,
    logger: gluetool.log.ContextAdapter,
    manager: GuestRequestManager
) -> Tuple[str, None]:
    if not manager.get_by_guestname(guestname):
        raise errors.NoSuchEntityError(request=request)

    manager.delete_by_guestname(guestname, request, logger)

    return HTTP_204, None


def get_events(
        request: Request,
        manager: GuestEventManager,
) -> Tuple[str, List[GuestEvent]]:
    return HTTP_200, manager.get_events(EventSearchParameters.from_request(request))


def get_guest_events(guestname: str, request: Request, manager: GuestEventManager) -> Tuple[str, List[GuestEvent]]:
    return HTTP_200, manager.get_events_by_guestname(guestname, EventSearchParameters.from_request(request))


def acquire_guest_console_url(
        guestname: str,
        request: Request,
        manager: GuestRequestManager,
        logger: gluetool.log.ContextAdapter
) -> Tuple[str, ConsoleUrlResponse]:
    from ..tasks import get_guest_logger
    console_url_logger = get_guest_logger('acquire-guest-console-url', logger, guestname)

    # first see if the console has already been created and isn't expired yet
    gr = manager.get_by_guestname(guestname)
    if not gr:
        # no such guest found, aborting
        raise errors.NoSuchEntityError(request=request, logger=console_url_logger)
    console_url_response = ConsoleUrlResponse(
        url=gr.console_url,
        expires=gr.console_url_expires
    )
    has_expired = gr.console_url_expires and gr.console_url_expires < datetime.datetime.utcnow()
    if not gr.console_url or has_expired:
        if has_expired:
            logger.warning(f'Guest console url {console_url_response.url} has expired, will fetch a new one')
        else:
            logger.warning('Fetching a new guest console url')
        console_url_response = manager.acquire_guest_console_url(guestname, console_url_logger)
    return HTTP_200, console_url_response


def get_metrics(
    request: Request,
    db: artemis_db.DB,
    metrics_tree: 'metrics.Metrics',
    logger: gluetool.log.ContextAdapter
) -> Response:
    LOGGER.set(logger)
    DATABASE.set(db)

    r_metrics = metrics_tree.render_prometheus_metrics()

    if r_metrics.is_error:
        raise errors.InternalServerError(caused_by=r_metrics.unwrap_error())

    with METRICS_LOCK:
        return Response(
            HTTP_200,
            content=r_metrics.unwrap().decode('utf-8'),
            headers={
                "content-type": "text/plain; charset=utf-8"
            }
        )


def get_snapshot_request(guestname: str, snapshotname: str, manager: SnapshotRequestManager) -> SnapshotResponse:
    snapshot_response = manager.get_snapshot(guestname, snapshotname)

    if snapshot_response is None:
        raise errors.NoSuchEntityError()

    return snapshot_response


def create_snapshot_request(guestname: str,
                            snapshot_request: SnapshotRequest,
                            manager: SnapshotRequestManager,
                            logger: gluetool.log.ContextAdapter) -> Tuple[str, SnapshotResponse]:
    return HTTP_201, manager.create_snapshot(guestname, snapshot_request, logger)


def delete_snapshot(
    guestname: str,
    snapshotname: str,
    manager: SnapshotRequestManager,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, None]:
    manager.delete_snapshot(guestname, snapshotname, logger)

    return HTTP_204, None


def restore_snapshot_request(
    guestname: str,
    snapshotname: str,
    manager: SnapshotRequestManager,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, SnapshotResponse]:
    return HTTP_201, manager.restore_snapshot(guestname, snapshotname, logger)


@molten.schema
@dataclasses.dataclass
class GuestLogResponse:
    state: artemis_db.GuestLogState
    contenttype: artemis_db.GuestLogContentType

    url: Optional[str]
    blob: Optional[str]

    updated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, log: artemis_db.GuestLog) -> 'GuestLogResponse':
        return cls(
            state=artemis_db.GuestLogState(log.state),
            contenttype=artemis_db.GuestLogContentType(log.contenttype),
            url=log.url,
            blob=log.blob,
            updated=log.updated,
            expires=log.expires
        )


def get_guest_request_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: GuestRequestManager,
    logger: gluetool.log.ContextAdapter
) -> Union[Tuple[str, None], GuestLogResponse]:
    from ..tasks import get_guest_logger

    failure_details = {
        'guestname': guestname
    }

    guest_logger = get_guest_logger('create-guest-request-log', logger, guestname)

    with manager.db.get_session() as session:
        r_log = artemis_db.SafeQuery.from_session(session, artemis_db.GuestLog) \
            .filter(artemis_db.GuestLog.guestname == guestname) \
            .filter(artemis_db.GuestLog.logname == logname) \
            .filter(artemis_db.GuestLog.contenttype == artemis_db.GuestLogContentType(contenttype)) \
            .one_or_none()

        if r_log.is_error:
            raise errors.InternalServerError(
                logger=guest_logger,
                caused_by=r_log.unwrap_error(),
                failure_details=failure_details
            )

        log = r_log.unwrap()

        if log is None:
            raise errors.NoSuchEntityError(logger=guest_logger)

        if log.is_expired:
            raise errors.ConflictError(
                message='guest log has expired',
                logger=guest_logger
            )

        return GuestLogResponse.from_db(log)


def create_guest_request_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: GuestRequestManager,
    logger: gluetool.log.ContextAdapter
) -> Tuple[str, None]:
    from ..tasks import dispatch_task, get_guest_logger, update_guest_log

    failure_details = {
        'guestname': guestname
    }

    guest_logger = get_guest_logger('create-guest-request-log', logger, guestname)

    r_dispatch = dispatch_task(
        guest_logger,
        update_guest_log,
        guestname,
        logname,
        contenttype
    )

    if r_dispatch.is_error:
        raise errors.InternalServerError(
            logger=guest_logger,
            caused_by=r_dispatch.unwrap_error(),
            failure_details=failure_details
        )

    return HTTP_202, None


def get_about(request: Request) -> AboutResponse:
    """
    Some docs.
    """

    return AboutResponse(
        package_version=__VERSION__,
        image_digest=os.getenv('ARTEMIS_IMAGE_DIGEST'),
        image_url=os.getenv('ARTEMIS_IMAGE_URL'),
        artemis_deployment=KNOB_DEPLOYMENT.value,
        artemis_deployment_environment=KNOB_DEPLOYMENT_ENVIRONMENT.value
    )


class OpenAPIHandler(_OpenAPIHandler):
    """
    Dynamically generates and serves OpenAPI v3 documents based on the current application object. Once
    generated, the document is subsequently served from cache.

    This custom handler was implemented to replace :py:class:`molten.openapi.handlers.OpenAPIHandler`,
    which returns ``dict`` instead of :py:class:`molten.Response`. Ideally, we need every route to return
    :py:class:`molten.Response` (or :py:class:`APIResponse`) so that we can use middleware that is designed
    to work with :py:class:`molten.Response` and just stay consistent in general.
    """

    def __call__(self, app: BaseApp) -> Response:  # type: ignore[override] # return type incompatible with supertype
        super().__call__(app)

        return Response(
            status=HTTP_200,
            content=json.dumps(self.document),
            headers={'Content-Type': 'application/json'}
        )


#
# Route generators
#
# These functions take care of generating routes - endpoints - for their respective API versions.
#
class CreateRouteCallbackType(Protocol):
    """
    Represents a callable that creates a :py:class:`molten.Route` for given parameters.

    Pretty much the type of :py:class:`molten.Route` ``__init__()`` method, including accepted parameters.
    """

    def __call__(self, template: str, handler: Callable[..., Any], method: str = 'GET') -> Route:
        pass


class RouteGeneratorType(Protocol):
    """
    Represents a callable that creates a list of routes. This is what we need to implement for each API version.

    :param create_route: a callable to create one individual route. Similar to a bare :py:class:`molten.Route`,
        but not necessarily the class itself.
    :param name_prefix: a prefix applied to all route names. It must be unique among all the routes, because
        Molten does not allow two routes with the same name, even if they represent different endpoints.
    :param metadata: OpenAPI metadata. Usually shared by the whole tree, and passed to OpenAPI handlers taking
        care of endpoints like ``/_docs``.
    """

    def __call__(
        self,
        create_route: CreateRouteCallbackType,
        name_prefix: str,
        metadata: Any
    ) -> List[Union[Route, Include]]:
        pass


class RouteGeneratorOuterType(Protocol):
    """
    "Public" API of a route generator.

    :param url_prefix: first step of the desired URL, usually a version, e.g. ``/v0.0.1``. It is added to all
        endpoints.
    :param name_prefix: a prefix applied to all internal route names. It must be unique among all the tree's built
        by this helper, because Molten does not allow two routes with the same name, even if they represent
        different endpoints.
    :param metadata: OpenAPI metadata. Usually shared by the whole tree, and passed to OpenAPI handlers taking
        care of endpoints like ``/_docs``.
    :param redirect_to_prefix: if set, instead of calling the usual handler to generate response, a redirect is
        returned. The redirect URL is created by replacing ``url_prefix`` part of the original URL with this value.
        For example, ``url_prefix='/v0.0.15', redirect_to_prefix='/v0.0.16'`` would redirect ``/v0.0.15/foo`` to
        ``/v0.0.16/foo``.
    """

    def __call__(
        self,
        url_prefix: str,
        name_prefix: str,
        metadata: Any,
        redirect_to_prefix: Optional[str] = None
    ) -> List[Union[Route, Include]]:
        pass


def _create_route(
    template: str,
    handler: Callable[..., Any],
    method: str = 'GET',
    name_prefix: str = ''
) -> Route:
    """
    Create a single route for given parameters.

    Since Molten does not allow multiple routes with the same name, and since the name is created from
    the handler name, we need to provide custom name for each route that shares the handler. We do that
    by prefixing the handler name with an arbitrary prefix, which is specified by route generator calling
    this helper.

    Without this Molten requirement, we could just use `Route(...)` and be done with it.
    """

    return Route(template, handler, method=method, name=f'{name_prefix}{handler.__name__}')


def route_generator(fn: RouteGeneratorType) -> RouteGeneratorOuterType:
    """
    Decorator for route generators, providing shared functionality.

    Decorates function with signature matching :py:class:`RouteGeneratorType`, which does the actual work,
    and wraps it to provide some shared functionality, presenting :py:class:`RouteGeneratorOuterType` signature
    to API server code. This signature demands more parameters, but the wrapped function doesn't have to be
    concerned with these are consumed by the wrapper.
    """

    @functools.wraps(fn)
    def wrapper(
        url_prefix: str,
        name_prefix: str,
        metadata: Any,
        redirect_to_prefix: Optional[str] = None
    ) -> List[Union[Route, Include]]:
        if redirect_to_prefix:
            # Keeping the same API as `_create_route`, to make the structure below easier to handle. But we will ignore
            # the given handler, and use a custom one.
            def create_route(
                template: str,
                handler: Callable[..., Any],
                method: str = 'GET'
            ) -> Route:
                def real_handler(request: Request) -> Any:
                    assert redirect_to_prefix is not None

                    # Replace just once, no more - doesn't metter with regular versions, but the pseudo "top-level"
                    # version means an empty string as a prefix, and that would insert the `redirect_to_prefix` between
                    # each and every character of the path.
                    return molten.redirect(
                        request.path.replace(url_prefix, redirect_to_prefix, 1),
                        redirect_type=molten.RedirectType.PERMANENT
                    )

                return Route(template, real_handler, method=method, name=f'{name_prefix}{handler.__name__}')

        else:
            def create_route(
                template: str,
                handler: Callable[..., Any],
                method: str = 'GET'
            ) -> Route:
                return _create_route(template, handler, method=method, name_prefix=name_prefix)

        return [
            Include(url_prefix, fn(create_route, name_prefix, metadata))
        ]

    return wrapper


# NEW: added hostname HW constraint
@route_generator
def generate_routes_v0_0_38(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_38, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info),
                create_route('/image-info', CacheManager.entry_refresh_pool_image_info, method='POST'),
                create_route('/flavor-info', CacheManager.entry_refresh_pool_flavor_info, method='POST')
            ])
        ]),
        Include('/_status', [
            Include('/workers', [
                create_route('/traffic', StatusManager.entry_workers_traffic)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: virtualization HW constraint
@route_generator
def generate_routes_v0_0_37(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_37, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info),
                create_route('/image-info', CacheManager.entry_refresh_pool_image_info, method='POST'),
                create_route('/flavor-info', CacheManager.entry_refresh_pool_flavor_info, method='POST')
            ])
        ]),
        Include('/_status', [
            Include('/workers', [
                create_route('/traffic', StatusManager.entry_workers_traffic)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: current worker tasks
# NEW: boot.method HW constraint
@route_generator
def generate_routes_v0_0_32(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_32, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info),
                create_route('/image-info', CacheManager.entry_refresh_pool_image_info, method='POST'),
                create_route('/flavor-info', CacheManager.entry_refresh_pool_flavor_info, method='POST')
            ])
        ]),
        Include('/_status', [
            Include('/workers', [
                create_route('/traffic', StatusManager.entry_workers_traffic)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: trigger pool info refresh
# NEW: HW requirement changes - added `network`
@route_generator
def generate_routes_v0_0_28(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_28, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info),
                create_route('/image-info', CacheManager.entry_refresh_pool_image_info, method='POST'),
                create_route('/flavor-info', CacheManager.entry_refresh_pool_flavor_info, method='POST')
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: HW requirement changes - refactored `disk`
@route_generator
def generate_routes_v0_0_27(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_27, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info),
                create_route('/image-info', CacheManager.entry_refresh_pool_image_info, method='POST'),
                create_route('/flavor-info', CacheManager.entry_refresh_pool_flavor_info, method='POST')
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: allow log-types to be specified in guest request
@route_generator
def generate_routes_v0_0_26(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_26, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: allow skipping verify-ssh steps
@route_generator
def generate_routes_v0_0_24(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_24, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: user management
@route_generator
def generate_routes_v0_0_21(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_20, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        Include('/users', [
            create_route('/', UserManager.entry_get_users, method='GET'),
            create_route('/{username}', UserManager.entry_get_user, method='GET'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_create_user, method='POST'),  # noqa: FS003
            create_route('/{username}', UserManager.entry_delete_user, method='DELETE'),  # noqa: FS003
            create_route('/{username}/tokens/{tokentype}/reset', UserManager.entry_reset_token, method='POST')  # noqa: FS003,E501
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: guest logs
@route_generator
def generate_routes_v0_0_20(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_20, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', get_guest_request_log, method='GET'),  # noqa: FS003,E501
            create_route('/{guestname}/logs/{logname}/{contenttype}', create_guest_request_log, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: HW requirements
@route_generator
def generate_routes_v0_0_19(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_19, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/console/url', acquire_guest_console_url, method='GET')  # noqa: FS003
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


# NEW: /{guestname}/console/url
@route_generator
def generate_routes_v0_0_18(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_18, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),  # noqa: FS003,E501
            create_route('/{guestname}/console/url', acquire_guest_console_url, method='GET')  # noqa: FS003
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


@route_generator
def generate_routes_v0_0_17(
    create_route: CreateRouteCallbackType,
    name_prefix: str,
    metadata: Any
) -> List[Union[Route, Include]]:
    return [
        Include('/guests', [
            create_route('/', get_guest_requests, method='GET'),
            create_route('/', create_guest_request_v0_0_17, method='POST'),
            create_route('/{guestname}', get_guest_request),  # noqa: FS003
            create_route('/{guestname}', delete_guest, method='DELETE'),  # noqa: FS003
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),  # noqa: FS003
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),  # noqa: FS003
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST')  # noqa: FS003,E501
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),  # noqa: FS003
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')  # noqa: FS003
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [  # noqa: FS003
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name=f'{name_prefix}OpenAPIUIHandler')),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


#: API milestones: describes milestone API version, its route generator, and optionally also compatible
#: API versions. Based on this list, routes are created with proper endpoints, and possibly redirected
#: when necessary.
API_MILESTONES: List[Tuple[str, RouteGeneratorOuterType, List[str]]] = [
    # NEW: added hostname HW constraint
    ('v0.0.38', generate_routes_v0_0_38, [
        # For lazy clients who don't care about the version, our most current API version should add
        # `/current` redirected to itself.
        'current',

        # For clients that did not switch to versioned API yet, keep top-level endpoints.
        # TODO: this one's supposed to disappear once everyone switches to versioned API endpoints
        'toplevel'
    ]),
    # NEW: virtualization HW constraint
    ('v0.0.37', generate_routes_v0_0_37, []),
    # NEW: current worker tasks
    # NEW: boot.method HW constraint
    ('v0.0.32', generate_routes_v0_0_32, []),
    # NEW: trigger pool info refresh
    # NEW: HW requirement changes - added `network`
    ('v0.0.28', generate_routes_v0_0_28, []),
    # NEW: HW requirement changes - refactored `disk`
    ('v0.0.27', generate_routes_v0_0_27, []),
    # NEW: allow log-types to be specified in guest request
    ('v0.0.26', generate_routes_v0_0_26, []),
    # NEW: allow skipping verify-ssh steps
    ('v0.0.24', generate_routes_v0_0_24, []),
    # NEW: user management
    ('v0.0.21', generate_routes_v0_0_21, []),
    # NEW: guest logs
    ('v0.0.20', generate_routes_v0_0_20, []),
    # NEW: environment.hw opens
    ('v0.0.19', generate_routes_v0_0_19, []),
    # NEW: /guest/$GUESTNAME/console/url
    ('v0.0.18', generate_routes_v0_0_18, []),
    ('v0.0.17', generate_routes_v0_0_17, [])
]

CURRENT_MILESTONE_VERSION = API_MILESTONES[0][0]


def run_app() -> molten.app.App:
    from molten.router import Include, Route

    logger = get_logger()

    # Load routing hook to populate our list of knobs with those created dynamicaly for custom policies - the hook
    # is loaded by workers, but those are completely different processes, therefore they would remain invisible
    # to us.
    if os.getenv('ARTEMIS_HOOK_ROUTE'):
        r_routing_hook = hook_engine('ROUTE')

        if r_routing_hook.is_error:
            r_routing_hook.unwrap_error().handle(logger)

            sys.exit(1)

    db = get_db(logger, application_name='artemis-api-server')
    cache = get_cache(logger)

    metrics_tree = metrics.Metrics()
    metrics_tree.register_with_prometheus(CollectorRegistry())

    if KNOB_WORKER_PROCESS_METRICS_ENABLED.value is True:
        metrics.WorkerMetrics.spawn_metrics_refresher(  # noqa: F841
            logger,
            f'api-{platform.node()}-{os.getpid()}',
            KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK.value,
            # TODO: try to find out the actual values
            lambda _unused: Ok((1, KNOB_API_THREADS.value))
        )

    components: List[molten.dependency_injection.Component[Any]] = [
        molten.settings.SettingsComponent(
            molten.settings.Settings({
                'logger': logger
            })
        ),
        SchemaComponent(),
        LoggerComponent(logger),
        DBComponent(db),
        CacheComponent(cache),
        GuestRequestManagerComponent(),
        GuestEventManagerComponent(),
        SnapshotRequestManagerComponent(),
        KnobManagerComponent(),
        CacheManagerComponent(),
        StatusManagerComponent(),
        UserManagerComponent(),
        AuthContextComponent(),
        MetricsComponent(metrics_tree)
    ]

    mw: List[Middleware] = [
        ResponseRendererMiddleware(),
        error_handler_middleware,
        authorization_middleware,
        prometheus_middleware
    ]

    # Type checking this call is hard, mypy complains about unexpected keyword arguments, and refactoring
    # didn't help at all, just yielded another kind of errors.
    metadata = molten.openapi.documents.Metadata(  # type: ignore[call-arg]
        title='Artemis API',
        description='Artemis provisioning system API.',
        version=__VERSION__
    )

    #
    # Current routes and API endpoints
    #
    # API provides following structure:
    #
    # * /current/<endpoints> - the most up-to-date API
    # * /$VERSION/<endpoints> - API implementation correspoding to the given version
    # * /<endpoints> - the same as `current` but deprecated - it will be removed once all clients switch
    # to version-prefixed endpoints.
    routes: List[Union[Route, Include]] = []

    for milestone_version, routes_generator, compatible_versions in API_MILESTONES:
        # Preload environment schema.
        r_schema = load_validation_schema(f'environment-{milestone_version}.yml')

        if r_schema.is_error:
            r_schema.unwrap_error().handle(logger)

            sys.exit(1)

        ENVIRONMENT_SCHEMAS[milestone_version] = r_schema.unwrap()

        # Create the base API endpoints of this version.
        logger.info(f'API: /{milestone_version}')

        routes += routes_generator(
            f'/{milestone_version}',
            f'{milestone_version}_',
            metadata
        )

        # Then create all compatible versions
        for compatible_version in compatible_versions:
            # If this version is the "current" version, make its environment schema available under `current` key.
            if compatible_version == 'current':
                ENVIRONMENT_SCHEMAS['current'] = ENVIRONMENT_SCHEMAS[milestone_version]

            # "toplevel" is a pseudo-version, similar to "current" - it's backed by "current", and its endpoints
            # have no version prefix. Once all clients lear to use versioned API, we will drop this dog-leg.
            if compatible_version == 'toplevel':
                logger.info(f'API: / => /{milestone_version}')

                endpoint_root = ''

            else:
                logger.info(f'API: /{compatible_version} => /{milestone_version}')

                endpoint_root = f'/{compatible_version}'

            routes += routes_generator(
                endpoint_root,
                f'legacy_{compatible_version}_',
                metadata,
                redirect_to_prefix=f'/{milestone_version}'
            )

    def log_routes() -> None:
        extracted_routes = []

        def _extract_routes(items: List[Union[Route, Include]], prefix: str = '') -> None:
            for item in items:
                if isinstance(item, Route):
                    extracted_routes.append(f'{prefix}{item.template} (name={item.name})')

                else:
                    _extract_routes(item.routes, prefix=f'{prefix}{item.prefix}')

        _extract_routes(routes)

        gluetool.log.log_dict(logger.debug, 'routes', extracted_routes)

    log_routes()

    return molten.app.App(
        components=components,
        middleware=mw,
        routes=routes,
        renderers=[
            JSONRenderer()
        ]
    )


def main() -> NoReturn:
    gunicorn_path = shutil.which('gunicorn')

    if not gunicorn_path:
        raise Exception('No "gunicorn" executable found')

    sys.stdout.flush()
    sys.stderr.flush()

    gunicorn_options: List[str] = []

    if KNOB_API_ENABLE_PROFILING.value is True:
        gunicorn_options += [
            '-c', 'src/tft/artemis/api/wsgi_profiler.py'
        ]

    gunicorn_options += [
        '--bind', '0.0.0.0:8001',
        '--workers', str(KNOB_API_PROCESSES.value),
        '--threads', str(KNOB_API_THREADS.value),
        '--access-logfile', '-',
        '--error-logfile', '-'
    ]

    if KNOB_API_ENGINE_DEBUG.value is True:
        gunicorn_options += [
            '--log-level', 'debug'
        ]

    if KNOB_API_ENGINE_RELOAD_ON_CHANGE.value is True:
        gunicorn_options += [
            '--reload'
        ]

    if KNOB_LOGGING_JSON.value is True:
        # See https://docs.gunicorn.org/en/stable/settings.html#access-log-format
        gunicorn_options += [
            '--access-logformat',
            json.dumps({
                'client': '%(h)s',
                'request_method': '%(m)s',
                'request_path': '%(U)s',
                'request_query_string': '%(q)s',
                'request_status_line': '%(r)s',
                'request_user_agent': '%(a)s',
                'response_code': '%(s)s',
                'response_length': '%(B)s',
                'duration': '%(D)s'
            })
        ]

    if KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value != 0:
        gunicorn_options += [
            '--max-requests', str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value),
            '--max-requests-jitter', str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD.value)
        ]

    os.execve(
        gunicorn_path,
        [
            'gunicorn'
        ] + gunicorn_options + [
            'tft.artemis.api:run_app()'
        ],
        os.environ
    )


if __name__ == '__main__':
    main()
