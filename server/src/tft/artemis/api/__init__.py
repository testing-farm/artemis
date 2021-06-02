import dataclasses
import datetime
import enum
import functools
import json
import os
import shutil
import sys
import threading
import uuid
from inspect import Parameter
from typing import Any, Callable, Dict, List, NoReturn, Optional, Tuple, Type, Union

import gluetool.log
import gluetool.utils
import molten
import molten.dependency_injection
import molten.openapi
import sqlalchemy
import sqlalchemy.orm.exc
from molten import HTTP_200, HTTP_201, HTTP_204, Include, Request, Response, Route
from molten.app import BaseApp
# from molten.contrib.prometheus import prometheus_middleware
from molten.middleware import ResponseRendererMiddleware
from molten.openapi.handlers import OpenAPIHandler as _OpenAPIHandler
from molten.openapi.handlers import OpenAPIUIHandler
from molten.typing import Middleware
from prometheus_client import CollectorRegistry
from typing_extensions import Protocol

from .. import __VERSION__, FailureDetailsType, JSONSchemaType, Knob
from .. import db as artemis_db
from .. import get_db, get_logger, load_validation_schema, log_guest_event, metrics, safe_db_change, validate_data
from ..context import DATABASE, LOGGER
from ..guest import GuestState
from ..tasks import get_snapshot_logger
from . import errors
from .middleware import AuthContext, authorization_middleware, error_handler_middleware, prometheus_middleware

DEFAULT_GUEST_REQUEST_OWNER = 'artemis'

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USERNAME = 'root'

DEFAULT_EVENTS_PAGE = 1
DEFAULT_EVENTS_PAGE_SIZE = 20
DEFAULT_EVENTS_SORT_FIELD = 'updated'
DEFAULT_EVENTS_SORT_BY = 'desc'


#: Number of processes to spawn for servicing API requests.
KNOB_API_PROCESSES: Knob[int] = Knob(
    'api.processes',
    has_db=False,
    envvar='ARTEMIS_API_PROCESSES',
    envvar_cast=int,
    default=1
)

#: Number of threads to spawn in each process for servicing API requests.
KNOB_API_THREADS: Knob[int] = Knob(
    'api.threads',
    has_db=False,
    envvar='ARTEMIS_API_THREADS',
    envvar_cast=int,
    default=1
)

#: If enabled, APi server will profile handling of each request, emitting a summary into log.
KNOB_API_ENABLE_PROFILING: Knob[bool] = Knob(
    'api.profiling.enabled',
    has_db=False,
    envvar='ARTEMIS_API_ENABLE_PROFILING',
    envvar_cast=gluetool.utils.normalize_bool_option,
    default=False
)

#: How many functions should be included in the summary.
KNOB_API_PROFILE_LIMIT: Knob[int] = Knob(
    'api.profiling.limit',
    has_db=False,
    envvar='ARTEMIS_API_PROFILING_LIMIT',
    envvar_cast=int,
    default=20
)

#: Reload API server when its code changes.
KNOB_API_ENGINE_RELOAD_ON_CHANGE: Knob[bool] = Knob(
    'api.engine.reload-on-change',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_ON_CHANGE',
    envvar_cast=gluetool.utils.normalize_bool_option,
    default=False
)

#: Run engine with a debugging enabled.
KNOB_API_ENGINE_DEBUG: Knob[bool] = Knob(
    'api.engine.debug',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_DEBUG',
    envvar_cast=gluetool.utils.normalize_bool_option,
    default=False
)

#: Protects our metrics tree when updating & rendering to user.
METRICS_LOCK = threading.Lock()


# Will be filled with the actual schema during API server bootstrap.
ENVIRONMENT_SCHEMAS: Dict[str, JSONSchemaType] = {}


def _validate_environment(
    logger: gluetool.log.ContextAdapter,
    environment: Any,
    schema: JSONSchemaType,
    failure_details: Dict[str, str]
) -> None:
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

        return super(JSONRenderer, self).default(obj)


class LoggerComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, logger: gluetool.log.ContextAdapter) -> None:
        self.logger = logger

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is gluetool.log.ContextAdapter

    def resolve(self) -> gluetool.log.ContextAdapter:
        return self.logger


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

    r_change = safe_db_change(logger, session, query)

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
    user_data: Optional[Dict[str, Optional[str]]]
    post_install_script: Optional[str]


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
    user_data: Dict[str, Optional[str]]
    post_install_script: Optional[str]
    ctime: datetime.datetime
    console_url: Optional[str]
    console_url_expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, guest: artemis_db.GuestRequest):
        # type: (...) -> GuestResponse

        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            environment=json.loads(guest.environment),
            address=guest.address,
            ssh=GuestSSHInfo(
                guest.ssh_username,
                guest.ssh_port,
                guest.ssh_keyname
            ),
            state=GuestState(guest.state),
            user_data=json.loads(guest.user_data),
            post_install_script=guest.post_install_script,
            ctime=guest.ctime,
            console_url=guest.console_url,
            console_url_expires=guest.console_url_expires
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
    def from_db(cls, event: artemis_db.GuestEvent):
        # type: (...) -> GuestEvent

        return cls(
            eventname=event.eventname,
            guestname=event.guestname,
            details=json.loads(event.details) if event.details else {},
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
    def from_db(cls, snapshot_request: artemis_db.SnapshotRequest):
        # type: (...) -> SnapshotResponse

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
    value: str


@molten.schema
@dataclasses.dataclass
class AboutResponse:
    package_version: str
    image_digest: Optional[str]
    image_url: Optional[str]
    artemis_deployment: Optional[str]


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
        from ..tasks import dispatch_task, get_guest_logger, route_guest_request

        guestname = str(uuid.uuid4())

        failure_details = {
            'guestname': guestname
        }

        guest_logger = get_guest_logger('create-guest-request', logger, guestname)

        # Validate given environment specification
        _validate_environment(
            guest_logger,
            guest_request.environment,
            environment_schema,
            failure_details
        )

        # In v0.0.17, internal representation of environment changes, for some time it will not match the API
        # specification exactly. This situation will remain with us for couple of versions, until addition of
        # HW requirements settles down. Here we add code handling the possible issues.

        # COMPAT: internal `arch` is replaced with `hw.arch` - move `arch` to proper position, and drop it from
        # the input. Drop once API catches up with internal format.
        if 'arch' in guest_request.environment:
            guest_request.environment['hw'] = {
                'arch': guest_request.environment.pop('arch')
            }

        with self.db.get_session() as session:
            perform_safe_db_change(
                guest_logger,
                session,
                sqlalchemy.insert(artemis_db.GuestRequest.__table__).values(
                    guestname=guestname,
                    environment=json.dumps(guest_request.environment),
                    ownername=DEFAULT_GUEST_REQUEST_OWNER,
                    ssh_keyname=guest_request.keyname,
                    ssh_port=DEFAULT_SSH_PORT,
                    ssh_username=DEFAULT_SSH_USERNAME,
                    priorityname=guest_request.priority_group,
                    poolname=None,
                    pool_data=json.dumps({}),
                    user_data=json.dumps(guest_request.user_data),
                    state=GuestState.ROUTING.value,
                    post_install_script=guest_request.post_install_script,
                ),
                conflict_error=errors.InternalServerError,
                failure_details=failure_details
            )

            log_guest_event(
                guest_logger,
                session,
                guestname,
                'created',
                **{
                    'user_data': guest_request.user_data
                }
            )

            r_dispatch = dispatch_task(guest_logger, route_guest_request, guestname)

            if r_dispatch.is_error:
                # Now we're in a pickle. We successfully created a new guest request, but we failed to start
                # the provisioning chain of tasks. We can't retry too much, because we need to send a response
                # to client Soon (TM), and we can't leave the guest request in the database, because we won't
                # provision it. We could try to remove it, but what if we fail to do so? We risk we'd be stuck
                # with an orphaned guest request.
                #
                # Transactions probably would help - we could prepare the addition, but not commit the change,
                # try to dispatch and only commit when we succeed. But there's a race condition: what if the
                # freshly dispatched task is executed before our commit and finds no guest record?
                #
                # At this moment, we try to do the following: at least handle the dispatch failure, then try to
                # remove the record from database - and report a internal error in any case.

                r_dispatch.unwrap_error().handle(guest_logger)

                perform_safe_db_change(
                    guest_logger,
                    session,
                    sqlalchemy.delete(artemis_db.GuestRequest.__table__).where(
                        artemis_db.GuestRequest.guestname == guestname
                    ),
                    conflict_error=errors.InternalServerError,
                    failure_details=failure_details
                )

                # We successfully removed the request, but return the internal error anyway because of the
                # failed dispatch.
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_dispatch.unwrap_error(),
                    failure_details=failure_details
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
        from ..tasks import dispatch_task, get_guest_logger, release_guest_request

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

            if guest_request.state != GuestState.CONDEMNED.value:
                snapshot_count_subquery = session.query(  # type: ignore # untyped function "query"
                    sqlalchemy.func.count(artemis_db.SnapshotRequest.snapshotname).label('snapshot_count')
                ).filter(
                    artemis_db.SnapshotRequest.guestname == guestname
                ).subquery('t')

                query = sqlalchemy \
                    .update(artemis_db.GuestRequest.__table__) \
                    .where(artemis_db.GuestRequest.guestname == guestname) \
                    .where(snapshot_count_subquery.c.snapshot_count == 0) \
                    .values(state=GuestState.CONDEMNED.value)

                # The query can miss either with existing snapshots, or when the guest request has been
                # removed from DB already. The "gone already" situation could be better expressed by
                # returning "404 Not Found", but we can't tell which of these two situations caused the
                # change to go vain, therefore returning general "409 Conflict", expressing our believe
                # user should resolve the conflict and try again.
                perform_safe_db_change(guest_logger, session, query)

                log_guest_event(guest_logger, session, guestname, 'condemned')

            r_dispatch = dispatch_task(guest_logger, release_guest_request, guestname)

            if r_dispatch.is_error:
                # This looks like a problem: we already marked the request as condemned, but we failed to dispatch
                # the task. We can't undo that change, because we did not bother to save the original state.
                #
                # But this does not have to be an issue, because we can freely report this error to user, and
                # ask him to try again since this change is idempotent - when marking the request as condemned,
                # we don't check its current state. If the request is already condemned, we merely proceed to
                # dispatch the task.
                #
                # This is not a perfect solution: if we fail to dispatch the task, we report the error and expect
                # user to try again. User may decide to give up, leaving us with a condemned request and no release
                # task to take care of it.
                #
                # The other possible course of action - mark the request as condemned and then use a dispatcher
                # process to dispatch the task asynchronously - has its own issues. For example, when facing excess
                # of messages to process, workers may take time to reach the release task we scheduled - dispatcher
                # would keep dispatching the task because the request still exists and is still marked as condemned,
                # adding even more messages to the mix.
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_dispatch.unwrap_error(),
                    failure_details=failure_details
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
        page: int = DEFAULT_EVENTS_PAGE,
        page_size: int = DEFAULT_EVENTS_PAGE_SIZE,
        sort_field: str = DEFAULT_EVENTS_SORT_FIELD,
        sort_by: str = DEFAULT_EVENTS_SORT_BY,
        since: Optional[str] = None,
        until: Optional[str] = None,
        **kwargs: Optional[Dict[str, Any]]
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_by,
                since=since,
                until=until
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
        page: int = DEFAULT_EVENTS_PAGE,
        page_size: int = DEFAULT_EVENTS_PAGE_SIZE,
        sort_field: str = DEFAULT_EVENTS_SORT_FIELD,
        sort_by: str = DEFAULT_EVENTS_SORT_BY,
        since: Optional[str] = None,
        until: Optional[str] = None,
        **kwargs: Optional[Dict[str, Any]]
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                guestname=guestname,
                page=page,
                page_size=page_size,
                sort_field=sort_field,
                sort_direction=sort_by,
                since=since,
                until=until
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
                    state=GuestState.PENDING.value,
                    start_again=snapshot_request.start_again
                ),
                conflict_error=errors.InternalServerError,
                failure_details=failure_details
            )

            log_guest_event(
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
                .values(state=GuestState.CONDEMNED.value)

            # Unline guest requests, here seem to be no possibility of conflict or relationships we must
            # preserve. Given the query, snapshot request already being removed seems to be the only option
            # here - what else could cause the query *not* marking the record as condemned?
            perform_safe_db_change(snapshot_logger, session, query, conflict_error=errors.NoSuchEntityError)

            log_guest_event(snapshot_logger, session, guestname, 'snapshot-condemned')

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
                .where(artemis_db.SnapshotRequest.state != GuestState.CONDEMNED.value) \
                .values(state=GuestState.RESTORING.value)

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
    def entry_get_knobs(manager: 'KnobManager') -> Tuple[str, List[KnobResponse]]:
        return HTTP_200, manager.get_knobs()

    @staticmethod
    def entry_get_knob(manager: 'KnobManager', knobname: str) -> KnobResponse:
        response = manager.get_knob(knobname)

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

        response = manager.get_knob(knobname)

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

    def get_knobs(self) -> List[KnobResponse]:
        with self.db.get_session() as session:
            r_knobs = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .all()

            if r_knobs.is_error:
                raise errors.InternalServerError(caused_by=r_knobs.unwrap_error())

            return [
                KnobResponse(name=knob.knobname, value=knob.value)
                for knob in r_knobs.unwrap()
            ]

    def get_knob(self, knobname: str) -> Optional[KnobResponse]:
        with self.db.get_session() as session:
            r_knob = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .filter(artemis_db.Knob.knobname == knobname) \
                .one_or_none()

            if r_knob.is_error:
                raise errors.InternalServerError(caused_by=r_knob.unwrap_error())

            knob_record = r_knob.unwrap()

            if knob_record is None:
                return None

            return KnobResponse(
                name=knob_record.knobname,
                value=knob_record.value
            )

    def set_knob(self, knobname: str, value: str, logger: gluetool.log.ContextAdapter) -> None:
        with self.db.get_session() as session:
            artemis_db.upsert(
                logger,
                session,
                artemis_db.Knob,
                {
                    artemis_db.Knob.knobname: knobname
                },
                insert_data={
                    artemis_db.Knob.value: value
                },
                update_data={
                    'value': value
                }
            )

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

    def _get_pool_object_infos(self, logger: gluetool.log.ContextAdapter, poolname: str, method_name: str) -> Response:
        from ..tasks import _get_pool

        with self.db.get_session() as session:
            r_pool = _get_pool(logger, session, poolname)

            if r_pool.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_pool.unwrap_error(),
                    failure_details={
                        'poolname': poolname
                    }
                )

            pool = r_pool.unwrap()

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
                content=json.dumps({
                    info.name: info.serialize_to_json()
                    for info in r_infos.unwrap()
                }),
                headers={'Content-Type': 'application/json'}
            )

    def get_pool_image_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_image_infos')

    def get_pool_flavor_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_flavor_infos')


class CacheManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is CacheManager or parameter.annotation == 'CacheManager'

    def resolve(self, db: artemis_db.DB) -> CacheManager:
        return CacheManager(db)


#
# Routes
#
def get_guest_requests(manager: GuestRequestManager, request: Request) -> Tuple[str, List[GuestResponse]]:
    return HTTP_200, manager.get_guest_requests()


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


def _validate_events_params(request: Request) -> Dict[str, Any]:
    '''Not a route, utility function to validate URL params for all */events routes'''

    req_params = request.params
    params: Dict[str, Any] = {}

    try:
        page_param = req_params.get('page')
        page_size_param = req_params.get('page_size')
        params['page'] = int(page_param) if page_param else DEFAULT_EVENTS_PAGE
        params['page_size'] = int(page_size_param) if page_size_param else DEFAULT_EVENTS_PAGE_SIZE
        params['sort_field'] = req_params.get('sort_field', DEFAULT_EVENTS_SORT_FIELD)
        params['sort_by'] = req_params.get('sort_by', DEFAULT_EVENTS_SORT_BY)
        params['since'] = req_params.get('since')
        params['until'] = req_params.get('until')
    except (ValueError, AttributeError):
        raise errors.BadRequestError(request=request)

    if params['sort_field'] not in filter(lambda x: not x.startswith('_'), artemis_db.GuestEvent.__dict__) or \
       params['sort_by'] not in ('asc', 'desc'):
        raise errors.BadRequestError(request=request)

    return params


def get_events(
        request: Request,
        manager: GuestEventManager,
) -> Tuple[str, List[GuestEvent]]:
    params: Dict[str, Any] = _validate_events_params(request)
    return HTTP_200, manager.get_events(**params)


def get_guest_events(guestname: str, request: Request, manager: GuestEventManager) -> Tuple[str, List[GuestEvent]]:
    params: Dict[str, Any] = _validate_events_params(request)
    return HTTP_200, manager.get_events_by_guestname(guestname, **params)


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


def get_about(request: Request) -> AboutResponse:
    """
    Some docs.
    """

    return AboutResponse(
        package_version=__VERSION__,
        image_digest=os.getenv('ARTEMIS_IMAGE_DIGEST'),
        image_url=os.getenv('ARTEMIS_IMAGE_URL'),
        artemis_deployment=os.getenv('ARTEMIS_DEPLOYMENT')
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

    def __call__(self, app: BaseApp) -> Response:  # type: ignore # return type incomaptible with supertype
        super(OpenAPIHandler, self).__call__(app)

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

    return Route(template, handler, method=method, name='{}{}'.format(name_prefix, handler.__name__))


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

                return Route(template, real_handler, method=method, name='{}{}'.format(name_prefix, handler.__name__))

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
            create_route('/{guestname}', get_guest_request),
            create_route('/{guestname}', delete_guest, method='DELETE'),
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),
            create_route('/{guestname}/console/url', acquire_guest_console_url, method='GET')
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name='{}OpenAPIUIHandler'.format(name_prefix))),
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
            create_route('/{guestname}', get_guest_request),
            create_route('/{guestname}', delete_guest, method='DELETE'),
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST'),
            create_route('/{guestname}/console/url', acquire_guest_console_url, method='GET')
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name='{}OpenAPIUIHandler'.format(name_prefix))),
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
            create_route('/{guestname}', get_guest_request),
            create_route('/{guestname}', delete_guest, method='DELETE'),
            create_route('/events', get_events),
            create_route('/{guestname}/events', get_guest_events),
            create_route('/{guestname}/snapshots', create_snapshot_request, method='POST'),
            create_route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),
            create_route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),
            create_route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST')
        ]),
        Include('/knobs', [
            create_route('/', KnobManager.entry_get_knobs, method='GET'),
            create_route('/{knobname}', KnobManager.entry_get_knob, method='GET'),
            create_route('/{knobname}', KnobManager.entry_set_knob, method='PUT'),
            create_route('/{knobname}', KnobManager.entry_delete_knob, method='DELETE')
        ]),
        create_route('/metrics', get_metrics),
        create_route('/about', get_about),
        Include('/_cache', [
            Include('/pools/{poolname}', [
                create_route('/image-info', CacheManager.entry_pool_image_info),
                create_route('/flavor-info', CacheManager.entry_pool_flavor_info)
            ])
        ]),
        create_route('/_docs', OpenAPIUIHandler(schema_route_name='{}OpenAPIUIHandler'.format(name_prefix))),
        create_route('/_schema', OpenAPIHandler(metadata=metadata))
    ]


#: API milestones: describes milestone API version, its route generator, and optionally also compatible
#: API versions. Based on this list, routes are created with proper endpoints, and possibly redirected
#: when necessary.
API_MILESTONES: List[Tuple[str, RouteGeneratorOuterType, List[str]]] = [
    # NEW: environment.hw opens
    ('v0.0.19', generate_routes_v0_0_19, [
        # For lazy clients who don't care about the version, our most current API version should add
        # `/current` redirected to itself.
        'current',

        # For clients that did not switch to versioned API yet, keep top-level endpoints.
        # TODO: this one's supposed to disappear once everyone switches to versioned API endpoints
        'toplevel'
    ]),
    # NEW: /guest/$GUESTNAME/console/url
    ('v0.0.18', generate_routes_v0_0_18, []),
    ('v0.0.17', generate_routes_v0_0_17, [])
]

CURRENT_MILESTONE_VERSION = API_MILESTONES[0][0]


def run_app() -> molten.app.App:
    from molten.router import Include, Route

    logger = get_logger()
    db = get_db(logger, application_name='artemis-api-server')

    metrics_tree = metrics.Metrics()
    metrics_tree.register_with_prometheus(CollectorRegistry())

    components: List[molten.dependency_injection.Component[Any]] = [
        molten.settings.SettingsComponent(
            molten.settings.Settings({
                'logger': logger
            })
        ),
        LoggerComponent(logger),
        DBComponent(db),
        GuestRequestManagerComponent(),
        GuestEventManagerComponent(),
        SnapshotRequestManagerComponent(),
        KnobManagerComponent(),
        CacheManagerComponent(),
        AuthContextComponent(),
        MetricsComponent(metrics_tree)
    ]

# TODO: uncomment when registration is done
    mw: List[Middleware] = [
        # middleware.AuthorizationMiddleware,
        ResponseRendererMiddleware(),
        error_handler_middleware,
        authorization_middleware,
        prometheus_middleware
    ]

    # Type checking this call is hard, mypy complains about unexpected keyword arguments, and refactoring
    # didn't help at all, just yielded another kind of errors.
    metadata = molten.openapi.documents.Metadata(  # type: ignore
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
        r_schema = load_validation_schema('environment-{}.yml'.format(milestone_version))

        if r_schema.is_error:
            r_schema.unwrap_error().handle(logger)

            sys.exit(1)

        ENVIRONMENT_SCHEMAS[milestone_version] = r_schema.unwrap()

        # Create the base API endpoints of this version.
        logger.info('API: /{}'.format(milestone_version))

        routes += routes_generator(
            '/{}'.format(milestone_version),
            '{}_'.format(milestone_version),
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
                logger.info('API: / => /{}'.format(milestone_version))

                endpoint_root = ''

            else:
                logger.info('API: /{} => /{}'.format(compatible_version, milestone_version))

                endpoint_root = '/{}'.format(compatible_version)

            routes += routes_generator(
                endpoint_root,
                'legacy_{}_'.format(compatible_version),
                metadata,
                redirect_to_prefix='/{}'.format(milestone_version)
            )

    def log_routes() -> None:
        extracted_routes = []

        def _extract_routes(items: List[Union[Route, Include]], prefix: str = '') -> None:
            for item in items:
                if isinstance(item, Route):
                    extracted_routes.append('{}{} (name={})'.format(prefix, item.template, item.name))

                else:
                    _extract_routes(item.routes, prefix='{}{}'.format(prefix, item.prefix))

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
