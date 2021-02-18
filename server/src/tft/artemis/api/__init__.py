import datetime
import io
import json
import os
import shutil
import sys
import threading
import uuid
from inspect import Parameter
from typing import Any, Dict, List, NoReturn, Optional, Type, Union

import gluetool.log
import molten
import molten.dependency_injection
import molten.openapi
import sqlalchemy
import sqlalchemy.orm.exc
from gluetool.log import log_dict
from molten import HTTP_200, HTTP_201, HTTP_400, HTTP_404, Field, Request, Response
from molten.app import BaseApp
# from molten.contrib.prometheus import prometheus_middleware
from molten.middleware import ResponseRendererMiddleware
from molten.openapi.handlers import OpenAPIHandler as _OpenAPIHandler
from molten.openapi.handlers import OpenAPIUIHandler
from molten.typing import Middleware
from prometheus_client import CollectorRegistry

from .. import __VERSION__, DATABASE, Knob
from .. import db as artemis_db
from .. import get_db, get_logger, log_guest_event, metrics, safe_db_change
from ..guest import GuestState
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

#: Protects our metrics tree when updating & rendering to user.
METRICS_LOCK = threading.Lock()


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

    def resolve(self, request: Request) -> AuthContext:
        r_ctx = AuthContext.extract(request)

        # If the context does not exist, it means we have a handler that requests it, by adding
        # corresponding parameter, but auth middleware did not create it - the most likely chance
        # is the handler takes care of path that is marked as "auth not needed".
        if r_ctx.is_error:
            failure = r_ctx.unwrap_error()

            failure.handle(get_logger())

            # We cannot continue: handler requires auth context, and we don't have any. It's not possible to
            # recover.
            raise Exception(failure.message)

        return r_ctx.unwrap()


def perform_safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    conflict_error: Union[Type[errors.ConflictError], Type[errors.NoSuchEntityError]] = errors.ConflictError
) -> None:
    """
    Helper for handling :py:func:`safe_db_change` in the same manner. Performs the query and tests the result:

    * raise ``500 Internal Server Error`` if the change failed,
    * raise ``conflict_error`` if the query didn't fail but changed no records,
    * do nothing and return when the query didn't fail and changed expected number of records.
    """

    r_change = safe_db_change(logger, session, query)

    if r_change.is_error:
        raise errors.InternalServerError(logger=logger, caused_by=r_change.unwrap_error())

    if not r_change.unwrap():
        raise conflict_error(logger=logger)


@molten.schema
class EnvironmentOs:
    compose: str

    def serialize_to_json(self) -> Dict[str, Any]:
        return {'compose': self.compose}


@molten.schema
class Environment:
    arch: str
    os: EnvironmentOs
    pool: Optional[str] = Field(default=None)
    snapshots: bool = Field(default=False)

    def serialize_to_json(self) -> Dict[str, Any]:
        return {
            'arch': self.arch,
            'os': self.os.serialize_to_json(),
            'pool': self.pool,
            'snapshots': self.snapshots
        }


@molten.schema
class GuestRequest:
    keyname: str
    environment: Environment
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

    def __init__(
        self,
        guestname: str,
        owner: str,
        environment: Dict[str, Any],
        address: Optional[str],
        ssh: GuestSSHInfo,
        state: GuestState,
        user_data: Dict[str, Optional[str]],
        post_install_script: Optional[str],
        ctime: datetime.datetime
    ) -> None:
        self.guestname = guestname
        self.owner = owner
        self.environment = environment
        self.address = address
        self.ssh = ssh
        self.state = state.value
        self.user_data = user_data
        self.post_install_script = post_install_script
        self.ctime = ctime

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
            ctime=guest.ctime
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


class SnapshotResponse:
    snapshotname: str
    guestname: str
    state: GuestState

    def __init__(
        self,
        snapshotname: str,
        guestname: str,
        state: GuestState

    ) -> None:
        self.snapshotname = snapshotname
        self.guestname = guestname
        self.state = state.value

    @classmethod
    def from_db(cls, snapshot_request: artemis_db.SnapshotRequest):
        # type: (...) -> SnapshotResponse

        return cls(
            snapshotname=snapshot_request.snapshotname,
            guestname=snapshot_request.guestname,
            state=GuestState(snapshot_request.state)
        )


class AboutResponse:
    package_version: str
    image_digest: Optional[str]
    image_url: Optional[str]


class APIResponse(Response):  # type: ignore
    ''' Class that represents API response structure.
        An instance of this class should be returned by routes.

        :param object obj: Schema instance (for example GuestRequest).
        :param str status: HTTP status code string.
        :param dict headers: HTTP response headers.
        :param str content: JSON-serializable string that will be used as response's body
        :param stream: bytes-like string that will be used as response's body
        :param str encoding: Data encoding
        :parame Request request: Request instance
    '''

    def __init__(
        self,
        obj: Optional[Union[Any, List[Any]]] = None,
        status: str = HTTP_200,
        headers: Optional[Dict[Any, Any]] = None,
        content: Optional[str] = None,
        stream: Optional[Union[bytes, str]] = None,
        encoding: str = 'utf-8',
        request: Optional[Request] = None
    ) -> None:

        def _convert_values(value: Any) -> Any:
            if isinstance(value, datetime.datetime):
                return str(value)

            return value.__dict__

        if obj is not None:

            header = 'Content-Type'
            hvalue = 'application/json'

            if headers is None:
                headers = {header: hvalue}
            elif header not in headers:
                headers[header] = hvalue

            try:
                content = json.dumps(obj, default=_convert_values, sort_keys=True)
            except (TypeError, OverflowError):
                error_msg = 'object is not JSON serializable'
                log = get_logger()
                log_dict(log.debug, error_msg, obj.__dict__)
                status = HTTP_400
                content = json.dumps({'message': error_msg})
                stream = None

        if isinstance(stream, str):
            stream = stream.encode(encoding)

        super(APIResponse, self).__init__(status=status,
                                          headers=headers,
                                          content=content,
                                          stream=io.BytesIO(stream or b''),
                                          encoding=encoding)


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

    def create(self, guest_request: GuestRequest, ownername: str) -> GuestResponse:
        from ..tasks import get_guest_logger

        guestname = str(uuid.uuid4())

        guest_logger = get_guest_logger('create-guest-request', get_logger(), guestname)

        with self.db.get_session() as session:
            session.add(
                artemis_db.GuestRequest(
                    guestname=guestname,
                    environment=json.dumps(guest_request.environment.serialize_to_json()),
                    ownername=DEFAULT_GUEST_REQUEST_OWNER,
                    ssh_keyname=guest_request.keyname,
                    ssh_port=DEFAULT_SSH_PORT,
                    ssh_username=DEFAULT_SSH_USERNAME,
                    priorityname=guest_request.priority_group,
                    poolname=None,
                    pool_data=json.dumps({}),
                    user_data=json.dumps(guest_request.user_data),
                    state=GuestState.PENDING.value,
                    post_install_script=guest_request.post_install_script,
                )
            )

            # update metrics counter for total guest requests
            metrics.ProvisioningMetrics.inc_requested(session)

        gr = self.get_by_guestname(guestname)

        assert gr is not None

        # add guest event
        with self.db.get_session() as session:
            log_guest_event(
                guest_logger,
                session,
                gr.guestname,
                'created',
                **{
                    'user_data': guest_request.user_data
                }
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

    def delete_by_guestname(self, guestname: str, request: Request) -> None:
        from ..tasks import get_guest_logger

        guest_logger = get_guest_logger('delete-guest-request', get_logger(), guestname)

        with self.db.get_session() as session:
            snapshot_count_subquery = session \
                .query(sqlalchemy.func.count(artemis_db.SnapshotRequest.snapshotname).label('snapshot_count')) \
                .filter(artemis_db.SnapshotRequest.guestname == guestname) \
                .subquery('t')

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
            return [
                GuestEvent.from_db(event_record)
                for event_record in artemis_db.GuestEvent.fetch(
                    session,
                    page=page,
                    page_size=page_size,
                    sort_field=sort_field,
                    sort_direction=sort_by,
                    since=since,
                    until=until
                )
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
            return [
                GuestEvent.from_db(event_record)
                for event_record in artemis_db.GuestEvent.fetch(
                    session,
                    guestname=guestname,
                    page=page,
                    page_size=page_size,
                    sort_field=sort_field,
                    sort_direction=sort_by,
                    since=since,
                    until=until
                )
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

    def create_snapshot(self, guestname: str, snapshot_request: SnapshotRequest) -> SnapshotResponse:
        snapshotname = str(uuid.uuid4())

        with self.db.get_session() as session:
            session.add(
                artemis_db.SnapshotRequest(
                    snapshotname=snapshotname,
                    guestname=guestname,
                    poolname=None,
                    state=GuestState.PENDING.value,
                    start_again=snapshot_request.start_again
                )
            )

        snapshot_response = self.get_snapshot(guestname, snapshotname)

        assert snapshot_response is not None

        return snapshot_response

    def delete_snapshot(self, guestname: str, snapshotname: str) -> None:
        from ..tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', get_logger(), guestname, snapshotname)

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

    def restore_snapshot(self, guestname: str, snapshotname: str) -> SnapshotResponse:
        from ..tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', get_logger(), guestname, snapshotname)

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


#
# Routes
#
def get_guest_requests(manager: GuestRequestManager, request: Request) -> APIResponse:
    return APIResponse(manager.get_guest_requests(), request=request)


def create_guest_request(
    guest_request: GuestRequest,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext
) -> APIResponse:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = DEFAULT_GUEST_REQUEST_OWNER

    return APIResponse(manager.create(guest_request, ownername=ownername), request=request, status=HTTP_201)


def get_guest_request(guestname: str, manager: GuestRequestManager, request: Request) -> APIResponse:
    guest_response = manager.get_by_guestname(guestname)

    if guest_response is None:
        raise errors.NoSuchEntityError(request=request)

    return APIResponse(guest_response, request=request)


def delete_guest(guestname: str, request: Request, manager: GuestRequestManager) -> APIResponse:
    if not manager.get_by_guestname(guestname):
        return APIResponse(request=request, status=HTTP_404)

    manager.delete_by_guestname(guestname, request=request)

    return APIResponse(request=request)


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
) -> APIResponse:
    params: Dict[str, Any] = _validate_events_params(request)
    events = manager.get_events(**params)
    return APIResponse(events)


def get_guest_events(guestname: str, request: Request, manager: GuestEventManager) -> APIResponse:
    params: Dict[str, Any] = _validate_events_params(request)
    events = manager.get_events_by_guestname(guestname, **params)
    return APIResponse(events, request=request)


def get_metrics(request: Request, db: artemis_db.DB, metrics_tree: 'metrics.Metrics') -> APIResponse:
    DATABASE.set(db)

    with METRICS_LOCK:
        return APIResponse(
            stream=metrics_tree.render_prometheus_metrics(),
            request=request
        )


def get_snapshot_request(guestname: str, snapshotname: str, manager: SnapshotRequestManager) -> APIResponse:
    snapshot_response = manager.get_snapshot(guestname, snapshotname)

    if snapshot_response is None:
        raise errors.NoSuchEntityError()

    return APIResponse(snapshot_response)


def create_snapshot_request(guestname: str,
                            snapshot_request: SnapshotRequest,
                            manager: SnapshotRequestManager) -> APIResponse:
    return APIResponse(manager.create_snapshot(guestname, snapshot_request), status=HTTP_201)


def delete_snapshot(guestname: str, snapshotname: str, manager: SnapshotRequestManager) -> APIResponse:
    manager.delete_snapshot(guestname, snapshotname)
    return APIResponse()


def restore_snapshot_request(guestname: str, snapshotname: str, manager: SnapshotRequestManager) -> APIResponse:
    return APIResponse(manager.restore_snapshot(guestname, snapshotname), status=HTTP_201)


def get_about(request: Request) -> APIResponse:
    response = AboutResponse()
    response.package_version = __VERSION__
    response.image_digest = os.getenv('ARTEMIS_IMAGE_DIGEST')
    response.image_url = os.getenv('ARTEMIS_IMAGE_URL')

    return APIResponse(response, request=request)


class OpenAPIHandler(_OpenAPIHandler):
    """
    Dynamically generates and serves OpenAPI v3 documents based on the current application object. Once
    generated, the document is subsequently served from cache.

    This custom handler was implemented to replace :py:class:`molten.openapi.handlers.OpenAPIHandler`,
    which returns ``dict`` instead of :py:class:`molten.Response`. Ideally, we need every route to return
    :py:class:`molten.Response` (or :py:class:`APIResponse`) so that we can use middleware that is designed
    to work with :py:class:`molten.Response` and just stay consistent in general.
    """

    def __call__(self, app: BaseApp) -> Response:
        super(OpenAPIHandler, self).__call__(app)

        return Response(
            status=HTTP_200,
            content=json.dumps(self.document),
            headers={'Content-Type': 'application/json'}
        )


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
        DBComponent(db),
        GuestRequestManagerComponent(),
        GuestEventManagerComponent(),
        SnapshotRequestManagerComponent(),
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

    routes: List[Union[Route, Include]] = [
        Include('/guests', [
            Route('/', get_guest_requests, method='GET'),
            Route('/', create_guest_request, method='POST'),
            Route('/{guestname}', get_guest_request),
            Route('/{guestname}', delete_guest, method='DELETE'),
            Route('/events', get_events),
            Route('/{guestname}/events', get_guest_events),
            Route('/{guestname}/snapshots', create_snapshot_request, method='POST'),
            Route('/{guestname}/snapshots/{snapshotname}', get_snapshot_request, method='GET'),
            Route('/{guestname}/snapshots/{snapshotname}', delete_snapshot, method='DELETE'),
            Route('/{guestname}/snapshots/{snapshotname}/restore', restore_snapshot_request, method='POST')
        ]),
        Route('/metrics', get_metrics),
        Route('/about', get_about),
        Route('/_docs', OpenAPIUIHandler()),
        Route('/_schema', OpenAPIHandler(metadata=metadata))
    ]

    return molten.app.App(
        components=components,
        middleware=mw,
        routes=routes
    )


def main() -> NoReturn:
    gunicorn_path = shutil.which('gunicorn')

    if not gunicorn_path:
        raise Exception('No "gunicorn" executable found')

    sys.stdout.flush()
    sys.stderr.flush()

    gunicorn_options = [
        '--bind', '0.0.0.0:8001',
        '--reload',
        '--workers', str(KNOB_API_PROCESSES.value),
        '--threads', str(KNOB_API_THREADS.value)
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
