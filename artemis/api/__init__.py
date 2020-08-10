import datetime
import json
import io
import os
import shutil
import sys
import sqlalchemy
import sqlalchemy.orm.exc
import uuid

import molten
import molten.dependency_injection
import molten.openapi
from molten import HTTP_201, HTTP_200, HTTP_400, Field, Response, Request
from molten.middleware import ResponseRendererMiddleware
from molten.typing import Middleware

from gluetool.log import log_dict

import artemis
import artemis.db
import artemis.guest
import artemis.snapshot

from artemis.api import errors, handlers
from artemis.metrics import generate_metrics
from artemis.api.middleware import error_handler_middleware, prometheus_middleware

from typing import Any, Dict, List, NoReturn, Optional, Union
from artemis.db import DB
from inspect import Parameter


DEFAULT_GUEST_REQUEST_OWNER = 'artemis'

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USERNAME = 'root'

DEFAULT_EVENTS_PAGE = 1
DEFAULT_EVENTS_PAGE_SIZE = 20
DEFAULT_EVENTS_SORT_FIELD = 'updated'
DEFAULT_EVENTS_SORT_BY = 'desc'


class DBComponent:
    is_cacheable = True
    is_singleton = True

    def __init__(self, db: DB) -> None:
        self.db = db

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is DB

    def resolve(self) -> DB:
        return self.db


@molten.schema
class GuestRequest:
    keyname: str = Field()
    environment: Dict[str, Any] = Field()
    priority_group: Optional[str] = Field()
    user_data: Optional[Dict[str, Optional[str]]] = Field()

    def __init__(
        self,
        keyname: str,
        environment: Dict[str, Any],
        priority_group: str,
        user_data: Optional[Dict[str, Optional[str]]]
    ) -> None:
        self.keyname = keyname
        self.environment = environment
        self.priority_group = priority_group
        self.user_data = user_data or {}


@molten.schema
class GuestSSHInfo:
    username: str = Field()
    port: int = Field()
    keyname: str = Field()

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
    guestname: str = Field()
    owner: str = Field()
    environment: Dict[str, Any] = Field()
    address: Optional[str] = Field()
    ssh: GuestSSHInfo = Field()
    state: artemis.guest.GuestState = Field()
    user_data: Dict[str, Optional[str]] = Field()

    def __init__(
        self,
        guestname: str,
        owner: str,
        environment: Dict[str, Any],
        address: Optional[str],
        ssh: GuestSSHInfo,
        state: artemis.guest.GuestState,
        user_data: Dict[str, Optional[str]]
    ) -> None:
        self.guestname = guestname
        self.owner = owner
        self.environment = environment
        self.address = address
        self.ssh = ssh
        self.state = state.value
        self.user_data = user_data

    @classmethod
    def from_db(cls, guest: artemis.db.GuestRequest):
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
            state=artemis.guest.GuestState(guest.state),
            user_data=json.loads(guest.user_data)
        )


@molten.schema
class GuestEvent:
    eventname: str = Field()

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
    def from_db(cls, event: artemis.db.GuestEvent):
        # type: (...) -> GuestEvent

        return cls(
            eventname=event.eventname,
            guestname=event.guestname,
            details=json.loads(event.details) if event.details else {},
            updated=event.updated
        )


@molten.schema
class SnapshotRequest:
    start_again: bool = Field()

    def __init__(
        self,
        start_again: bool,
    ) -> None:
        self.start_again = start_again


class SnapshotResponse:
    snapshotname: str = Field()
    guestname: str = Field()
    state: artemis.guest.GuestState = Field()

    def __init__(
        self,
        snapshotname: str,
        guestname: str,
        state: artemis.guest.GuestState

    ) -> None:
        self.snapshotname = snapshotname
        self.guestname = guestname
        self.state = state.value

    @classmethod
    def from_db(cls, snapshot_request: artemis.db.SnapshotRequest):
        # type: (...) -> SnapshotResponse

        return cls(
            snapshotname=snapshot_request.snapshotname,
            guestname=snapshot_request.guestname,
            state=artemis.guest.GuestState(snapshot_request.state)
        )


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
        request: Request = None
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
                log = artemis.get_logger()
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
    def __init__(self, db: DB) -> None:
        self.db = db

    def get_guest_requests(self) -> List[GuestResponse]:
        with self.db.get_session() as session:
            guests = session.query(artemis.db.GuestRequest).all()

            responses = [
                GuestResponse.from_db(guest) for guest in guests
            ]

        return responses

    def create(self, guest_request: GuestRequest) -> GuestResponse:
        guestname = str(uuid.uuid4())

        with self.db.get_session() as session:
            session.add(
                artemis.db.GuestRequest(
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
                    state=artemis.guest.GuestState.PENDING.value
                )
            )

            # update metrics table counter
            query = sqlalchemy \
                .update(artemis.db.Metrics.__table__) \
                .values({artemis.db.Metrics.count: artemis.db.Metrics.count + 1,
                         artemis.db.Metrics.updated: datetime.datetime.now()})

            artemis.safe_call(session.execute, query)

        gr = self.get_by_guestname(guestname)

        assert gr is not None

        # add guest event
        logger = artemis.get_logger()
        with self.db.get_session() as session:
            artemis.log_guest_event(
                logger,
                session,
                gr.guestname,
                'created',
                **{
                    'user_data': guest_request.user_data
                }
            )

        return gr

    def get_by_guestname(self, guestname: str) -> Optional[GuestResponse]:
        try:
            with self.db.get_session() as session:
                guest = session \
                        .query(artemis.db.GuestRequest) \
                        .filter(artemis.db.GuestRequest.guestname == guestname) \
                        .one()

                response = GuestResponse.from_db(guest)

        except sqlalchemy.orm.exc.NoResultFound:
            return None

        return response

    def delete_by_guestname(self, guestname: str, request: Request) -> None:
        with self.db.get_session() as session:
            query = sqlalchemy \
                    .update(artemis.db.GuestRequest.__table__) \
                    .where(artemis.db.GuestRequest.guestname == guestname) \
                    .values(state=artemis.guest.GuestState.CONDEMNED.value)

            logger = artemis.get_logger()
            if artemis.safe_db_execute(logger, session, query):
                # add guest event
                artemis.log_guest_event(
                    logger,
                    session,
                    guestname,
                    'condemned'
                )
                return

            raise errors.GenericError(request=request)


class GuestEventManager:
    def __init__(self, db: DB) -> None:
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
            query = session.query(artemis.db.GuestEvent)
            events = artemis.db.GuestEvent.sort(query, page, page_size, sort_field, sort_by, since, until)
            guest_events = [GuestEvent.from_db(event) for event in events]
            return guest_events

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
            query = session.query(artemis.db.GuestEvent) \
                .filter(artemis.db.GuestEvent.guestname == guestname)
            events = artemis.db.GuestEvent.sort(query, page, page_size, sort_field, sort_by, since, until)
            guest_events = [GuestEvent.from_db(event) for event in events]
            return guest_events


class GuestRequestManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is GuestRequestManager

    def resolve(self, db: DB) -> GuestRequestManager:
        return GuestRequestManager(db)


class GuestEventManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is GuestEventManager

    def resolve(self, db: DB) -> GuestEventManager:
        return GuestEventManager(db)


class SnapshotRequestManager:
    def __init__(self, db: DB) -> None:
        self.db = db

    def get_snapshot(self, guestname: str, snapshotname: str) -> Optional[SnapshotResponse]:
        try:
            with self.db.get_session() as session:
                snapshot = session \
                           .query(artemis.db.SnapshotRequest.__table__) \
                           .filter(artemis.db.SnapshotRequest.snapshotname == snapshotname) \
                           .filter(artemis.db.SnapshotRequest.guestname == guestname) \
                           .one()

                response = SnapshotResponse.from_db(snapshot)

        except sqlalchemy.orm.exc.NoResultFound:
            return None

        return response

    def create_snapshot(self, guestname: str, snapshot_request: SnapshotRequest) -> SnapshotResponse:
        snapshotname = str(uuid.uuid4())

        with self.db.get_session() as session:
            session.add(
                artemis.db.SnapshotRequest(
                    snapshotname=snapshotname,
                    guestname=guestname,
                    poolname=None,
                    state=artemis.guest.GuestState.PENDING.value,
                    start_again=snapshot_request.start_again
                )
            )

        snapshot_response = self.get_snapshot(guestname, snapshotname)

        assert snapshot_response is not None

        return snapshot_response

    def delete_snapshot(self, guestname: str, snapshotname: str) -> None:
        with self.db.get_session() as session:
            query = sqlalchemy \
                    .update(artemis.db.SnapshotRequest.__table__) \
                    .where(artemis.db.SnapshotRequest.snapshotname == snapshotname) \
                    .where(artemis.db.SnapshotRequest.guestname == guestname) \
                    .values(state=artemis.guest.GuestState.CONDEMNED.value)

            if artemis.safe_db_execute(artemis.get_logger(), session, query):
                return

            raise errors.GenericError()

    def restore_snapshot(self, guestname: str, snapshotname: str) -> SnapshotResponse:
        with self.db.get_session() as session:
            query = sqlalchemy \
                    .update(artemis.db.SnapshotRequest.__table__) \
                    .where(artemis.db.SnapshotRequest.snapshotname == snapshotname) \
                    .where(artemis.db.SnapshotRequest.guestname == guestname) \
                    .where(artemis.db.SnapshotRequest.state != artemis.guest.GuestState.CONDEMNED.value) \
                    .values(state=artemis.guest.GuestState.RESTORING.value)

            if artemis.safe_db_execute(artemis.get_logger(), session, query):
                snapshot_response = self.get_snapshot(guestname, snapshotname)

                assert snapshot_response is not None

                return snapshot_response

            raise errors.GenericError()


class SnapshotRequestManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is SnapshotRequestManager

    def resolve(self, db: DB) -> SnapshotRequestManager:
        return SnapshotRequestManager(db)


#
# Routes
#
def get_guest_requests(manager: GuestRequestManager, request: Request) -> APIResponse:
    return APIResponse(manager.get_guest_requests(), request=request)


def create_guest_request(guest_request: GuestRequest, manager: GuestRequestManager, request: Request) -> APIResponse:
    return APIResponse(manager.create(guest_request), request=request, status=HTTP_201)


def get_guest_request(guestname: str, manager: GuestRequestManager, request: Request) -> APIResponse:
    guest_response = manager.get_by_guestname(guestname)

    if guest_response is None:
        raise errors.NoSuchEntityError(request=request)

    return APIResponse(guest_response, request=request)


def delete_guest(guestname: str, request: Request, manager: GuestRequestManager) -> APIResponse:
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

    if params['sort_field'] not in filter(lambda x: not x.startswith('_'), artemis.db.GuestEvent.__dict__) or \
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


def get_metrics(request: Request) -> APIResponse:
    return APIResponse(stream=generate_metrics(), request=request)


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


def run_app() -> molten.app.App:
    from molten.router import Include, Route

    logger = artemis.get_logger()
    db = artemis.get_db(logger)

    components: List[molten.dependency_injection.Component[Any]] = [
        molten.settings.SettingsComponent(
            molten.settings.Settings({
                'logger': logger
            })
        ),
        DBComponent(db),
        GuestRequestManagerComponent(),
        GuestEventManagerComponent(),
        SnapshotRequestManagerComponent()
    ]

# TODO: uncomment when registration is done
    mw: List[Middleware] = [
        # middleware.AuthorizationMiddleware,
        ResponseRendererMiddleware(),
        error_handler_middleware,
        prometheus_middleware
    ]

    get_docs = molten.openapi.handlers.OpenAPIUIHandler()

    # Type checking this call is hard, mypy complains about unexpected keyword arguments, and refactoring
    # didn't help at all, just yielded another kind of errors.
    metadata = molten.openapi.documents.Metadata(  # type: ignore
        title='Artemis API',
        description='Artemis provisioning system API.',
        version='0.0.1'
    )

    get_schema = handlers.OpenAPIHandler(metadata=metadata)

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
        Route('/_docs', get_docs),
        Route('/_schema', get_schema),
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

    os.execve(
        gunicorn_path,
        [
            'gunicorn',
            '--bind', '0.0.0.0:8001',
            '--reload',
            'artemis.api:run_app()'
        ],
        os.environ
    )


if __name__ == '__main__':
    main()
