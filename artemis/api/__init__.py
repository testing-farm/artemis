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
from molten import HTTP_201, HTTP_200, Field, Response, Request
from molten.contrib.prometheus import prometheus_middleware
from molten.middleware import ResponseRendererMiddleware
from molten.typing import Middleware

from gluetool.log import log_dict

import artemis
import artemis.db
import artemis.guest
import artemis.snapshot

from artemis.api import errors, handlers
from artemis.metrics import generate_metrics

from typing import Any, Dict, List, NoReturn, Optional, Union
from artemis.db import DB
from inspect import Parameter


DEFAULT_GUEST_REQUEST_OWNER = 'artemis'

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USERNAME = 'root'


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

    def __init__(
        self,
        keyname: str,
        environment: Dict[str, Any],
        priority_group: str
    ) -> None:
        self.keyname = keyname
        self.environment = environment
        self.priority_group = priority_group


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

    def __init__(
        self,
        guestname: str,
        owner: str,
        environment: Dict[str, Any],
        address: Optional[str],
        ssh: GuestSSHInfo,
        state: artemis.guest.GuestState
    ) -> None:
        self.guestname = guestname
        self.owner = owner
        self.environment = environment
        self.address = address
        self.ssh = ssh
        self.state = state.value

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
            state=artemis.guest.GuestState(guest.state)
        )


@molten.schema
class GuestEvent:
    eventname: str = Field()

    def __init__(
        self,
        eventname: str,
        guestname: str,
        updated: Any,
        details: Any
    ) -> None:
        self.eventname = eventname
        self.guestname = guestname
        self.details = details
        self.updated = str(updated)

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

        if obj is not None:

            header = 'Content-Type'
            hvalue = 'application/json'

            if headers is None:
                headers = {header: hvalue}
            elif header not in headers:
                headers[header] = hvalue

            try:
                content = json.dumps(obj, default=lambda o: o.__dict__, sort_keys=True)
            except (TypeError, OverflowError):
                log = artemis.get_logger()
                log_dict(log.debug, 'object is not JSON serializable', obj.__dict__)
                raise errors.BadRequestError(request=request)

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
                'created',
                gr.guestname,
                state=gr.state
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
                    'deleted',
                    guestname
                )
                return

            raise errors.GenericError(request=request)


class GuestEventManager:
    def __init__(self, db: DB) -> None:
        self.db = db

    def get_events_by_guestname(self, guestname: str) -> Optional[List[GuestEvent]]:
        with self.db.get_session() as session:
            events = session.query(artemis.db.GuestEvent) \
                .filter(artemis.db.GuestEvent.guestname == guestname) \
                .all()

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


def get_guest_events(guestname: str, request: Request, manager: GuestEventManager) -> APIResponse:
    events = manager.get_events_by_guestname(guestname)
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
