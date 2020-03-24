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
from molten import HTTP_201, HTTP_200, Field, Response
from molten.contrib.prometheus import prometheus_middleware
from molten.typing import Middleware

from gluetool.log import log_dict

import artemis
import artemis.db
import artemis.guest

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


class APIResponse(Response):  # type: ignore
    ''' Class that represents API response structure.
        An instance of this class should be returned by routes.

        :param object obj: Schema instance (for example GuestRequest).
        :param str status: HTTP status code string.
        :param dict headers: HTTP response headers.
        :param str content: JSON-serializable string that will be used as response's body
        :param stream: bytes-like string that will be used as response's body
        :param str encoding: Data encoding
    '''

    def __init__(
        self,
        obj: Optional[Union[Any, List[Any]]] = None,
        status: str = HTTP_200,
        headers: Optional[Dict[Any, Any]] = None,
        content: Optional[str] = None,
        stream: Optional[Union[bytes, str]] = None,
        encoding: str = 'utf-8'
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
                raise errors.BadRequestError()

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

    def delete_by_guestname(self, guestname: str) -> None:
        with self.db.get_session() as session:
            query = sqlalchemy \
                    .update(artemis.db.GuestRequest.__table__) \
                    .where(artemis.db.GuestRequest.guestname == guestname) \
                    .values(state=artemis.guest.GuestState.CONDEMNED.value)

            if artemis.safe_db_execute(artemis.get_logger(), session, query):
                return

            raise errors.GenericError()


class GuestRequestManagerComponent:
    is_cacheable = True
    is_singleton = True

    def can_handle_parameter(self, parameter: Parameter) -> bool:
        return parameter.annotation is GuestRequestManager

    def resolve(self, db: DB) -> GuestRequestManager:
        return GuestRequestManager(db)


#
# Routes
#
def get_guest_requests(manager: GuestRequestManager) -> APIResponse:
    return APIResponse(manager.get_guest_requests())


def create_guest_request(guest_request: GuestRequest, manager: GuestRequestManager) -> APIResponse:
    return APIResponse(manager.create(guest_request), status=HTTP_201)


def get_guest_request(guestname: str, manager: GuestRequestManager) -> APIResponse:
    guest_response = manager.get_by_guestname(guestname)

    if guest_response is None:
        raise errors.NoSuchEntityError()

    return APIResponse(guest_response)


def delete_guest(guestname: str, manager: GuestRequestManager) -> APIResponse:
    manager.delete_by_guestname(guestname)
    return APIResponse()


def get_metrics() -> APIResponse:
    return APIResponse(stream=generate_metrics())


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
        GuestRequestManagerComponent()
    ]

# TODO: uncomment when registration is done
    mw: List[Middleware] = [
        # middleware.AuthorizationMiddleware,
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
