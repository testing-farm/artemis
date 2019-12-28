import json
import os
import shutil
import sys
import uuid

import molten
import molten.dependency_injection
import molten.openapi
import sqlalchemy
import sqlalchemy.orm.exc

import artemis
import artemis.guest

from molten import HTTP_201, Field
from artemis.api import errors

from typing import Any, Dict, List, NoReturn, Optional, Tuple, Union
from artemis.db import DB
from inspect import Parameter


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
    def from_db(cls, guest: artemis.db.Guest) -> Any:
        return cls(
            guestname=guest.guestname,
            owner='artemis',  # guest.owner.username,
            environment=json.loads(guest.environment),
            address=guest.address,
            ssh=GuestSSHInfo(
                'root', 22, guest.sshkey.keyname
            ),
            state=artemis.guest.GuestState(guest.state)
        )


class GuestRequestManager:
    def __init__(self, db: DB) -> None:
        self.db = db

    def get_guest_requests(self) -> List[GuestResponse]:
        with self.db.get_session() as session:
            guests = session.query(artemis.db.Guest).all()

        return [
            GuestResponse.from_db(guest) for guest in guests
        ]

    def create(self, guest_request: GuestRequest) -> GuestResponse:
        guestname = str(uuid.uuid4())

        with self.db.get_session() as session:
            session.add(
                artemis.db.Guest(
                    guestname=guestname,
                    environment=json.dumps(guest_request.environment),
                    ownername=None,
                    keyname=guest_request.keyname,
                    priorityname=guest_request.priority_group,
                    poolname=None,
                    state=artemis.guest.GuestState.PENDING.value
                )
            )

        return GuestResponse(
            guestname=guestname,
            owner='artemis',
            environment=guest_request.environment,
            address=None,
            ssh=GuestSSHInfo(
                'root', 22, guest_request.keyname
            ),
            state=artemis.guest.GuestState.PENDING
        )

    def get_by_guestname(self, guestname: str) -> Optional[GuestResponse]:
        try:
            with self.db.get_session() as session:
                guest = session.query(artemis.db.Guest).filter(artemis.db.Guest.guestname == guestname).one()

        except sqlalchemy.orm.exc.NoResultFound:
            return None

        return GuestResponse.from_db(guest)

    def delete_by_guestname(self, guestname: str) -> None:
        with self.db.get_session() as session:
            query = sqlalchemy \
                .update(artemis.db.Guest) \
                .where(artemis.db.Guest.guestname == guestname) \
                .values(state=artemis.guest.GuestState.CONDEMNED.value)

            session.execute(query)


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
def get_guest_requests(manager: GuestRequestManager) -> List[GuestResponse]:
    return manager.get_guest_requests()


def create_guest_request(guest_request: GuestRequest, manager: GuestRequestManager) -> Tuple[str, GuestResponse]:
    return HTTP_201, manager.create(guest_request)


def get_guest_request(guestname: str, manager: GuestRequestManager) -> GuestResponse:
    guest_response = manager.get_by_guestname(guestname)

    if guest_response is None:
        raise errors.NoSuchEntityError

    return guest_response


def delete_guest(guestname: str, manager: GuestRequestManager) -> None:
    manager.delete_by_guestname(guestname)


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

#    mw: List[molten.Middleware] = [
#        molten.ResponseRendererMiddleware(),
#        middleware.AuthorizationMiddleware,
#    ]

    get_docs = molten.openapi.handlers.OpenAPIUIHandler()

    metadata = molten.openapi.documents.Metadata(
        title='Artemis API',
        description='Artemis provisioning system API.',
        version='0.0.1'
    )

    get_schema = molten.openapi.handlers.OpenAPIHandler(metadata=metadata)

    routes: List[Union[Route, Include]] = [
        Include('/guests', [
            Route('/', get_guest_requests, method='GET'),
            Route('/', create_guest_request, method='POST'),
            Route('/{guestname}', get_guest_request),
            Route('/{guestname}', delete_guest, method='DELETE'),
        ]),
        Route('/_docs', get_docs),
        Route('/_schema', get_schema),
    ]

    return molten.app.App(
            components=components,
            # TODO: uncomment when registration is done
            # middleware=mw,
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
