import dataclasses
import enum
import json
import sqlalchemy

import gluetool.log

import artemis
import artemis.db

from typing import Any, Optional


class GuestState(enum.Enum):
    ERROR = 'error'

    #: Initial state. Newly created guest requests are set to PENDING and wait for
    #: being picked up be the router.
    PENDING = 'pending'

    #: Guest request is being evaluated. A router task exists for this guest request.
    ROUTING = 'routing'

    #: A pool has been assigned to fulfill the request. A provisioning task exists for this guest request.
    PROVISIONING = 'provisioning'

    #: A pool driver began provisioning, and promised us delivery of the guest. This may require
    #: some time, and probably also a series of additional tasks.
    PROMISED = 'promised'

    #: Provisioning is done, there is a guest available for SSH connections.
    READY = 'ready'

    #: The guest has been released by the user, and it's resources may be released by its pool's driver.
    CONDEMNED = 'condemned'

    #: Initial state for snapshot restoring. Newly created restore snapshot request are set to RESTORING.
    RESTORING = 'restoring'

    #: Restore request is being evaluated
    PROCESSING = 'processing'

    #: Release request is being evaluated
    RELEASING = 'releasing'

    #: A pool has been assigned to fulfill the request. A provisioning task exists for this guest request.
    CREATING = 'creating'


class GuestLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, guestname: str) -> None:
        super(GuestLogger, self).__init__(logger, {
            'ctx_guest_name': (10, guestname)
        })


@dataclasses.dataclass
class SSHInfo:
    """
    SSH-related information used to transport all the relevant information between different subsystems.
    We want to keep our use of SSH usernames and keys consistent.
    """

    key: artemis.db.SSHKey
    port: int = 22
    username: str = 'root'

    def __repr__(self) -> str:
        return '<SSHInfo: port={}, username={}, key={}>'.format(
            self.port,
            self.username,
            self.key.keyname if self.key else ''
        )


class Guest:
    """
    Parent class of all provisioned machines. Pool drivers may create their own child classes
    to track their own internal information (e.g. cloud instance IDs) within the same object.
    """

    def __init__(
        self,
        guestname: str,
        address: Optional[str] = None,
        ssh_info: Optional[SSHInfo] = None
    ) -> None:
        self.guestname = guestname
        self.address = address
        self.ssh_info = ssh_info

    def __repr__(self) -> str:
        return '<Guest: address={}, ssh_info={}>'.format(
            self.address,
            self.ssh_info
        )

    def pool_data_to_db(self) -> str:
        return json.dumps({})

    def pool_data_from_db(self, guest_record: artemis.db.GuestRequest) -> Any:
        assert guest_record.pool_data is not None

        return json.loads(guest_record.pool_data)

    def log_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        eventname: str,
        **details: Any
    ) -> None:
        """ Create event log record for guest """

        artemis.log_guest_event(logger, session, eventname, self.guestname, **details)

    @property
    def is_promised(self) -> bool:
        return self.address is None
