import dataclasses
import enum
import json

import gluetool.log

import artemis.db

from typing import Any, List


class GuestState(enum.Enum):
    ERROR = 'error'

    #: Initial state. Newly created guest requests are set to PENDING and wait for
    #: being picked up be the router.
    PENDING = 'pending'

    #: Guest request is being evaluated. A router task exists for this guest request.
    ROUTING = 'routing'

    #: A pool has been assigned to fulfill the request. A provisioning task exists for this guest request.
    PROVISIONING = 'provisioning'

    #: Provisioning is done, there is a guest available for SSH connections.
    READY = 'ready'

    CONDEMNED = 'condemned'


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
    options: List[str] = dataclasses.field(default_factory=list)

    def __repr__(self) -> str:
        return '<SSHInfo: port={}, username={}, key={}, options={}>'.format(
            self.port,
            self.username,
            self.key.keyname if self.key else '',
            self.options
        )


class Guest:
    """
    Parent class of all provisioned machines. Pool drivers may create their own child classes
    to track their own internal information (e.g. cloud instance IDs) within the same object.
    """

    def __init__(self, address: str, ssh_info: SSHInfo) -> None:
        self.address = address
        self.ssh_info = ssh_info

    def __repr__(self) -> str:
        return '<Guest: address={}, ssh_info={}>'.format(
            self.address,
            self.ssh_info
        )

    def pool_data_to_db(self) -> str:
        return json.dumps({})

    def pool_data_from_db(self, guest_record: artemis.db.Guest) -> Any:
        assert guest_record.pool_data is not None

        return json.loads(guest_record.pool_data)
