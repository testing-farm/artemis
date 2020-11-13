import dataclasses
import enum

import gluetool.log

from . import db as artemis_db


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

    #: A pool was requested to stop a guest. A stopping task exists for this guest request.
    STOPPING = 'stopping'

    #: Guest was stopped and no SSH connection is available anymore.
    STOPPED = 'stopped'

    #: A pool has been assigned to fulfill the request. A starting task exists for this guest request.
    STARTING = 'starting'


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

    key: artemis_db.SSHKey
    port: int = 22
    username: str = 'root'

    def __repr__(self) -> str:
        return '<SSHInfo: port={}, username={}, key={}>'.format(
            self.port,
            self.username,
            self.key.keyname if self.key else ''
        )
