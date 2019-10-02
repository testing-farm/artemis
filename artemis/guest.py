import dataclasses

import artemis.keys
from typing import List


@dataclasses.dataclass
class SSHInfo:
    """
    SSH-related information used to transport all the relevant information between different subsystems.
    We want to keep our use of SSH usernames and keys consistent.
    """

    key: artemis.keys.Key
    port: int = 22
    username: str = 'root'
    options: List[str] = dataclasses.field(default_factory=list)

    def __repr__(self):
        # type: () -> str

        return '<SSHInfo: port={}, username={}, key={}, options={}>'.format(
            self.port,
            self.username,
            self.key,
            self.options
        )


class Guest:
    """
    Parent class of all provisioned machines. Pool drivers may create their own child classes
    to track their own internal information (e.g. cloud instance IDs) within the same object.
    """

    def __init__(self, address, ssh_info):
        # type: (str, SSHInfo) -> None

        self.address = address
        self.ssh_info = ssh_info

    def __repr__(self):
        # type: () -> str

        return '<Guest: address={}, ssh_info={}>'.format(
            self.address,
            self.ssh_info
        )
