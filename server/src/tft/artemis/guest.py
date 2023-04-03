# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Guest request state definitions and helpers.
"""

import enum
from typing import cast

import gluetool.log


class GuestState(enum.Enum):
    """
    Guest request states.
    """

    ERROR = 'error'

    #: Initial state. Newly created guest requests are set to PENDING and wait for
    #: being picked up be the router.
    PENDING = 'pending'

    #: Cache (if specified) is being searched for a matching guest
    SHELF_LOOKUP = 'shelf-lookup'

    #: Guest request is being evaluated. A router task exists for this guest request.
    ROUTING = 'routing'

    #: A pool has been assigned to fulfill the request. A provisioning task exists for this guest request.
    PROVISIONING = 'provisioning'

    #: A pool driver began provisioning, and promised us delivery of the guest. This may require
    #: some time, and probably also a series of additional tasks.
    PROMISED = 'promised'

    PREPARING = 'preparing'

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

    #: The guest is assigned to a shelf
    SHELVED = 'shelved'


class GuestLogger(gluetool.log.ContextAdapter):
    """
    Logger adapter which adds a given guest request name to context.
    """

    def __init__(self, logger: gluetool.log.ContextAdapter, guestname: str) -> None:
        """
        Logger adapter which adds a given guest request name to context.

        :param logger: logger to extend.
        :param guestname: snapshot request name to add.
        """

        super().__init__(logger, {
            'ctx_guest_name': (10, guestname)
        })

    @property
    def guestname(self) -> str:
        """
        Return guest request name tracked by the logger.

        :returns: name of the guest request to propagate into logging context.
        """

        return cast(str, self._contexts['guest_name'][1])


class ShelfLogger(gluetool.log.ContextAdapter):
    """
    Logger adapter which adds the given guest shelf name to context.
    """

    def __init__(self, logger: gluetool.log.ContextAdapter, shelfname: str) -> None:
        """
        Logger adapter which adds a given guest shelf name to context.

        :param logger: logger to extend.
        :param shelfname: guest shelf name to add.
        """

        super().__init__(logger, {
            'ctx_shelf_name': (12, shelfname)
        })

    @property
    def shelfname(self) -> str:
        """
        Return shelf name tracked by the logger.

        :returns: name of the shelf to propagate into logging context.
        """

        return cast(str, self._contexts['shelf_name'][1])


class SnapshotLogger(gluetool.log.ContextAdapter):
    """
    Logger adapter which adds a given snapshot request name to context.
    """

    def __init__(self, logger: gluetool.log.ContextAdapter, snapshotname: str) -> None:
        """
        Logger adapter which adds a given snapshot request name to context.

        :param logger: logger to extend.
        :param snapshotname: snapshot request name to add.
        """

        super().__init__(logger, {
            'ctx_snapshot_name': (11, snapshotname)
        })

    @property
    def snapshotname(self) -> str:
        """
        Return snapshot name tracked by the logger.

        :returns: name of the snapshot to propagate into logging context.
        """

        return cast(str, self._contexts['snapshot_name'][1])
