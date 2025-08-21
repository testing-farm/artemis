# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import gluetool.utils
import sqlalchemy.orm.session
from gluetool.result import Ok, Result

from .. import Failure
from ..db import GuestRequest
from . import PoolData, PoolDriver, PoolImageSSHInfo, ProvisioningProgress, ProvisioningState


class LocalhostDriver(PoolDriver):
    """
    A dummy driver always "provisioning" a localhost for the given guest.
    """

    drivername = 'localhost'

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        self.log_acquisition_attempt(logger, session, guest_request)

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.COMPLETE, pool_data=PoolData(), address='127.0.0.1', ssh_info=PoolImageSSHInfo()
            )
        )

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        return Ok(None)


PoolDriver._drivers_registry['localhost'] = LocalhostDriver
