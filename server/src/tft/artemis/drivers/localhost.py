# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional

import gluetool.log
import gluetool.utils
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import GuestRequest
from . import (
    ConfigImageFilter,
    ConsoleUrlData,
    Instance,
    PoolData,
    PoolDriver,
    PoolImageInfo,
    PoolImageSSHInfo,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
)


class LocalhostDriver(PoolDriver[Instance]):
    """
    A dummy driver always "provisioning" a localhost for the given guest.
    """

    drivername = 'localhost'

    def list_images(
        self, logger: gluetool.log.ContextAdapter, filters: Optional[ConfigImageFilter] = None
    ) -> Result[list[PoolImageInfo], Failure]:
        return Ok([])

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        self.log_acquisition_attempt(logger, session, guest_request)

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.COMPLETE, pool_data=PoolData(), address='127.0.0.1', ssh_info=PoolImageSSHInfo()
            )
        )

    def update_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
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

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resources_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        return Ok(ReleasePoolResourcesState.RELEASED)

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        return Error(Failure('guest reboot not supported'))

    # The following are necessary implementations of abstract methods the driver does not have use for. They are
    # required, but we will remove them in the future.
    def acquire_console_url(
        self, logger: gluetool.log.ContextAdapter, guest: GuestRequest
    ) -> Result[ConsoleUrlData, Failure]:
        return Error(Failure('unsupported driver method', poolname=self.poolname, method='acquire_console_url'))


PoolDriver._drivers_registry['localhost'] = LocalhostDriver
