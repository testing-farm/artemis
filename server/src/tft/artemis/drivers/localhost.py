import threading
from typing import Optional

import gluetool.log
import gluetool.utils
import sqlalchemy.orm.session
from gluetool.result import Ok, Result

from .. import Failure
from ..db import GuestRequest
from . import PoolData, PoolDriver, ProvisioningProgress, ProvisioningState


class LocalhostDriver(PoolDriver):
    """
    A dummy driver always "provisioning" a localhost for the given guest.
    """

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=PoolData(),
            address='127.0.0.1'
        ))

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        return Ok(True)
