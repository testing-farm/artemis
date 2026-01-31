# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from typing import Annotated

import gluetool.log
from fastapi import APIRouter, Depends, Request, status

from ..dependencies import get_logger
from . import GuestRequestManager, with_tracing
from .v0_0_73 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: guest reboot
    * Added: ``cpu.stepping`` HW requirement
    """

    _VERSION = (0, 0, 74)
    _PREVIOUS = PreviousAPIMilestone

    router_guests = APIRouter(
        prefix='/guests',
        tags=['guests'],
        responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}},
    )

    @staticmethod
    @router_guests.post('/{guestname}/reboot', status_code=status.HTTP_202_ACCEPTED)
    @with_tracing
    def trigger_guest_reboot(
        guestname: str,
        request: Request,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> None:
        return manager.trigger_reboot(guestname, logger)

    router_guests.routes += PreviousAPIMilestone.router_guests.routes
