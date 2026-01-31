# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from typing import Annotated

import gluetool.log
from fastapi import APIRouter, Depends, Request, status

from ..dependencies import get_auth_context, get_logger
from ..models import (
    AuthContext,
    ConsoleUrlResponse,
    GuestRequest,
    GuestResponse,
)
from . import (
    GuestRequestManager,
    acquire_guest_console_url,
    create_guest_request,
)
from .v0_0_17 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: ``/guest/$GUESTNAME/console/url``
    """

    _VERSION = (0, 0, 18)
    _PREVIOUS = PreviousAPIMilestone

    router_guests = APIRouter(
        prefix='/guests',
        tags=['guests'],
        responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}},
    )

    @staticmethod
    @router_guests.post('/', status_code=status.HTTP_201_CREATED)
    def create_guest(
        guest_request: GuestRequest,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        request: Request,
        auth: Annotated[AuthContext, Depends(get_auth_context)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> GuestResponse:
        return create_guest_request(
            api_version='v0.0.18',
            guest_request=guest_request,
            manager=manager,
            request=request,
            auth=auth,
            logger=logger,
        )

    @staticmethod
    @router_guests.get('/{guestname}/console/url', status_code=status.HTTP_200_OK)
    def get_guest_log(
        guestname: str,
        request: Request,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> ConsoleUrlResponse:
        return acquire_guest_console_url(guestname=guestname, manager=manager, logger=logger, request=request)

    router_guests.routes += PreviousAPIMilestone.router_guests.routes
