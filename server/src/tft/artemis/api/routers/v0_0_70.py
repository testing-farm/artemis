# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

import dataclasses
import datetime
from typing import Annotated, Optional

import gluetool.log
from fastapi import APIRouter, Depends, Request, status
from typing_extensions import Self

from ...db import GuestLog, GuestLogContentType, GuestLogState
from ..dependencies import get_logger
from . import (
    GuestRequestManager,
    get_guest_request_log,
    with_tracing,
)
from .v0_0_67 import GuestLogResponsePayload as PreviousGuestLogResponsePayload
from .v0_0_69 import APIMilestone as PreviousAPIMilestone


@dataclasses.dataclass
class GuestLogBlobResponsePayload:
    ctime: datetime.datetime
    content: str


@dataclasses.dataclass
class GuestLogResponsePayload(PreviousGuestLogResponsePayload):
    state: GuestLogState
    contenttype: GuestLogContentType

    url: Optional[str]
    blobs: list[GuestLogBlobResponsePayload]

    updated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, log: GuestLog) -> Self:
        return cls(
            state=GuestLogState(log.state),
            contenttype=GuestLogContentType(log.contenttype),
            url=log.url,
            blobs=[GuestLogBlobResponsePayload(ctime=blob.ctime, content=blob.content) for blob in log.blobs],
            updated=log.updated,
            expires=log.expires,
        )


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: guest log API adds multiple blobs
    * Removed: ``boot.method`` enum
    """

    _VERSION = (0, 0, 70)
    _PREVIOUS = PreviousAPIMilestone

    router_guests = APIRouter(
        prefix='/guests',
        tags=['guests'],
        responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}},
    )

    @staticmethod
    @router_guests.get('/{guestname}/logs/{logname}/{contenttype}', status_code=status.HTTP_200_OK)
    @with_tracing
    def get_guest_log(
        guestname: str,
        logname: str,
        contenttype: str,
        request: Request,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> GuestLogResponsePayload:
        return get_guest_request_log(guestname, logname, contenttype, manager, logger, GuestLogResponsePayload)

    router_guests.routes += PreviousAPIMilestone.router_guests.routes
