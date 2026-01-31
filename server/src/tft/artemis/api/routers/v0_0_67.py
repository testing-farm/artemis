# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

import dataclasses
import datetime
from typing import Annotated, Any, Optional

import gluetool.log
from fastapi import APIRouter, Depends, Request, status
from typing_extensions import Self

from ...db import GuestLog, GuestLogContentType, GuestLogState, GuestState, UserDataType
from ..dependencies import get_auth_context, get_logger
from ..models import (
    AuthContext,
    BaseModel,
    EventSearchParameters,
    GuestEvent,
)
from ..routers import APIMilestone as PreviousAPIMilestone
from . import (
    GuestEventManager,
    GuestRequestManager,
    create_guest_request,
    create_guest_request_log,
    delete_guest as delete_artemis_guest,
    get_guest_request,
    get_guest_request_log,
    get_guest_requests,
    with_tracing,
)
from .common import (
    DefaultAPI,
    KnobsAPI,
    StatusAPI,
    UsersAPI,
)
from .v0_0_27 import CacheAPI
from .v0_0_58 import ShelvesAPI


@dataclasses.dataclass
class GuestLogResponsePayload:
    state: GuestLogState
    contenttype: GuestLogContentType

    url: Optional[str]
    blob: Optional[str]

    updated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, log: GuestLog) -> Self:
        blob_components: list[str] = []

        for blob in log.blobs:
            blob_components.append(f'# Captured at {blob.ctime}')
            blob_components.append(blob.content)
            blob_components.append('')

        return cls(
            state=GuestLogState(log.state),
            contenttype=GuestLogContentType(log.contenttype),
            url=log.url,
            blob='\n'.join(blob_components),
            updated=log.updated,
            expires=log.expires,
        )


@dataclasses.dataclass
class GuestRequestRequestPayload:
    keyname: str
    environment: dict[str, Optional[Any]]
    priority_group: Optional[str] = None
    shelfname: Optional[str] = None
    user_data: Optional[UserDataType] = None
    post_install_script: Optional[str] = None
    log_types: Optional[list[Any]] = None
    watchdog_dispatch_delay: Optional[int] = None
    watchdog_period_delay: Optional[int] = None
    bypass_shelf_lookup: bool = False
    skip_prepare_verify_ssh: bool = False


class GuestRequestSSHInfoResponsePayload(BaseModel):
    username: str
    port: int
    keyname: str


class GuestRequestResponsePayload(BaseModel):
    guestname: str
    owner: str
    shelf: Optional[str]
    environment: dict[str, Any]
    address: Optional[str]
    ssh: GuestRequestSSHInfoResponsePayload
    state: GuestState
    state_mtime: Optional[datetime.datetime]
    mtime: datetime.datetime
    user_data: UserDataType
    skip_prepare_verify_ssh: Optional[bool]
    post_install_script: Optional[str]
    ctime: datetime.datetime
    console_url: Optional[str]
    console_url_expires: Optional[datetime.datetime]
    log_types: list[tuple[str, GuestLogContentType]]
    watchdog_dispatch_delay: Optional[int]
    watchdog_period_delay: Optional[int]

    poolname: Optional[str]
    last_poolname: Optional[str]

    @classmethod
    def from_db(cls, guest: GuestRequestRequestPayload) -> Self:
        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            shelf=guest.shelfname,
            environment=guest.environment.serialize(),
            address=guest.address,
            ssh=GuestRequestSSHInfoResponsePayload(
                username=guest.ssh_username, port=guest.ssh_port, keyname=guest.ssh_keyname
            ),
            state=GuestState(guest.state),
            state_mtime=guest.state_mtime,
            mtime=guest.mtime,
            user_data=guest.user_data,
            skip_prepare_verify_ssh=guest.skip_prepare_verify_ssh,
            post_install_script=guest.post_install_script,
            ctime=guest.ctime,
            console_url=guest.console_url,
            console_url_expires=guest.console_url_expires,
            log_types=guest.log_types,
            watchdog_dispatch_delay=guest.watchdog_dispatch_delay,
            watchdog_period_delay=guest.watchdog_period_delay,
            poolname=guest.poolname,
            last_poolname=guest.last_poolname,
        )


class APIMilestone(CacheAPI, ShelvesAPI, KnobsAPI, DefaultAPI, UsersAPI, StatusAPI, PreviousAPIMilestone):
    """
    * Added: ``cpu.flag`` HW requirement
    """

    router_guests = APIRouter(
        prefix='/guests',
        tags=['guests'],
        responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}},
    )

    @staticmethod
    @router_guests.get('/', status_code=status.HTTP_200_OK)
    @with_tracing
    def get_guests(
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        request: Request,
    ) -> list[GuestRequestResponsePayload]:
        return get_guest_requests(logger, manager=manager, request=request, response_model=GuestRequestResponsePayload)

    @staticmethod
    @router_guests.post('/', status_code=status.HTTP_201_CREATED)
    @with_tracing
    def create_guest(
        guest_request: GuestRequestRequestPayload,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        request: Request,
        auth: Annotated[AuthContext, Depends(get_auth_context)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> GuestRequestResponsePayload:
        return create_guest_request(
            api_version=APIMilestone.version,
            guest_request=guest_request,
            manager=manager,
            request=request,
            auth=auth,
            logger=logger,
            response_model=GuestRequestResponsePayload,
        )

    @staticmethod
    @router_guests.get('/{guestname}', status_code=status.HTTP_200_OK)
    @with_tracing
    def get_guest(
        guestname: str,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        request: Request,
    ) -> GuestRequestResponsePayload:
        return get_guest_request(
            logger, guestname=guestname, manager=manager, request=request, response_model=GuestRequestResponsePayload
        )

    @staticmethod
    @router_guests.delete('/{guestname}', status_code=status.HTTP_204_NO_CONTENT)
    @with_tracing
    def delete_guest(
        guestname: str,
        request: Request,
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    ) -> None:
        return delete_artemis_guest(guestname=guestname, request=request, logger=logger, manager=manager)

    @staticmethod
    @router_guests.get('/events', status_code=status.HTTP_200_OK)
    @with_tracing
    def get_events(
        request: Request,
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        manager: Annotated[GuestEventManager, Depends(GuestEventManager)],
    ) -> list[GuestEvent]:
        return manager.get_events(logger, EventSearchParameters.from_request(request))

    @staticmethod
    @router_guests.get('/{guestname}/events', status_code=status.HTTP_200_OK)
    @with_tracing
    def get_guest_events(
        guestname: str,
        request: Request,
        manager: Annotated[GuestEventManager, Depends(GuestEventManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> list[GuestEvent]:
        return manager.get_events_by_guestname(logger, guestname, EventSearchParameters.from_request(request))

    @staticmethod
    @router_guests.post('/{guestname}/logs/{logname}/{contenttype}', status_code=status.HTTP_202_ACCEPTED)
    @with_tracing
    def create_guest_log(
        guestname: str,
        logname: str,
        contenttype: str,
        request: Request,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> None:
        return create_guest_request_log(guestname, logname, contenttype, manager, logger)

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
