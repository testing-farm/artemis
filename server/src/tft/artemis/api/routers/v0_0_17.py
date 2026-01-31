# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from typing import Annotated

import gluetool.log
from fastapi import APIRouter, Depends, Request, Response, status

from ..dependencies import get_auth_context, get_logger
from ..models import (
    AuthContext,
    EventSearchParameters,
    GuestEvent,
    GuestRequest,
    GuestResponse,
)
from . import (
    APIMilestone as PreviousAPIMilestone,
    CacheManager,
    GuestEventManager,
    GuestRequestManager,
    create_guest_request,
    delete_guest as delete_artemis_guest,
    get_guest_request,
    get_guest_requests,
)
from .common import DefaultAPI, KnobsAPI


class APIMilestone(KnobsAPI, DefaultAPI, PreviousAPIMilestone):
    _VERSION = (0, 0, 17)

    router_guests = APIRouter(
        prefix='/guests',
        tags=['guests'],
        responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}},
    )

    @staticmethod
    @router_guests.get('/', status_code=status.HTTP_200_OK)
    def get_guests(
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        request: Request,
    ) -> list[GuestResponse]:
        return get_guest_requests(logger, manager=manager, request=request)

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
            api_version='v0.0.17',
            guest_request=guest_request,
            manager=manager,
            request=request,
            auth=auth,
            logger=logger,
        )

    @staticmethod
    @router_guests.get('/{guestname}', status_code=status.HTTP_200_OK)
    def get_guest(
        guestname: str,
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        request: Request,
    ) -> GuestResponse:
        return get_guest_request(logger, guestname=guestname, manager=manager, request=request)

    @staticmethod
    @router_guests.delete('/{guestname}', status_code=status.HTTP_204_NO_CONTENT)
    def delete_guest(
        guestname: str,
        request: Request,
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    ) -> None:
        return delete_artemis_guest(guestname=guestname, request=request, logger=logger, manager=manager)

    @staticmethod
    @router_guests.get('/events', status_code=status.HTTP_200_OK)
    def get_events(
        request: Request,
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        manager: Annotated[GuestEventManager, Depends(GuestEventManager)],
    ) -> list[GuestEvent]:
        return manager.get_events(logger, EventSearchParameters.from_request(request))

    @staticmethod
    @router_guests.get('/{guestname}/events', status_code=status.HTTP_200_OK)
    def get_guest_events(
        guestname: str,
        request: Request,
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
        manager: Annotated[GuestEventManager, Depends(GuestEventManager)],
    ) -> list[GuestEvent]:
        return manager.get_events_by_guestname(logger, guestname, EventSearchParameters.from_request(request))

    router_cache = APIRouter(
        prefix='/_cache', tags=['cache'], responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}}
    )

    @staticmethod
    @router_cache.get('/pools/{poolname}/image-info', status_code=status.HTTP_200_OK)
    def get_pool_image_info(
        poolname: str,
        manager: Annotated[CacheManager, Depends(CacheManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> Response:
        return manager.entry_pool_image_info(poolname=poolname, manager=manager, logger=logger)

    @staticmethod
    @router_cache.get('/pools/{poolname}/flavor-info', status_code=status.HTTP_200_OK)
    def get_pool_flavor_info(
        poolname: str,
        manager: Annotated[CacheManager, Depends(CacheManager)],
        logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    ) -> Response:
        return manager.entry_pool_flavor_info(poolname=poolname, manager=manager, logger=logger)


router__cache = APIRouter(
    prefix='/_cache', tags=['cache'], responses={status.HTTP_404_NOT_FOUND: {'description': 'Not found'}}
)
