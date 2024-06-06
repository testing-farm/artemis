# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix
# NEW: fixed virtualization.hypervisor enum

from typing import List, Optional

import fastapi
import gluetool.log
from fastapi import APIRouter, Depends, Request, Response, status
from typing_extensions import Annotated

from .. import errors
from ..dependencies import get_auth_context, get_logger
from ..models import AuthContext, EventSearchParameters, GuestEvent, GuestLogResponse, GuestRequest, GuestResponse, \
    GuestShelfResponse, PreprovisioningRequest, SnapshotRequest, SnapshotResponse
from . import CacheManager, GuestEventManager, GuestRequestManager, GuestShelfManager, SnapshotRequestManager, \
    create_guest_request, create_guest_request_log
from . import delete_guest as delete_artemis_guest
from . import get_guest_request, get_guest_request_log, get_guest_requests, preprovision_guest
from .common import router__status, router_default, router_knobs, router_users
from .v0_0_27 import router__cache

router_guests = APIRouter(
    prefix="/guests",
    tags=["guests"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}},
)

router_shelves = APIRouter(
    prefix="/shelves",
    tags=["shelves"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}}
)


@router_guests.get("/", status_code=status.HTTP_200_OK)
def get_guests(
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    request: Request
) -> List[GuestResponse]:
    return get_guest_requests(manager=manager, request=request)


@router_guests.post("/", status_code=status.HTTP_201_CREATED)
def create_guest(
    guest_request: GuestRequest,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> GuestResponse:
    return create_guest_request(
        api_version='v0.0.58',
        guest_request=guest_request,
        manager=manager,
        request=request,
        auth=auth,
        logger=logger)


@router_guests.get("/{guestname}", status_code=status.HTTP_200_OK)
def get_guest(
    guestname: str,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    request: Request
) -> GuestResponse:
    return get_guest_request(guestname=guestname, manager=manager, request=request)


@router_guests.delete("/{guestname}", status_code=status.HTTP_204_NO_CONTENT)
def delete_guest(
    guestname: str,
    request: Request,
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)]
) -> None:
    return delete_artemis_guest(guestname=guestname, request=request, logger=logger, manager=manager)


@router_guests.get("/events", status_code=status.HTTP_200_OK)
def get_events(
    request: Request,
    manager: Annotated[GuestEventManager, Depends(GuestEventManager)]
) -> List[GuestEvent]:
    return manager.get_events(EventSearchParameters.from_request(request))


@router_guests.get("/{guestname}/events", status_code=status.HTTP_200_OK)
def get_guest_events(
    guestname: str,
    request: Request,
    manager: Annotated[GuestEventManager, Depends(GuestEventManager)]
) -> List[GuestEvent]:
    return manager.get_events_by_guestname(guestname, EventSearchParameters.from_request(request))


# NOTE(ivasilev) Snapshots are doomed, so didn't really check them properly

@router_guests.get("/{guestname}/snapshots/{snapshotname}", status_code=status.HTTP_200_OK)
def get_snapshot_request(
    guestname: str,
    snapshotname: str,
    manager: Annotated[SnapshotRequestManager, Depends(SnapshotRequestManager)]
) -> SnapshotResponse:
    snapshot_response = manager.get_snapshot(guestname, snapshotname)

    if snapshot_response is None:
        raise errors.NoSuchEntityError()

    return snapshot_response


@router_guests.post("/{guestname}/snapshots", status_code=status.HTTP_201_CREATED)
def create_snapshot_request(
    guestname: str,
    snapshot_request: SnapshotRequest,
    manager: Annotated[SnapshotRequestManager, Depends(SnapshotRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> SnapshotResponse:
    return manager.create_snapshot(guestname, snapshot_request, logger)


@router_guests.delete("/{guestname}/snapshots/{snapshotname}",
                      status_code=status.HTTP_204_NO_CONTENT)
def delete_snapshot(
    guestname: str,
    snapshotname: str,
    manager: Annotated[SnapshotRequestManager, Depends(SnapshotRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> None:
    manager.delete_snapshot(guestname, snapshotname, logger)

    return None


@router_guests.post("/{guestname}/snapshots/{snapshotname}/restore",
                    status_code=status.HTTP_201_CREATED)
def restore_snapshot_request(
    guestname: str,
    snapshotname: str,
    manager: Annotated[SnapshotRequestManager, Depends(SnapshotRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> SnapshotResponse:
    return manager.restore_snapshot(guestname, snapshotname, logger)


@router_guests.get("/{guestname}/logs/{logname}/{contenttype}", status_code=status.HTTP_200_OK)
def get_guest_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> GuestLogResponse:
    return get_guest_request_log(guestname, logname, contenttype, manager, logger)


@router_guests.post("/{guestname}/logs/{logname}/{contenttype}",
                    status_code=status.HTTP_202_ACCEPTED)
def create_guest_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> None:
    return create_guest_request_log(guestname, logname, contenttype, manager, logger)


@router_shelves.get("/", status_code=status.HTTP_200_OK)
def get_shelves(
    manager: Annotated[GuestShelfManager, Depends(GuestShelfManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> List[GuestShelfResponse]:
    return GuestShelfManager.entry_get_shelves(manager=manager, auth=auth, logger=logger)


@router_shelves.get("/{shelfname}", status_code=status.HTTP_200_OK)
def get_shelf(
    shelfname: str,
    manager: Annotated[GuestShelfManager, Depends(GuestShelfManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> Optional[GuestShelfResponse]:
    return GuestShelfManager.entry_get_shelf(shelfname=shelfname, manager=manager, logger=logger)


@router_shelves.post("/{shelfname}", status_code=status.HTTP_201_CREATED)
def create_shelf(
    shelfname: str,
    manager: Annotated[GuestShelfManager, Depends(GuestShelfManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> GuestShelfResponse:
    return GuestShelfManager.entry_create_shelf(shelfname=shelfname, manager=manager, auth=auth, logger=logger)


@router_shelves.delete("/{shelfname}", status_code=status.HTTP_204_NO_CONTENT)
def delete_shelf(
    shelfname: str,
    request: Request,
    manager: Annotated[GuestShelfManager, Depends(GuestShelfManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> None:
    return GuestShelfManager.entry_delete_shelf(shelfname=shelfname, request=request, manager=manager, auth=auth,
                                                logger=logger)


@router_shelves.delete("/guests/{guestname}", status_code=status.HTTP_204_NO_CONTENT)
def entry_delete_shelved_guest(
    guestname: str,
    request: Request,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> None:
    return GuestShelfManager.entry_delete_shelved_guest(guestname=guestname, request=request, manager=manager,
                                                        auth=auth, logger=logger)


@router_shelves.post("/{shelfname}/preprovision", status_code=status.HTTP_202_ACCEPTED)
def preprovision(
    shelfname: str,
    preprovisioning_request: PreprovisioningRequest,
    manager: Annotated[GuestShelfManager, Depends(GuestShelfManager)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> None:
    return preprovision_guest(
        api_version='v0.0.58',
        shelfname=shelfname,
        preprovisioning_request=preprovisioning_request,
        manager=manager,
        auth=auth,
        logger=logger)


def register_routes(app: fastapi.FastAPI) -> None:
    app.include_router(router_guests)
    app.include_router(router_knobs)
    app.include_router(router__cache)
    app.include_router(router__status)
    app.include_router(router_shelves)
    app.include_router(router_users)
    app.include_router(router_default)
