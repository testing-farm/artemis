# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix
# NEW: current worker tasks
# NEW: boot.method HW constraint

from typing import List

import fastapi
import gluetool.log
from fastapi import APIRouter, Depends, Request, status
from typing_extensions import Annotated

from .. import errors
from ..dependencies import get_auth_context, get_logger
from ..models import (
    AuthContext,
    EventSearchParameters,
    GuestEvent,
    GuestLogResponse,
    GuestRequest,
    GuestResponse,
    SnapshotRequest,
    SnapshotResponse,
)
from . import (
    GuestEventManager,
    GuestRequestManager,
    SnapshotRequestManager,
    create_guest_request,
    create_guest_request_log,
    delete_guest as delete_artemis_guest,
    get_guest_request,
    get_guest_request_log,
    get_guest_requests,
)
from .common import router__status, router_default, router_knobs, router_users
from .v0_0_27 import router__cache

router_guests = APIRouter(
    prefix="/guests",
    tags=["guests"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}},
)


@router_guests.get("/", status_code=status.HTTP_200_OK)
def get_guests(
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> List[GuestResponse]:
    return get_guest_requests(logger, manager=manager, request=request)


@router_guests.post("/", status_code=status.HTTP_201_CREATED)
def create_guest(
    guest_request: GuestRequest,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> GuestResponse:
    return create_guest_request(
        api_version='v0.0.32',
        guest_request=guest_request,
        manager=manager,
        request=request,
        auth=auth,
        logger=logger)


@router_guests.get("/{guestname}", status_code=status.HTTP_200_OK)
def get_guest(
    guestname: str,
    manager: Annotated[GuestRequestManager, Depends(GuestRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> GuestResponse:
    return get_guest_request(logger, guestname=guestname, manager=manager, request=request)


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
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    manager: Annotated[GuestEventManager, Depends(GuestEventManager)]
) -> List[GuestEvent]:
    return manager.get_events(logger, EventSearchParameters.from_request(request))


@router_guests.get("/{guestname}/events", status_code=status.HTTP_200_OK)
def get_guest_events(
    guestname: str,
    request: Request,
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    manager: Annotated[GuestEventManager, Depends(GuestEventManager)]
) -> List[GuestEvent]:
    return manager.get_events_by_guestname(logger, guestname, EventSearchParameters.from_request(request))


# NOTE(ivasilev) Snapshots are doomed, so didn't really check them properly

@router_guests.get("/{guestname}/snapshots/{snapshotname}", status_code=status.HTTP_200_OK)
def get_snapshot_request(
    guestname: str,
    snapshotname: str,
    manager: Annotated[SnapshotRequestManager, Depends(SnapshotRequestManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> SnapshotResponse:
    snapshot_response = manager.get_snapshot(logger, guestname, snapshotname)

    if snapshot_response is None:
        raise errors.NoSuchEntityError

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


def register_routes(app: fastapi.FastAPI) -> None:
    app.include_router(router_guests)
    app.include_router(router_knobs)
    app.include_router(router__cache)
    app.include_router(router__status)
    app.include_router(router_users)
    app.include_router(router_default)
