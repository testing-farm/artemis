# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from typing import List

import gluetool.log
import redis
from fastapi import APIRouter, Depends, Request, Response, status
from typing_extensions import Annotated

from ... import db as artemis_db, metrics
from ..dependencies import get_cache, get_db, get_logger, get_metrics_tree
from ..models import (
    AboutResponse,
    CreateUserRequest,
    KnobResponse,
    KnobUpdateRequest,
    TokenResetResponse,
    UserResponse,
)
from . import (
    CacheManager,
    KnobManager,
    StatusManager,
    UserManager,
    get_about,
    get_metrics,
    with_tracing,
)

router_knobs = APIRouter(
    prefix="/knobs",
    tags=["knobs"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}}
)

router_users = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}}
)

router__status = APIRouter(
    prefix="/_status",
    tags=["status"],
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}}
)

router_default = APIRouter(
    responses={status.HTTP_404_NOT_FOUND: {"description": "Not found"}}
)


@router_default.get("/metrics", status_code=status.HTTP_200_OK)
@with_tracing
def show_metrics(
    request: Request,
    db: Annotated[artemis_db.DB, Depends(get_db)],
    metrics_tree: Annotated['metrics.Metrics', Depends(get_metrics_tree)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> Response:
    return get_metrics(request=request, db=db, metrics_tree=metrics_tree, logger=logger)


@router_default.get("/about", status_code=status.HTTP_200_OK)
@with_tracing
def show_about(
    request: Request
) -> AboutResponse:
    return get_about(request)


@router_knobs.get('/', status_code=status.HTTP_200_OK)
@with_tracing
def get_knobs(
    manager: Annotated[KnobManager, Depends(KnobManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> List[KnobResponse]:
    return manager.entry_get_knobs(manager=manager, logger=logger)


@router_knobs.get('/{knobname}', status_code=status.HTTP_200_OK)
@with_tracing
def get_knob(
    knobname: str,
    manager: Annotated[KnobManager, Depends(KnobManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> KnobResponse:
    return manager.entry_get_knob(knobname=knobname, manager=manager, logger=logger)


@router_knobs.put('/{knobname}', status_code=status.HTTP_201_CREATED)
@with_tracing
def set_knob(
    knobname: str,
    payload: KnobUpdateRequest,
    manager: Annotated[KnobManager, Depends(KnobManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> KnobResponse:
    return manager.entry_set_knob(knobname=knobname, payload=payload, manager=manager, logger=logger)


@router_knobs.delete('/{knobname}', status_code=status.HTTP_204_NO_CONTENT)
@with_tracing
def delete_knob(
    knobname: str,
    manager: Annotated[KnobManager, Depends(KnobManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    request: Request
) -> None:
    return manager.entry_delete_knob(knobname=knobname, manager=manager, logger=logger)


@router_users.get('/', status_code=status.HTTP_200_OK)
@with_tracing
def get_users(
    manager: Annotated[UserManager, Depends(UserManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> List[UserResponse]:
    return manager.entry_get_users(manager, logger)


@router_users.get('/{username}', status_code=status.HTTP_200_OK)
@with_tracing
def get_user(
    username: str,
    manager: Annotated[UserManager, Depends(UserManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> UserResponse:
    return manager.entry_get_user(manager, username, logger)


@router_users.post('/{username}', status_code=status.HTTP_201_CREATED)
@with_tracing
def create_user(
    username: str,
    user_request: CreateUserRequest,
    manager: Annotated[UserManager, Depends(UserManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> UserResponse:
    return manager.entry_create_user(username=username, manager=manager, user_request=user_request, logger=logger)


@router_users.delete('/{username}', status_code=status.HTTP_204_NO_CONTENT)
@with_tracing
def delete_user(
    username: str,
    manager: Annotated[UserManager, Depends(UserManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]
) -> None:
    return manager.entry_delete_user(username=username, manager=manager, logger=logger)


@router_users.post('/{username}/tokens/{tokentype}/reset', status_code=status.HTTP_201_CREATED)
@with_tracing
def reset_token(
    username: str,
    tokentype: str,
    manager: Annotated[UserManager, Depends(UserManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
) -> TokenResetResponse:
    return manager.entry_reset_token(username=username, tokentype=tokentype, manager=manager, logger=logger)


@router__status.get('/workers/traffic', status_code=status.HTTP_200_OK)
@with_tracing
def get_workers_traffic(
    manager: Annotated[CacheManager, Depends(StatusManager)],
    logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)],
    cache: Annotated['redis.Redis', Depends(get_cache)],
    request: Request
) -> Response:
    return StatusManager.entry_workers_traffic(manager=manager, logger=logger, cache=cache)
