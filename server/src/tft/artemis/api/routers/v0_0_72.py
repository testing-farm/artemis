# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

import dataclasses
from typing import Annotated, Any, Optional

import gluetool.log
from fastapi import APIRouter, Depends, Request, status
from typing_extensions import Self

from ...db import GuestRequest, GuestState
from ..dependencies import get_auth_context, get_logger
from ..models import (
    AuthContext,
)
from . import (
    GuestRequestManager,
    create_guest_request,
    get_guest_request,
    get_guest_requests,
    with_tracing,
)
from .v0_0_67 import (
    GuestRequestRequestPayload as PreviousGuestRequestRequestPayload,
    GuestRequestResponsePayload as PreviousGuestRequestResponsePayload,
    GuestRequestSSHInfoResponsePayload as PreviousGuestRequestSSHInfoResponsePayload,
)
from .v0_0_70 import APIMilestone as PreviousAPIMilestone


@dataclasses.dataclass
class GuestRequestRequestPayload(PreviousGuestRequestRequestPayload):
    security_group_rules_ingress: Optional[list[dict[str, Any]]] = None
    security_group_rules_egress: Optional[list[dict[str, Any]]] = None


class GuestRequestResponsePayload(PreviousGuestRequestResponsePayload):
    security_group_rules_ingress: Optional[list[dict[str, Any]]]
    security_group_rules_egress: Optional[list[dict[str, Any]]]

    @classmethod
    def from_db(cls, guest: GuestRequest) -> Self:
        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            shelf=guest.shelfname,
            environment=guest.environment.serialize(),
            address=guest.address,
            ssh=PreviousGuestRequestSSHInfoResponsePayload(
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
            security_group_rules_ingress=(
                [rule.serialize() for rule in guest.security_group_rules_ingress]
                if guest.security_group_rules_ingress
                else None
            ),
            security_group_rules_egress=(
                [rule.serialize() for rule in guest.security_group_rules_egress]
                if guest.security_group_rules_egress
                else None
            ),
        )


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: allow passing security group rules for guest creation
    """

    _VERSION = (0, 0, 72)
    _PREVIOUS = PreviousAPIMilestone

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

    router_guests.routes += PreviousAPIMilestone.router_guests.routes
