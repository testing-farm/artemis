# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel

from ... import db as artemis_db
from ...guest import GuestState
from . import GuestSSHInfo


@dataclasses.dataclass
class GuestRequest_v0_0_72:
    keyname: str
    environment: Dict[str, Optional[Any]]
    priority_group: Optional[str] = None
    shelfname: Optional[str] = None
    user_data: Optional[artemis_db.UserDataType] = None
    post_install_script: Optional[str] = None
    log_types: Optional[List[Any]] = None
    watchdog_dispatch_delay: Optional[int] = None
    watchdog_period_delay: Optional[int] = None
    bypass_shelf_lookup: bool = False
    skip_prepare_verify_ssh: bool = False
    security_group_rules_ingress: Optional[List[Dict[str, Any]]] = None
    security_group_rules_egress: Optional[List[Dict[str, Any]]] = None


class GuestResponse_v0_0_72(BaseModel):
    guestname: str
    owner: str
    shelf: Optional[str]
    environment: Dict[str, Any]
    address: Optional[str]
    ssh: GuestSSHInfo
    state: GuestState
    state_mtime: Optional[datetime.datetime]
    mtime: datetime.datetime
    user_data: artemis_db.UserDataType
    skip_prepare_verify_ssh: Optional[bool]
    post_install_script: Optional[str]
    ctime: datetime.datetime
    console_url: Optional[str]
    console_url_expires: Optional[datetime.datetime]
    log_types: List[Tuple[str, artemis_db.GuestLogContentType]]
    watchdog_dispatch_delay: Optional[int]
    watchdog_period_delay: Optional[int]
    security_group_rules_ingress: Optional[List[Dict[str, Any]]] = None
    security_group_rules_egress: Optional[List[Dict[str, Any]]] = None

    poolname: Optional[str]
    last_poolname: Optional[str]

    @classmethod
    def from_db(cls, guest: artemis_db.GuestRequest) -> 'GuestResponse_v0_0_72':
        return cls(
            guestname=guest.guestname,
            owner=guest.ownername,
            shelf=guest.shelfname,
            environment=guest.environment.serialize(),
            address=guest.address,
            ssh=GuestSSHInfo(
                username=guest.ssh_username,
                port=guest.ssh_port,
                keyname=guest.ssh_keyname
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
            security_group_rules_ingress=([rule.serialize() for rule in guest.security_group_rules_ingress]
                                          if guest.security_group_rules_ingress else None),
            security_group_rules_egress=([rule.serialize() for rule in guest.security_group_rules_egress]
                                         if guest.security_group_rules_egress else None)
        )
