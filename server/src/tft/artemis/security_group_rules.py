# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import ipaddress
from typing import Any, Dict, List, Optional

from gluetool.result import Error, Ok, Result

from . import Failure, SerializableContainer

SecurityGroupRulesInput = Optional[List[Dict[str, Any]]]


@dataclasses.dataclass(repr=False)
class SecurityGroupRule(SerializableContainer):
    # ingress / egress
    type: str
    protocol: str
    port_min: int
    port_max: int
    cidr: str

    @classmethod
    def validate_cidr(cls, cidr_or_ip: str) -> str:
        "Raises ValueError if validation didn't succeed, otherwise returns normalized CIDR"
        return str(ipaddress.ip_network(cidr_or_ip))

    def __post_init__(self) -> None:
        self.cidr = self.validate_cidr(self.cidr)

    @property
    def is_ipv6(self) -> bool:
        return ipaddress.ip_network(self.cidr).version == 6


@dataclasses.dataclass(repr=False)
class SecurityGroupRules(SerializableContainer):
    ingress: List[SecurityGroupRule] = dataclasses.field(default_factory=list)
    egress: List[SecurityGroupRule] = dataclasses.field(default_factory=list)

    def update(self, data: List[SecurityGroupRule]) -> None:
        self.ingress.extend([rule for rule in data if rule.type == 'ingress'])
        self.egress.extend([rule for rule in data if rule.type == 'egress'])

    def extend(self, rules: 'SecurityGroupRules') -> None:
        # NOTE(ivasilev) Probably worth checking for and filtering out duplicates one day
        self.ingress.extend(rules.ingress)
        self.egress.extend(rules.egress)

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'SecurityGroupRules':
        return SecurityGroupRules(
            ingress=[SecurityGroupRule.unserialize(rule) for rule in serialized['ingress']],
            egress=[SecurityGroupRule.unserialize(rule) for rule in serialized['egress']],
        )

    @classmethod
    def load_from_pool_config(cls, serialized_config: List[Dict[str, Any]]) -> Result['SecurityGroupRules', Failure]:
        """
        We are being permissive with clients and allow then to specify multiple cidrs per rule, pool config not
        excluded. However artemis expects one rule to hold one cidr only, so in case more are there we need to convert
        those into multiple SecurityGroupRule objects.
        """
        res = SecurityGroupRules()
        rules_from_config = []
        for rule in serialized_config:
            # Either port or port_min/port_max have to be defined in config, look for port_min/port_max first
            port_min = rule.get('port_min')
            if not port_min:
                # Convert single port or -1 to expected port_min
                port_min = 0 if rule['port'] == -1 else str(rule['port']).split('-')[0]
            port_max = rule.get('port_max')
            if not port_max:
                # Convert single port or -1 to expected port_max
                port_max = 65535 if rule['port'] == -1 else str(rule['port']).split('-')[-1]

            # Validate port numbers
            try:
                port_min = int(port_min)
                port_max = int(port_max)
            except ValueError as err:
                return Error(Failure.from_exc('Failed to parse port number, expected int', err))

            # Convert list of cidrs to multiple rules with 1 cidr per rule
            for cidr in rule['cidr']:
                try:
                    rules_from_config.append(
                        SecurityGroupRule(
                            type=rule['type'],
                            protocol=str(rule['protocol']),
                            port_min=port_min,
                            port_max=port_max,
                            cidr=cidr,
                        )
                    )
                except ValueError as err:
                    return Error(Failure.from_exc('Failed to parse CIDR', err))

        res.update(rules_from_config)

        return Ok(res)
