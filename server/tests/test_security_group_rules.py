# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Any

import pytest
import yaml

from tft.artemis.security_group_rules import SecurityGroupRule, SecurityGroupRules


@pytest.mark.parametrize(
    ('data',),
    [
        (
            {
                'ingress': [
                    {'type': 'ingress', 'port_min': 22, 'port_max': 22, 'protocol': 'tcp', 'cidr': '10.0.0.42/32'}
                ],
                'egress': [],
            },
        ),
    ],
)
def test_deserialization(data: dict[str, Any]) -> None:
    security_group_rules = SecurityGroupRules.unserialize(data)
    assert isinstance(security_group_rules, SecurityGroupRules)
    assert isinstance(security_group_rules.ingress[0], SecurityGroupRule)


def test_update() -> None:
    security_group_rules = SecurityGroupRules()
    rules_to_add = [
        SecurityGroupRule(type='ingress', port_min=22, port_max=22, protocol='tcp', cidr='10.0.0.42/32'),
        SecurityGroupRule(type='egress', port_min=0, port_max=65535, protocol='-1', cidr='10.0.0.0/8'),
    ]
    security_group_rules.update(rules_to_add)
    assert security_group_rules.ingress == [rules_to_add[0]]
    assert security_group_rules.egress == [rules_to_add[1]]


def test_extend() -> None:
    security_group_rules = SecurityGroupRules(
        ingress=[SecurityGroupRule(type='ingress', port_min=22, port_max=22, protocol='tcp', cidr='10.0.0.42/32')],
        egress=[SecurityGroupRule(type='egress', port_min=0, port_max=65535, protocol='-1', cidr='10.0.0.0/8')],
    )
    rules_to_add = SecurityGroupRules(
        ingress=[SecurityGroupRule(type='ingress', port_min=22, port_max=22, protocol='tcp', cidr='10.0.0.24/32')]
    )
    security_group_rules.extend(rules_to_add)
    assert len(security_group_rules.ingress) == 2
    assert len(security_group_rules.egress) == 1


@pytest.mark.parametrize(
    ('config', 'expected_ingress', 'expected_egress'),
    [
        (
            """
security-group-rules:
    - type: ingress
      protocol: tcp
      port: "22"
      cidr:
        - 95.140.241.12/32
        - 89.102.32.120/32
        - 185.189.160.75/32
    - type: ingress
      protocol: tcp
      port: "22-4444"
      cidr:
        - 95.140.241.12/32
    - type: ingress
      protocol: -1
      port_min: 7777
      port_max: 8888
      cidr:
        - 89.102.32.120/32
    - type: egress
      protocol: tcp
      port: -1
      cidr:
          - 42.42.42.42/32
        """,
            [
                SecurityGroupRule(type='ingress', protocol='tcp', port_min=22, port_max=22, cidr='95.140.241.12/32'),
                SecurityGroupRule(type='ingress', protocol='tcp', port_min=22, port_max=22, cidr='89.102.32.120/32'),
                SecurityGroupRule(type='ingress', protocol='tcp', port_min=22, port_max=22, cidr='185.189.160.75/32'),
                SecurityGroupRule(type='ingress', protocol='tcp', port_min=22, port_max=4444, cidr='95.140.241.12/32'),
                SecurityGroupRule(type='ingress', protocol='-1', port_min=7777, port_max=8888, cidr='89.102.32.120/32'),
            ],
            [
                SecurityGroupRule(type='egress', protocol='tcp', port_min=0, port_max=65535, cidr='42.42.42.42/32'),
            ],
        )
    ],
)
def test_load_from_pool_config(
    config: str, expected_ingress: list[SecurityGroupRule], expected_egress: list[SecurityGroupRule]
) -> None:
    rules_from_config = yaml.safe_load(config)
    security_group_rules = SecurityGroupRules.load_from_pool_config(rules_from_config['security-group-rules']).unwrap()
    assert security_group_rules.ingress == expected_ingress
    assert security_group_rules.egress == expected_egress


@pytest.mark.parametrize(
    ('config', 'expected_err'),
    [
        (
            """
security-group-rules:
    - type: ingress
      protocol: tcp
      port: 'bad port number'
      cidr:
        - 95.140.241.12/32
        """,
            'Failed to parse port number, expected int',
        ),
        (
            """
security-group-rules:
    - type: ingress
      protocol: tcp
      port: 42
      cidr:
        - None
        """,
            'Failed to parse CIDR',
        ),
        (
            """
security-group-rules:
    - type: ingress
      protocol: tcp
      port: 42
      cidr:
        - just.a.bad.cidr/100500
        """,
            'Failed to parse CIDR',
        ),
    ],
)
def test_load_from_pool_config_invalid(config: str, expected_err: str) -> None:
    rules_from_config = yaml.safe_load(config)
    r_security_group_rules = SecurityGroupRules.load_from_pool_config(rules_from_config['security-group-rules'])
    assert r_security_group_rules.is_error
    assert expected_err in str(r_security_group_rules.unwrap_error())
