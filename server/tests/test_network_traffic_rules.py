# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import enum
from collections.abc import Iterator
from ipaddress import IPv4Network
from typing import Optional

import pytest

ALL_PROTOCOLS = 0
ALL_PORTS = (0, 65535)

RULES_MAX_SIZE = 64


class RuleAction(enum.Enum):
    ALLOW = 'allow'
    DENY = 'deny'

    @property
    def toggle(self) -> 'RuleAction':
        return RuleAction.DENY if self == RuleAction.ALLOW else RuleAction.ALLOW


@dataclasses.dataclass(frozen=True)
class Rule:
    """
    A rule to apply on network traffic.
    """

    #: Whether the traffic shall be allowed or denied.
    action: RuleAction

    #: Address range the traffic must come from (ingress rules) or head to (egress rules).
    address_range: IPv4Network

    @classmethod
    def from_str(cls, s: str) -> 'Rule':
        t = [u.strip() for u in s.split(' ')]

        return Rule(
            action=RuleAction.ALLOW if t[0] == 'allow' else RuleAction.DENY,
            address_range=IPv4Network(t[1]),
        )

    def to_str(self) -> str:
        return f'{self.action.value} {self.address_range}'

    def __str__(self) -> str:
        return self.to_str()

    def is_address_range_overlapping(self, other: 'Rule') -> bool:
        """
        Test whether this rule's address range overlaps with the other rule's.
        """

        return self.address_range.overlaps(other.address_range)

    def is_supernet_of(self, other: 'Rule') -> bool:
        """
        Test whether this rule's address range is supernet of the other rule's.
        """

        return self.address_range.supernet_of(other.address_range)

    def exclude_address_range(self, other: 'Rule') -> Iterator['Rule']:
        """
        Generate address range by excluding the other rule's address range from this rule's.
        """

        if self.address_range == other.address_range:
            if self.action is RuleAction.DENY and other.action is RuleAction.ALLOW:
                return

            yield dataclasses.replace(
                self,
                action=self.action.toggle,
            )

        else:
            for address_range in self.address_range.address_exclude(other.address_range):
                yield dataclasses.replace(
                    self,
                    address_range=address_range,
                )


class Rules(list[Rule]):
    """
    A collection of rules.
    """

    def print(self, header: str) -> None:
        print(header)

        for rule in self:
            print(f'    {rule}')

        print()

    def append(self, rule: Rule) -> None:
        super().append(rule)

        if len(self) == RULES_MAX_SIZE:
            raise Exception('Too many rules')

        self.sort(key=lambda rule: rule.address_range)


def to_aws_sg_rules(rules: Rules) -> Rules:
    # AWS SG supports `allow` rules only, `deny` is implicit
    return Rules([rule for rule in rules if rule.action != RuleAction.DENY])


# TODO: pinnable rules that cannot be split
# TODO: per-IP protocol facets
# TODO: port ranges
# TODO: compact rules
def resolve(
    current_rules: Rules,
    user_rules: Rules,
) -> Rules:
    """
    Merge and amend the given rules.
    """

    current_rules.print('Starting rules')

    def _find_conflicts(rule: Rule, rules: list[Rule]) -> Optional[Rule]:
        conflicting_rules = [
            existing_rule
            for existing_rule in rules
            if existing_rule.action is not rule.action and rule.is_address_range_overlapping(existing_rule)
        ]

        return conflicting_rules[0] if conflicting_rules else None

    print('User rules')

    while user_rules:
        user_rule = user_rules.pop(0)

        print(f'    {user_rule}')

        if _find_conflicts(user_rule, current_rules):
            while conflicting_existing_rule := _find_conflicts(user_rule, current_rules):
                print(f'        overlaps with existing rule: {conflicting_existing_rule}')

                if user_rule.address_range == conflicting_existing_rule.address_range:
                    print(f'            user {user_rule} is equal in range to existing {conflicting_existing_rule}')

                    current_rules.remove(conflicting_existing_rule)
                    current_rules.append(user_rule)

                    break

                if user_rule.is_supernet_of(conflicting_existing_rule):
                    print(f'            user {user_rule} is a supernet of existing {conflicting_existing_rule}')

                    current_rules.remove(conflicting_existing_rule)

                    for conflictless_rule in user_rule.exclude_address_range(conflicting_existing_rule):
                        print(f'            splinter: {conflictless_rule}')

                        user_rules.append(conflictless_rule)

                    break

                if conflicting_existing_rule.is_supernet_of(user_rule):
                    print(f'            existing {conflicting_existing_rule} is a supernet of user {user_rule}')

                    current_rules.remove(conflicting_existing_rule)

                    for conflictless_rule in conflicting_existing_rule.exclude_address_range(user_rule):
                        print(f'            splinter: {conflictless_rule}')

                        if conflictless_rule != user_rule:
                            current_rules.append(conflictless_rule)

                    current_rules.append(user_rule)

                    break

                print('            no clear supernet detected')

                raise Exception

        else:
            print('        no overlaps with existing rules')

            current_rules.append(user_rule)

    print()

    current_rules.print('Final rules')

    print()

    current_rules = to_aws_sg_rules(current_rules)
    current_rules.print('Final AWS SG rules')

    return current_rules


def _test_range_resolution(current_rules: Rules, user_rules: Rules, expected_rules: Rules) -> None:
    actual_rules = resolve(current_rules, user_rules)

    assert actual_rules == expected_rules


@pytest.mark.parametrize(
    ('_current_rules', '_user_rules', '_expected_rules'),
    [
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [],
            [
                'allow 0.0.0.0/0',
            ],
            id='allow all, no user rules',
        ),
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [
                'deny 10.0.0.0/8',
            ],
            [
                'allow 0.0.0.0/5',
                'allow 8.0.0.0/7',
                'allow 11.0.0.0/8',
                'allow 12.0.0.0/6',
                'allow 16.0.0.0/4',
                'allow 32.0.0.0/3',
                'allow 64.0.0.0/2',
                'allow 128.0.0.0/1',
            ],
            id='allow all, user rule `deny 10.0.0.0/8`',
        ),
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [
                'deny 0.0.0.0/0',
                'allow 192.168.97.0/24',
            ],
            [
                'allow 192.168.97.0/24',
            ],
            id='allow all, user rules `deny all`, `allow download.rdu2.redhat.com`',
        ),
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [
                'allow 192.168.97.0/24',
                'deny 0.0.0.0/0',
            ],
            [
                'allow 192.168.97.0/24',
            ],
            id='allow all, user rules `deny all`, `allow download.rdu2.redhat.com`, but in different order',
        ),
        pytest.param(
            [
                'deny 0.0.0.0/0',
                'allow 192.168.79.0/28',
            ],
            [
                'allow 192.168.1.1/32',
            ],
            [
                'allow 192.168.1.1/32',
                'allow 192.168.79.0/28',
            ],
            id='deny all, allow workers, user rule `allow <their IP>`',
        ),
        pytest.param(
            [
                'allow 192.168.0.0/16',
            ],
            [
                # Overlaps but is subnet, not supernet
                'deny 192.168.0.0/17',
            ],
            [
                'allow 192.168.128.0/17',
            ],
            id='allow subnet, user rules `deny <partial overlap>`',
        ),
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [
                'deny 10.0.0.0/8',
                'deny 172.16.0.0/12',
                'deny 192.168.0.0/16',
            ],
            [
                'allow 0.0.0.0/5',
                'allow 8.0.0.0/7',
                'allow 11.0.0.0/8',
                'allow 12.0.0.0/6',
                'allow 16.0.0.0/4',
                'allow 32.0.0.0/3',
                'allow 64.0.0.0/2',
                'allow 128.0.0.0/3',
                'allow 160.0.0.0/5',
                'allow 168.0.0.0/6',
                'allow 172.0.0.0/12',
                'allow 172.32.0.0/11',
                'allow 172.64.0.0/10',
                'allow 172.128.0.0/9',
                'allow 173.0.0.0/8',
                'allow 174.0.0.0/7',
                'allow 176.0.0.0/4',
                'allow 192.0.0.0/9',
                'allow 192.128.0.0/11',
                'allow 192.160.0.0/13',
                'allow 192.169.0.0/16',
                'allow 192.170.0.0/15',
                'allow 192.172.0.0/14',
                'allow 192.176.0.0/12',
                'allow 192.192.0.0/10',
                'allow 193.0.0.0/8',
                'allow 194.0.0.0/7',
                'allow 196.0.0.0/6',
                'allow 200.0.0.0/5',
                'allow 208.0.0.0/4',
                'allow 224.0.0.0/3',
            ],
            id='allow all, user rules `deny <multiple ranges>`',
        ),
        pytest.param(
            ['allow 0.0.0.0/0'],
            [
                'deny 10.0.0.0/8',
                # Re-allow subnet within denied range
                'allow 10.1.0.0/16',
            ],
            [
                'allow 0.0.0.0/5',
                'allow 8.0.0.0/7',
                'allow 10.1.0.0/16',  # Allowed subnet
                'allow 11.0.0.0/8',
                'allow 12.0.0.0/6',
                'allow 16.0.0.0/4',
                'allow 32.0.0.0/3',
                'allow 64.0.0.0/2',
                'allow 128.0.0.0/1',
            ],
            id='allow all, user rules `deny <subnet>`, `allow <subnet of the denied subnet>` (swiss cheese)',
        ),
        pytest.param(
            [
                'allow 192.168.1.0/24',
            ],
            [
                'allow 192.168.1.0/25',
            ],
            [
                # TODO: compact
                'allow 192.168.1.0/24',
                'allow 192.168.1.0/25',
            ],
            id='allow subnet, user rule `allow <narrower subnet>`',
        ),
        pytest.param(
            [
                'allow 192.168.1.0/25',
            ],
            [
                'allow 192.168.1.0/24',
            ],
            [
                # TODO: compact
                'allow 192.168.1.0/24',
                'allow 192.168.1.0/25',
            ],
            id='allow subnet, user rule `allow <wider supernet>`',
        ),
        pytest.param(
            [
                'allow 192.168.1.0/24',
            ],
            [
                'allow 192.168.1.0/24',
            ],
            [
                # TODO: compact
                'allow 192.168.1.0/24',
                'allow 192.168.1.0/24',
            ],
            id='allow subnet, user rule `allow <same subnet>`',
        ),
        pytest.param(
            [
                'deny 0.0.0.0/0',
                'allow 192.168.1.0/24',
            ],
            [
                'deny 0.0.0.0/0',
            ],
            [],
            id='deny all, allow <subnet>, user rule `deny all`',
        ),
        pytest.param(
            [
                'allow 0.0.0.0/0',
            ],
            [
                'deny 192.168.1.100/32',
            ],
            [
                'allow 0.0.0.0/1',
                'allow 128.0.0.0/2',
                'allow 192.0.0.0/9',
                'allow 192.128.0.0/11',
                'allow 192.160.0.0/13',
                'allow 192.168.0.0/24',
                'allow 192.168.1.0/26',
                'allow 192.168.1.64/27',
                'allow 192.168.1.96/30',
                'allow 192.168.1.101/32',
                'allow 192.168.1.102/31',
                'allow 192.168.1.104/29',
                'allow 192.168.1.112/28',
                'allow 192.168.1.128/25',
                'allow 192.168.2.0/23',
                'allow 192.168.4.0/22',
                'allow 192.168.8.0/21',
                'allow 192.168.16.0/20',
                'allow 192.168.32.0/19',
                'allow 192.168.64.0/18',
                'allow 192.168.128.0/17',
                'allow 192.169.0.0/16',
                'allow 192.170.0.0/15',
                'allow 192.172.0.0/14',
                'allow 192.176.0.0/12',
                'allow 192.192.0.0/10',
                'allow 193.0.0.0/8',
                'allow 194.0.0.0/7',
                'allow 196.0.0.0/6',
                'allow 200.0.0.0/5',
                'allow 208.0.0.0/4',
                'allow 224.0.0.0/3',
            ],
            id='allow all, user rule `deny <single IP>`',
        ),
        pytest.param(
            [
                'deny 0.0.0.0/0',
            ],
            [
                'allow 192.168.1.100/32',
                'allow 192.168.1.101/32',
            ],
            [
                'allow 192.168.1.100/32',
                'allow 192.168.1.101/32',
            ],
            id='deny all, user rules `allow <IP address>`, `allow <different IP address>`',
        ),
        pytest.param([], [], [], id='no rules at all'),
        pytest.param(
            [],
            [
                'allow 192.168.1.0/24',
            ],
            [
                'allow 192.168.1.0/24',
            ],
            id='no rules, user rules `allow <range>`',
        ),
    ],
)
def test_range_resolution(_current_rules: list[str], _user_rules: list[str], _expected_rules: list[str]) -> None:
    _test_range_resolution(
        Rules(Rule.from_str(s) for s in _current_rules),
        Rules(Rule.from_str(s) for s in _user_rules),
        Rules(Rule.from_str(s) for s in _expected_rules),
    )
