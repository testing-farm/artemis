# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy.orm.session
from tmt.hardware import UNITS

import tft.artemis.drivers
from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo
from tft.artemis.environment import FlavorBoot


def _mock_pool_resources_usage(monkeypatch: pytest.MonkeyPatch, flavor_counts: dict[str, int]) -> None:
    mock_usage = MagicMock()
    mock_usage.flavors = flavor_counts
    mock_usage.do_sync = MagicMock()

    monkeypatch.setattr(tft.artemis.drivers, 'PoolResourcesUsage', MagicMock(return_value=mock_usage))


def test_empty_flavors(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_pool_resources_usage(monkeypatch, {})

    r_result = aws_pool._filter_flavors_least_crowded(logger, session, guest_request, image, [])

    assert r_result.unwrap() == []


def test_sorted_by_usage(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Use distinct names since the filter sorts by flavor.name
    test_flavors = [
        AWSFlavor(
            name='flavor-a',
            id='a.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
        AWSFlavor(
            name='flavor-b',
            id='b.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
        AWSFlavor(
            name='flavor-c',
            id='c.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
    ]

    _mock_pool_resources_usage(
        monkeypatch,
        {
            'flavor-a': 10,
            'flavor-b': 2,
            'flavor-c': 7,
        },
    )

    r_result = aws_pool._filter_flavors_least_crowded(logger, session, guest_request, image, test_flavors)

    assert [f.id for f in r_result.unwrap()] == ['b.1', 'c.1', 'a.1']


def test_all_same_usage(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_flavors = [
        AWSFlavor(
            name='flavor-a',
            id='a.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
        AWSFlavor(
            name='flavor-b',
            id='b.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
    ]

    _mock_pool_resources_usage(
        monkeypatch,
        {
            'flavor-a': 5,
            'flavor-b': 5,
        },
    )

    r_result = aws_pool._filter_flavors_least_crowded(logger, session, guest_request, image, test_flavors)

    # Same usage count — original order preserved (stable sort)
    assert [f.id for f in r_result.unwrap()] == ['a.1', 'b.1']


def test_unknown_flavors_default_to_zero(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_flavors = [
        AWSFlavor(
            name='flavor-known',
            id='k.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
        AWSFlavor(
            name='flavor-unknown',
            id='u.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(method=['bios']),
        ),
    ]

    _mock_pool_resources_usage(
        monkeypatch,
        {
            'flavor-known': 10,
        },
    )

    r_result = aws_pool._filter_flavors_least_crowded(logger, session, guest_request, image, test_flavors)

    result = r_result.unwrap()
    # flavor-unknown not in usage dict -> defaults to 0, comes first
    assert [f.id for f in result] == ['u.1', 'k.1']
