# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast
from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy.orm.session
from gluetool.result import Ok

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo, FlavorBootMethodType
from tft.artemis.environment import constraints_from_environment_requirements


def test_irrelevant_hw_constraints(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements({'memory': '> 0'})
    )

    r_suitable_flavors = aws_pool._filter_flavors_hw_constraints(logger, session, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap() == flavors


def test_no_constraints(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(return_value=Ok(None))

    r_suitable_flavors = aws_pool._filter_flavors_hw_constraints(logger, session, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap() == flavors


def test_boot_method_match(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.boot.method = ['uefi']

    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements({'boot': {'method': '= uefi'}})
    )

    r_suitable_flavors = aws_pool._filter_flavors_hw_constraints(logger, session, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap()] == ['x86_64.3', 'aarch64.1']


def test_boot_method_mismatch(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.boot.method = ['uefi']

    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements({'boot': {'method': 'none'}})
    )

    r_suitable_flavors = aws_pool._filter_flavors_hw_constraints(logger, session, guest_request, image, flavors)

    assert not r_suitable_flavors.unwrap()


@pytest.mark.parametrize(
    'boot_method_constraint, image_boot_method, expected_flavors',
    (
        ('bios', ['bios'], ['x86_64.1', 'x86_64.2', 'x86_64.3']),
        ('bios', ['bios', 'uefi'], ['x86_64.1', 'x86_64.2']),
        ('bios', ['uefi'], []),
        ('!= bios', ['bios'], ['x86_64.3', 'aarch64.1']),
        ('!= bios', ['bios', 'uefi'], ['x86_64.3', 'aarch64.1']),
        ('!= bios', ['uefi'], ['x86_64.3', 'aarch64.1']),
        ('uefi', ['uefi'], ['x86_64.3', 'aarch64.1']),
        ('uefi', ['bios', 'uefi'], ['x86_64.3', 'aarch64.1']),
        ('uefi', ['bios'], []),
        ('!= uefi', ['uefi'], []),
        ('!= uefi', ['bios', 'uefi'], ['x86_64.1', 'x86_64.2']),
        ('!= uefi', ['bios'], ['x86_64.1', 'x86_64.2', 'x86_64.3']),
    ),
)
def test_boot_method_selection(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
    boot_method_constraint: str,
    image_boot_method: list[FlavorBootMethodType],
    expected_flavors: list[str],
) -> None:
    image.boot.method = image_boot_method

    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements({'boot': {'method': boot_method_constraint}})
    )

    r_suitable_flavors = aws_pool._filter_flavors_hw_constraints(logger, session, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap()] == expected_flavors
