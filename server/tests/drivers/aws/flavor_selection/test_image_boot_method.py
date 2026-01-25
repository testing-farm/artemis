# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast
from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy.orm.session
from gluetool.result import Ok

from tft_artemis.db import GuestRequest
from tft_artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo
from tft_artemis.environment import FlavorBootMethodType, constraints_from_environment_requirements


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

    r_suitable_flavors = aws_pool._filter_flavors_image_boot_method(logger, session, guest_request, image, flavors)

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

    r_suitable_flavors = aws_pool._filter_flavors_image_boot_method(logger, session, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap() == flavors


_BOOT_METHOD_MATRIX = [
    (['bios'], '= bios', ['x86_64.1', 'x86_64.2', 'x86_64.3']),
    (['uefi'], '= bios', []),
    (['bios', 'uefi'], '= bios', ['x86_64.1', 'x86_64.2']),
    (['bios'], '!= bios', []),
    (['uefi'], '!= bios', ['x86_64.3', 'aarch64.1']),
    (['bios', 'uefi'], '!= bios', ['x86_64.3', 'aarch64.1']),
    (['bios'], '= uefi', []),
    (['uefi'], '= uefi', ['x86_64.3', 'aarch64.1']),
    (['bios', 'uefi'], '= uefi', ['x86_64.3', 'aarch64.1']),
    (['bios'], '!= uefi', ['x86_64.1', 'x86_64.2', 'x86_64.3']),
    (['uefi'], '!= uefi', []),
    (['bios', 'uefi'], '!= uefi', ['x86_64.1', 'x86_64.2']),
]


@pytest.mark.parametrize(
    'image_boot_method, boot_method_constraint, expected_flavors',
    _BOOT_METHOD_MATRIX,
    ids=[
        f'image: {"|".join(image_boot_method)} constraint: {boot_method_constraint}'
        for image_boot_method, boot_method_constraint, _ in _BOOT_METHOD_MATRIX
    ],
)
def test_boot_method(
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

    r_suitable_flavors = aws_pool._filter_flavors_image_boot_method(logger, session, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap()] == expected_flavors
