# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import List, cast
from unittest.mock import MagicMock

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Ok

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo
from tft.artemis.environment import constraints_from_environment_requirements


def test_irrelevant_hw_constraints(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements(
            {
                'memory': '> 0'
            }
        )
    )

    suitable_flavors = aws_pool._filter_flavors_hw_constraints(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert suitable_flavors == flavors


def test_no_constraints(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=Ok(None)
    )

    suitable_flavors = aws_pool._filter_flavors_hw_constraints(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert suitable_flavors == flavors


def test_boot_method_match(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    image.boot.method = ['uefi']

    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements(
            {
                'boot': {
                    'method': '= uefi'
                }
            }
        )
    )

    suitable_flavors = aws_pool._filter_flavors_hw_constraints(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert [flavor.id for flavor in suitable_flavors] == ['x86_64.3', 'aarch64.1']


def test_boot_method_mismatch(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    image.boot.method = ['uefi']

    cast(MagicMock, guest_request).environment.get_hw_constraints = MagicMock(
        return_value=constraints_from_environment_requirements(
            {
                'boot': {
                    'method': 'none'
                }
            }
        )
    )

    suitable_flavors = aws_pool._filter_flavors_hw_constraints(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert not suitable_flavors
