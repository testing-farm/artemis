# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import List

import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo


def test_ena_supported(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    image.ena_support = True

    suitable_flavors = aws_pool._filter_flavors_image_ena_support(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert suitable_flavors == flavors


def test_ena_not_supported(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo
) -> None:
    image.ena_support = False

    suitable_flavors = aws_pool._filter_flavors_image_ena_support(
        logger,
        session,
        guest_request,
        image,
        flavors
    )

    assert [flavor.id for flavor in suitable_flavors] == ['x86_64.1', 'x86_64.2']
