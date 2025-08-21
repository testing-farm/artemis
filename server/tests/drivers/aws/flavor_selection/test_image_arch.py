# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import List

import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo


def test_sanity(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    suitable_flavors = aws_pool.filter_flavors_image_arch(logger, session, guest_request, image, flavors)

    assert [flavor.id for flavor in suitable_flavors] == ['x86_64.1', 'x86_64.2', 'x86_64.3']


def test_no_arch(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: List[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.arch = None

    suitable_flavors = aws_pool.filter_flavors_image_arch(logger, session, guest_request, image, flavors)

    assert suitable_flavors == flavors
