# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0


import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo, filter_flavors_image_ena_support


def test_ena_supported(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.ena_support = True

    r_suitable_flavors = filter_flavors_image_ena_support(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors


def test_ena_not_supported(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.ena_support = False

    r_suitable_flavors = filter_flavors_image_ena_support(logger, session, aws_pool, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap().matched_flavors] == ['x86_64.1', 'x86_64.2']
