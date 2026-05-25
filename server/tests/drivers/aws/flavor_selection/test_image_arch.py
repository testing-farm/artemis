# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0


import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers._image_flavor_filtering import filter_flavors_image_arch
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo


def test_sanity(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    r_suitable_flavors = filter_flavors_image_arch(logger, session, aws_pool, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap().matched_flavors] == ['x86_64.1', 'x86_64.2', 'x86_64.3']


def test_no_arch(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.arch = None

    r_suitable_flavors = filter_flavors_image_arch(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors
