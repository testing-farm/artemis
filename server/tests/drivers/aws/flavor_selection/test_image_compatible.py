# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0


import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers import PoolImageCompatible
from tft.artemis.drivers._image_flavor_filtering import filter_flavors_image_compatible
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo
from tft.artemis.environment import FlavorCompatible


def test_overlap(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.compatible = PoolImageCompatible(distro=['rhel-8', 'rhel8'])

    for flavor in flavors:
        flavor.compatible = FlavorCompatible(distro=['rhel-8', 'rhel-9'])

    r_suitable_flavors = filter_flavors_image_compatible(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors


def test_disjoint(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.compatible = PoolImageCompatible(distro=['rhel-7', 'rhel7'])

    for flavor in flavors:
        flavor.compatible = FlavorCompatible(distro=['rhel-8', 'rhel-9'])

    r_suitable_flavors = filter_flavors_image_compatible(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == []


def test_image_distros_empty(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.compatible = PoolImageCompatible(distro=[])

    for flavor in flavors:
        flavor.compatible = FlavorCompatible(distro=['rhel-8'])

    r_suitable_flavors = filter_flavors_image_compatible(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors


def test_flavor_distros_empty(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    image.compatible = PoolImageCompatible(distro=['rhel-7'])

    for flavor in flavors:
        flavor.compatible = FlavorCompatible(distro=[])

    r_suitable_flavors = filter_flavors_image_compatible(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors
