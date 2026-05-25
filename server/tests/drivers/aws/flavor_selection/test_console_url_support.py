# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast
from unittest.mock import MagicMock

import gluetool.log
import sqlalchemy.orm.session

from tft.artemis.db import GuestRequest
from tft.artemis.drivers.aws import AWSDriver, AWSFlavor, AWSPoolImageInfo, filter_flavors_console_url_support


def test_sanity(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    cast(MagicMock, guest_request).requests_guest_log = MagicMock('guest_request.requests_guest_log', return_value=True)

    r_suitable_flavors = filter_flavors_console_url_support(logger, session, aws_pool, guest_request, image, flavors)

    assert [flavor.id for flavor in r_suitable_flavors.unwrap().matched_flavors] == [
        'x86_64.1',
        'x86_64.3',
        'aarch64.1',
    ]


def test_not_requested(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    aws_pool: AWSDriver,
    guest_request: GuestRequest,
    flavors: list[AWSFlavor],
    image: AWSPoolImageInfo,
) -> None:
    cast(MagicMock, guest_request).requests_guest_log = MagicMock(
        'guest_request.requests_guest_log', return_value=False
    )

    r_suitable_flavors = filter_flavors_console_url_support(logger, session, aws_pool, guest_request, image, flavors)

    assert r_suitable_flavors.unwrap().matched_flavors == flavors
