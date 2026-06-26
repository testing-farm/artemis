# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Default flavor filtering for flavor-based pools.
"""

from collections.abc import Sequence

import gluetool.log
import sqlalchemy

import tft.artemis.db
import tft.artemis.drivers
from tft.artemis.drivers._image_flavor_filtering import (
    FilterReturnType,
    filter_flavors_default_fallback,
    filter_flavors_image_arch,
    filter_flavors_image_compatible,
    filter_flavors_prefer_default_flavor,
    run_image_flavor_filters,
)
from tft.artemis.drivers.aws import (
    AWSDriver,
    AWSFlavor,
    AWSPoolImageInfo,
    filter_flavors_console_url_support,
    filter_flavors_image_boot_method,
    filter_flavors_image_ena_support,
)


def hook_AWS_FLAVOR_FILTERS(  # noqa: N802
    *,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: AWSDriver,
    guest_request: tft.artemis.db.GuestRequest,
    image: AWSPoolImageInfo,
    flavors: Sequence[AWSFlavor],
) -> FilterReturnType[AWSFlavor]:
    return run_image_flavor_filters(
        logger,
        session,
        pool,
        guest_request,
        image,
        flavors,
        [
            filter_flavors_image_arch,
            filter_flavors_image_compatible,
            filter_flavors_console_url_support,
            filter_flavors_image_ena_support,
            filter_flavors_image_boot_method,
            filter_flavors_prefer_default_flavor,
            filter_flavors_default_fallback,
        ],
    )
