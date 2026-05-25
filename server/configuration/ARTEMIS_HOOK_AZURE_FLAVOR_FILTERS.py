# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Default flavor filtering for flavor-based pools.
"""

from collections.abc import Sequence
from typing import Any

import gluetool.log
import sqlalchemy

import tft.artemis.db
import tft.artemis.drivers
from tft.artemis.drivers import PoolImageInfo
from tft.artemis.drivers._image_flavor_filtering import (
    FilterReturnType,
    filter_flavors_default_fallback,
    filter_flavors_image_arch,
    filter_flavors_image_compatible,
    filter_flavors_prefer_default_flavor,
    run_image_flavor_filters,
)
from tft.artemis.environment import Flavor


def hook_AZURE_FLAVOR_FILTERS(  # noqa: N802
    *,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: tft.artemis.drivers.FlavorBasedPoolDriver[Any, Any, Any, Any, Any],
    guest_request: tft.artemis.db.GuestRequest,
    image: PoolImageInfo,
    flavors: Sequence[Flavor],
) -> FilterReturnType[Flavor]:
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
            filter_flavors_prefer_default_flavor,
            filter_flavors_default_fallback,
        ],
    )
