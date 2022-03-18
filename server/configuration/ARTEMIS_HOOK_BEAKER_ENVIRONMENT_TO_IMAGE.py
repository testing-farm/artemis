# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os.path

import gluetool.glue
import gluetool.log
from gluetool.result import Error

from tft.artemis.drivers import ImageInfoMapperOptionalResultType, PoolImageInfo
from tft.artemis.drivers.beaker import KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH, BeakerDriver
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_BEAKER_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: BeakerDriver,
    environment: Environment,
) -> ImageInfoMapperOptionalResultType[PoolImageInfo]:
    r_mapping_filepath = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH.get_value(pool=pool)

    if r_mapping_filepath.is_error:
        return Error(r_mapping_filepath.unwrap_error())

    return map_environment_to_image_info(
        logger,
        pool,
        environment,
        mapping_filepath=os.path.abspath(r_mapping_filepath.unwrap())
    )
