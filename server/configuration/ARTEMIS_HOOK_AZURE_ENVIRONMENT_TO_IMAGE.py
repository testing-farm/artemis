# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os.path

import gluetool.glue
import gluetool.log
from gluetool.result import Error

from tft.artemis.drivers import ImageInfoMapperResultType, PoolImageInfo
from tft.artemis.drivers.azure import KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH, \
    KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE, AzureDriver
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_AZURE_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: AzureDriver,
    environment: Environment,
) -> ImageInfoMapperResultType[PoolImageInfo]:
    r_mapping_filepath = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH.get_value(entityname=pool.poolname)

    if r_mapping_filepath.is_error:
        return Error(r_mapping_filepath.unwrap_error())

    r_needle_template = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE.get_value(entityname=pool.poolname)

    if r_needle_template.is_error:
        return Error(r_needle_template.unwrap_error())

    return map_environment_to_image_info(
        logger,
        pool,
        environment,
        r_needle_template.unwrap(),
        mapping_filepath=os.path.abspath(r_mapping_filepath.unwrap())
    )
