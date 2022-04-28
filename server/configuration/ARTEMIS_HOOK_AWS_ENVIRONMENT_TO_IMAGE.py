# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os.path
from typing import cast

import gluetool.glue
import gluetool.log
from gluetool.result import Error

from tft.artemis.drivers import ImageInfoMapperOptionalResultType
from tft.artemis.drivers.aws import KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH, \
    KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE, AWSDriver, AWSPoolImageInfo
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_AWS_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: AWSDriver,
    environment: Environment,
) -> ImageInfoMapperOptionalResultType[AWSPoolImageInfo]:
    r_mapping_filepath = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH.get_value(pool=pool)

    if r_mapping_filepath.is_error:
        return Error(r_mapping_filepath.unwrap_error())

    r_needle_template = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE.get_value(pool=pool)

    if r_needle_template.is_error:
        return Error(r_needle_template.unwrap_error())

    return cast(
        ImageInfoMapperOptionalResultType[AWSPoolImageInfo],
        map_environment_to_image_info(
            logger,
            pool,
            environment,
            r_needle_template.unwrap(),
            mapping_filepath=os.path.abspath(r_mapping_filepath.unwrap())
        )
    )
