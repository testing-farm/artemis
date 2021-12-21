# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast

import gluetool.glue
import gluetool.log

from tft.artemis.drivers import ImageInfoMapperOptionalResultType
from tft.artemis.drivers.aws import AWSDriver, AWSPoolImageInfo
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_AWS_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: AWSDriver,
    environment: Environment,
) -> ImageInfoMapperOptionalResultType[AWSPoolImageInfo]:
    return cast(
        ImageInfoMapperOptionalResultType[AWSPoolImageInfo],
        map_environment_to_image_info(
            logger,
            pool,
            environment,
            mapping_filename='artemis-image-map-aws.yaml'
        )
    )
