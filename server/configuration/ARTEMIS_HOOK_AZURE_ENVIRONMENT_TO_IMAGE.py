# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.glue
import gluetool.log

from tft.artemis.drivers import ImageInfoMapperOptionalResultType, PoolImageInfo
from tft.artemis.drivers.azure import AzureDriver
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_AZURE_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: AzureDriver,
    environment: Environment,
) -> ImageInfoMapperOptionalResultType[PoolImageInfo]:
    return map_environment_to_image_info(
        logger,
        pool,
        environment,
        mapping_filename='artemis-image-map-azure.yaml'
    )
