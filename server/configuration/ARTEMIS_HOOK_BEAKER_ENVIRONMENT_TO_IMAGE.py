import gluetool.glue
import gluetool.log

from tft.artemis.drivers import ImageInfoMapperOptionalResultType, PoolImageInfo
from tft.artemis.drivers.beaker import BeakerDriver
from tft.artemis.drivers.hooks import map_environment_to_image_info
from tft.artemis.environment import Environment


def hook_BEAKER_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: BeakerDriver,
    environment: Environment,
) -> ImageInfoMapperOptionalResultType[PoolImageInfo]:
    return map_environment_to_image_info(
        logger,
        pool,
        environment,
        mapping_filename='artemis-image-map-beaker.yaml'
    )
