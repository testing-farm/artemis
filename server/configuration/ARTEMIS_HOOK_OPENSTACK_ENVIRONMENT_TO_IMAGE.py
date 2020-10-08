import tft.artemis.hooks
from tft.artemis import Failure
from tft.artemis.drivers import PoolImageInfoType
from tft.artemis.drivers.openstack import OpenStackDriver
from tft.artemis.environment import Environment

import gluetool.glue
import gluetool.log
from gluetool.result import Result

from typing import Optional


def hook_OPENSTACK_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[OpenStackDriver] = None,
    environment: Optional[Environment] = None,
) -> Result[PoolImageInfoType, Failure]:
    assert logger is not None
    assert pool is not None
    assert environment is not None

    return tft.artemis.hooks.map_environment_to_image_info(
        logger,
        pool,
        environment,
        mapping_filename='artemis-image-map-openstack.yaml'
    )
