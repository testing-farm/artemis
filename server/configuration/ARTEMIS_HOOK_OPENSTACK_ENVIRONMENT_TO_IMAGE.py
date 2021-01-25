import os

from tft.artemis import Failure
from tft.artemis.drivers import PoolImageInfoType
from tft.artemis.drivers.openstack import OpenStackDriver
from tft.artemis.environment import Environment

import gluetool.glue
import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

from typing import Optional


def _map_compose_to_name(logger: gluetool.log.ContextAdapter, compose_id: str) -> Result[str, Failure]:
    configuration_dir = os.getenv('ARTEMIS_CONFIG_DIR', '/configuration')
    compose_image_map = os.path.join(configuration_dir, 'artemis-image-map-openstack.yaml')

    if not os.path.isfile(compose_image_map):
        return Error(Failure('Can not find an image map file {}'.format(compose_image_map)))

    pattern_map = PatternMap(compose_image_map, allow_variables=True, logger=logger)

    try:
        image_name = pattern_map.match(compose_id)

    except gluetool.glue.GlueError:
        error = 'cannot map compose {} to image name'.format(compose_id)
        logger.error(error)

        return Error(Failure(error))

    return Ok(image_name[0] if isinstance(image_name, list) else image_name)


def hook_OPENSTACK_ENVIRONMENT_TO_IMAGE(
    *,
    logger: gluetool.log.ContextAdapter,
    pool: OpenStackDriver,
    environment: Environment
) -> Result[PoolImageInfoType, Failure]:
    image_name: Optional[str] = None

    try:
        logger.info('deciding image for {}'.format(environment))

        # Convert compose to image name
        r_image_name = _map_compose_to_name(logger, environment.os.compose)

        if r_image_name.is_error:
            return Error(r_image_name.unwrap_error())

        image_name = r_image_name.unwrap()

        logger.info('mapped {} to image {}'.format(environment, image_name))

        return pool.image_info_by_name(logger, image_name)

    except Exception as exc:
        return Error(Failure.from_exc(
            'crashed while mapping environment to image',
            exc,
            environment=environment
        ))
