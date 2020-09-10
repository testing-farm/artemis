import os

from tft.artemis import Failure
from tft.artemis.drivers.openstack import OpenStackDriver
from tft.artemis.environment import Environment

import gluetool.glue
import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

import stackprinter

from typing import Any, Optional


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


def _image_by_name(
    logger: gluetool.log.ContextAdapter, pool: OpenStackDriver, image_name: str
) -> Result[Any, Failure]:
    r_images_list = pool._run_os(['image', 'list'])

    if r_images_list.is_error:
        error = 'Fail to get images'
        logger.error(error, sentry=True)
        return Error(Failure(error))

    images_list = r_images_list.unwrap()

    for image_data in images_list:
        if image_data['Name'] != image_name:
            continue

        return Ok(image_data['ID'])

    error = 'cannot find image {}'.format(image_name)
    logger.error(error)

    return Error(Failure(error))


def hook_OPENSTACK_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[OpenStackDriver] = None,
    environment: Optional[Environment] = None,
) -> Result[str, Failure]:
    assert logger is not None
    assert pool is not None
    assert environment is not None

    image_name: Optional[str] = None

    try:
        logger.info('deciding image for {}'.format(environment))

        # Convert compose to image name

        r_image_name = _map_compose_to_name(logger, environment.os.compose)
        if r_image_name.is_error:
            return r_image_name

        image_name = r_image_name.unwrap()

        if image_name is None:
            raise Exception

        logger.info('mapped {} to image {}'.format(environment, image_name))

        return _image_by_name(logger, pool, image_name)

    except Exception as exc:
        logger.error('crashed while mapping {} to image:\n{}'.format(environment, stackprinter.format(exc)))

    error = 'failed to map {} to image'.format(environment)
    logger.error(error)

    return Error(Failure(error))
