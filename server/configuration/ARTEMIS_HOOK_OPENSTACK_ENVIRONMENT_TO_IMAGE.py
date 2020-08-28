import os
import re

from tft.artemis import Failure
from tft.artemis.drivers.openstack import OpenStackDriver
from tft.artemis.environment import Environment

import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

import stackprinter

from typing import Any, List, Optional


def _map_compose_to_name(logger: gluetool.log.ContextAdapter, compose_id: str) -> Result[str, Failure]:
    compose_image_map = '/configuration/artemis-image-map-openstack.yaml'
    if not os.path.isfile(compose_image_map):
        return Error(Failure('Can not find an image map file {}'.format(compose_image_map)))

    pattern_map = PatternMap(compose_image_map, allow_variables=True, logger=logger)

    image_name = pattern_map.match(compose_id)

    if image_name:
        return Ok(image_name)

    error = 'cannot map compose {} to image name'.format(compose_id)
    logger.error(error)

    return Error(Failure(error))


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

        if environment.compose.is_openstack:
            # Use specified image

            assert environment.compose.openstack is not None

            image_name = environment.compose.openstack.image

        else:
            # Convert compose to image name

            assert environment.compose.id is not None

            r_image_name = _map_compose_to_name(logger, environment.compose.id)
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
