# NOTE(ivasilev) That's a copy of ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE.py with minimal changes. Should be
# moved to hooks library one day.

import os

from tft.artemis import Failure
from tft.artemis.drivers.azure import AzureDriver
from tft.artemis.environment import Environment

import gluetool.glue
import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

from typing import Any, Optional


def _map_compose_to_name(logger: gluetool.log.ContextAdapter, compose_id: str) -> Result[str, Failure]:

    configuration_dir = os.getenv('ARTEMIS_CONFIG_DIR', '/configuration')
    compose_image_map = os.path.join(configuration_dir, 'artemis-image-map-azure.yaml')

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
    logger: gluetool.log.ContextAdapter, pool: AzureDriver, image_name: str
) -> Result[Any, Failure]:
    r_images_show = pool._run_cmd_with_auth(['vm', 'image', 'show', '--urn', image_name])

    if r_images_show.is_error:
        error = 'Fail to show image details. The image does not exist?'
        logger.error(error, sentry=True)
        return Error(Failure(error))

    return Ok(image_name)


def hook_AZURE_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[AzureDriver] = None,
    environment: Optional[Environment] = None
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
        return Error(Failure.from_exc(
            'crashed while mapping environment to image',
            exc,
            environment=environment
        ))

    return Error(Failure(
        'failed to map environment to image',
        environment=environment
    ))
