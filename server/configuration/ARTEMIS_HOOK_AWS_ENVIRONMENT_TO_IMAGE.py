import os

from tft.artemis import Failure
from tft.artemis.drivers.aws import AWSDriver
from tft.artemis.environment import Environment

import gluetool.glue
import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

from typing import Any, Optional


def _map_compose_to_name(logger: gluetool.log.ContextAdapter, compose_id: str) -> Result[str, Failure]:

    configuration_dir = os.getenv('ARTEMIS_CONFIG_DIR', '/configuration')
    compose_image_map = os.path.join(configuration_dir, 'artemis-image-map-aws.yaml')

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
    logger: gluetool.log.ContextAdapter, pool: AWSDriver, image_name: str
) -> Result[Any, Failure]:
    result = pool._aws_command(['ec2', 'describe-images', '--owner=self'], key='Images')

    if result.is_error:
        logger.error("failed to run aws command")
        logger.error(result.unwrap_error().message)
        return result

    images = result.unwrap()

    suitable_images = [image for image in images if image['Name'] == image_name]

    if suitable_images:
        return Ok(suitable_images[0])

    available_images = [image['Name'] for image in images]
    error = 'cannot find image {}, available images'.format(image_name)

    gluetool.log.log_dict(logger.warning, error, available_images)

    return Error(Failure('{}: {}'.format(error, available_images)))


def hook_AWS_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[AWSDriver] = None,
    environment: Optional[Environment] = None,
) -> Result[Any, Failure]:
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
            environment=environment.serialize_to_json()
        ))

    return Error(Failure(
        'failed to map environment to image',
        environment=environment.serialize_to_json()
    ))
