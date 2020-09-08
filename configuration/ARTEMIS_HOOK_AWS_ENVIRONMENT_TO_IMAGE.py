import re

import artemis.db
import artemis.drivers.aws
import artemis.environment
from artemis import Failure

import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.utils import PatternMap

import stackprinter

from typing import Any, List, Optional


def _map_compose_to_name(logger: gluetool.log.ContextAdapter, compose_id: str) -> Result[str, Failure]:

    pattern_map = PatternMap('/configuration/artemis-image-map-aws.yaml', allow_variables=True, logger=logger)

    try:
        image_name = pattern_map.match(compose_id)

    except gluetool.GlueError:
        error = 'cannot map compose {} to image name'.format(compose_id)
        logger.error(error)

        return Error(Failure(error))

    return Ok(image_name)


def _image_by_name(
    logger: gluetool.log.ContextAdapter, pool: artemis.drivers.aws.AWSDriver, image_name: str
) -> Result[Any, Failure]:
    result = pool._aws_command(['ec2', 'describe-images', '--owner=self'], key='Images')

    if result.is_error:
        logger.error("failed to run aws command")
        logger.error(result.error.message)
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
    pool: Optional[artemis.drivers.aws.AWSDriver] = None,
    environment: Optional[artemis.environment.Environment] = None,
) -> Result[Any, Failure]:
    assert logger is not None
    assert pool is not None
    assert environment is not None

    image_name: Optional[str] = None

    try:
        logger.info('deciding image for {}'.format(environment))

        if environment.compose.is_aws:
            # Use specified image

            assert environment.compose.aws is not None

            image_name = environment.compose.aws.image

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
        error = 'crashed while mapping {} to image:\n{}'.format(environment, stackprinter.format(exc))
        logger.error(error)

    logger.error('failed to map {} to image'.format(environment))

    return Error(Failure(error))
