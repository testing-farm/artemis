import re

import artemis.db
import artemis.drivers.openstack
import artemis.environment
import gluetool.log

import stackprinter

from typing import Any, List, Optional


# We could use variables.yaml maybe, or openshift-image-map variant based on compose ID.
COMPOSE_TO_NAME_MAP = [
    (r'(?i)RHEL-8.2.0-.*', '1MT-RHEL-8.2.0-20200120.n.1'),
    (r'(?i)RHEL-8.1.1-.*', '1MT-RHEL-8.1.1-20200120.n.0')
]


def _map_compose_to_name(
    logger: gluetool.log.ContextAdapter,
    compose_id: str
) -> Optional[str]:
    for pattern, image_name in COMPOSE_TO_NAME_MAP:
        match = re.match(pattern, compose_id)

        if not match:
            continue

        return image_name

    logger.error('cannot map compose {} to image name'.format(compose_id))

    return None


def _image_by_name(
    logger: gluetool.log.ContextAdapter,
    pool: artemis.drivers.openstack.OpenStackDriver,
    image_name: str
) -> Optional[Any]:
    for image_data in pool._os_driver.connection.request('/images').object['images']:
        if image_data['name'] != image_name:
            continue

        return pool._os_driver.get_image(image_data['id'])

    logger.error('cannot find image {}'.format(image_name))

    return None


def hook_OPENSTACK_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[artemis.drivers.openstack.OpenStackDriver] = None,
    environment: Optional[artemis.environment.Environment] = None
) -> Optional[str]:
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

            image_name = _map_compose_to_name(logger, environment.compose.id)

        if image_name is None:
            return None

        logger.info('mapped {} to image {}'.format(environment, image_name))

        return _image_by_name(logger, pool, image_name)

    except Exception as exc:
        logger.error('crashed while mapping {} to image:\n{}'.format(environment, stackprinter.format(exc)))

    logger.error('failed to map {} to image'.format(environment))

    return None
