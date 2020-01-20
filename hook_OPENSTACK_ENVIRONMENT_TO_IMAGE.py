import sys

import artemis.db
import artemis.drivers
import artemis.environment
import gluetool.log

from typing import Any, List, Optional


def hook_OPENSTACK_ENVIRONMENT_TO_IMAGE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    pool: Optional[artemis.drivers.PoolDriver] = None,
    environment: Optional[artemis.environment.Environment] = None
) -> Optional[str]:
    assert logger is not None
    assert pool is not None
    assert environment is not None

    logger.info('Decided image for {}'.format(environment))

    if environment.compose.is_openstack:
        # Use specified image

        image_name = environment.compose.openstack.image

    else:
        # Convert compose to image name
        image_name = environment.compose.id

    try:
        image = pool._os_driver.get_image(image_name)

    except Exception:
        logger.error('Cannot find image for {}'.format(environment))

        return None

    return image
