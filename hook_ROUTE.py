import sys

import artemis.db
import artemis.drivers
import gluetool.log

from typing import List


def hook_ROUTE(
    logger: gluetool.log.ContextAdapter = None,
    guest_request: artemis.db.GuestRequest = None,
    pools: List[artemis.drivers.PoolDriver] = None
) -> str:
    assert guest_request is not None
    assert pools is not None

    logger.warn('Available pools')
    for pool in pools:
        logger.warn('  {}'.format(pool.__class__.__name__))

    return 'baseosci-openstack'
