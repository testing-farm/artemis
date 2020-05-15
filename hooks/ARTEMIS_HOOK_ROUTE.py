import random

import artemis.db
import artemis.drivers
import gluetool.log

from typing import List, Optional


def hook_ROUTE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    guest_request: Optional[artemis.db.GuestRequest] = None,
    pools: Optional[List[artemis.drivers.PoolDriver]] = None
) -> str:
    assert logger is not None
    assert guest_request is not None
    assert pools is not None

    logger.warning('Available pools')
    for pool in pools:
        logger.warning('  {}'.format(pool.__class__.__name__))

    # We don't have access to pool *names* :/
    suitable_pools = [
        'aws-testing-farm-01',
        'baseosci-openstack'
    ]

    return random.choice(suitable_pools)
