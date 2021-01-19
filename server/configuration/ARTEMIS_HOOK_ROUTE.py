"""
Routing script, for picking suitable pools for a given guest request. It is called by Artemis every time it needs to
decide which pool to ask for the actual provisioning.

This script is supposed to be tailored according to the deployment needs: add, remove or change order of policies,
but you probably won't need to touch :py:func:`hook_ROUTE` - it's pretty generic, and simply runs what's in
:py:data:`POLICIES`. Change that list rather than the code, since the decisions should happen in policies.
"""

from tft.artemis.drivers import PoolDriver
from tft.artemis.db import GuestRequest
from tft.artemis.routing_policies import policy_boilerplate, PolicyRuling, PolicyReturnType
from tft.artemis.routing_policies import policy_match_pool_name, policy_least_crowded, policy_one_attempt_forgiving, \
    policy_timeout_reached, policy_enough_resources, policy_supports_snapshots, run_routing_policies

import gluetool.log
from gluetool.result import Ok
import sqlalchemy

from typing import List


@policy_boilerplate
def policy_prefer_openstack(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    If there are OpenStack pools still in the mix, then prefer these pools over the rest. If there are no OpenStack
    pools allowed anymore, return the original list: *prefer*, not *use only*.
    """

    openstack_pools = [
        pool
        for pool in pools
        if pool.__class__.__name__ == 'OpenStackDriver'
    ]

    if not openstack_pools:
        return Ok(PolicyRuling(
            allowed_pools=pools
        ))

    return Ok(PolicyRuling(
        allowed_pools=openstack_pools
    ))


POLICIES = [
    policy_timeout_reached,
    policy_match_pool_name,
    policy_supports_snapshots,
    policy_one_attempt_forgiving,
    policy_enough_resources,
    policy_prefer_openstack,
    policy_least_crowded
]


def hook_ROUTE(
    *,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest_request: GuestRequest,
    pools: List[PoolDriver]
) -> PolicyReturnType:
    return run_routing_policies(logger, session, guest_request, pools, POLICIES)
