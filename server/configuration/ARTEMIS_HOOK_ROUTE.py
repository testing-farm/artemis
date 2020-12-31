"""
Routing script, for picking suitable pools for a given guest request. It is called by Artemis every time it needs to
decide which pool to ask for the actual provisioning.

This script is supposed to be tailored according to the deployment needs: add, remove or change order of policies,
but you probably won't need to touch :py:func:`hook_ROUTE` - it's pretty generic, and simply runs what's in
:py:data:`POLICIES`. Change that list rather than the code, since the decisions should happen in policies.
"""

from tft.artemis import Failure
from tft.artemis.drivers import PoolDriver
from tft.artemis.db import GuestRequest
from tft.artemis.routing_policies import policy_boilerplate, PolicyRuling, PolicyReturnType
from tft.artemis.routing_policies import policy_match_pool_name, policy_least_crowded, policy_one_attempt_forgiving, \
    policy_timeout_reached, policy_enough_resources, policy_supports_snapshots, run_routing_policies

import gluetool.log
from gluetool.result import Error, Ok, Result
import sqlalchemy

from typing import List, Optional


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
    logger: Optional[gluetool.log.ContextAdapter] = None,
    session: Optional[sqlalchemy.orm.session.Session] = None,
    guest_request: Optional[GuestRequest] = None,
    pools: Optional[List[PoolDriver]] = None,
) -> Result[Optional[PoolDriver], Failure]:

    assert logger is not None
    assert session is not None
    assert guest_request is not None
    assert pools is not None

    r = run_routing_policies(logger, session, guest_request, pools, POLICIES)

    if r.is_error:
        return Error(r.unwrap_error())

    ruling = r.unwrap()

    if ruling.cancel:
        # TODO: This was NOT handled correctly in the previous version: routing script returns Error, which leads
        # to task rescheduling, hitting the same timeout ruling once again.
        #
        # We should use PolicyRuling as the script's return value, that would help us explain more details
        # about the result.
        return Ok(None)

        # return Error(Failure(
        #     'Routing is taking more then {} hours, cannot continue'.format(KNOB_ROUTE_REQUEST_MAX_TIME)
        # ))

    # If no suitable pools found
    if not ruling.allowed_pools:
        return Ok(None)

    # At this point, all pools are equally worthy: we may very well return any of them.
    return Ok(ruling.allowed_pools[0])
