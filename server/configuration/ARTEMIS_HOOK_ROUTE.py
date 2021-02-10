"""
Routing script, for picking suitable pools for a given guest request. It is called by Artemis every time it needs to
decide which pool to ask for the actual provisioning.

This script is supposed to be tailored according to the deployment needs: add, remove or change order of policies,
but you probably won't need to touch :py:func:`hook_ROUTE` - it's pretty generic, and simply runs what's in
:py:data:`POLICIES`. Change that list rather than the code, since the decisions should happen in policies.
"""

from tft.artemis.drivers import PoolDriver
from tft.artemis.db import GuestRequest
from tft.artemis.routing_policies import PolicyReturnType
from tft.artemis.routing_policies import policy_match_pool_name, policy_least_crowded, policy_one_attempt_forgiving, \
    policy_timeout_reached, policy_enough_resources, policy_supports_snapshots, run_routing_policies, \
    policy_supports_architecture, create_preferrence_filter_by_driver_class

import tft.artemis.drivers.azure
import tft.artemis.drivers.aws
import tft.artemis.drivers.openstack

import gluetool.log
import sqlalchemy

from typing import List


#: If there are OpenStack pools still in the mix, then prefer these pools over the rest. If there are no OpenStack
#: pools allowed anymore, return the original list: *prefer*, not *use only*.
policy_prefer_openstack = create_preferrence_filter_by_driver_class(
    'prefer-openstack',
    tft.artemis.drivers.openstack.OpenStackDriver
)


#: If there are cloud-backed pools still in the mix, then prefer these pools over more expensive pools (like Beaker).
#: If there are no cloud-backed pools available anymore, return the original list: *prefer*, not *use only*.
policy_prefer_clouds = create_preferrence_filter_by_driver_class(
    'prefer-clouds',
    tft.artemis.drivers.aws.AWSDriver,
    tft.artemis.drivers.azure.AzureDriver,
    tft.artemis.drivers.openstack.OpenStackDriver
)


POLICIES = [
    policy_timeout_reached,
    policy_match_pool_name,
    policy_supports_architecture,
    policy_supports_snapshots,
    policy_one_attempt_forgiving,
    policy_enough_resources,
    policy_prefer_clouds,
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
