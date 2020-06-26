"""
Route request to suitable pools. Maximum request time is MAXIMUM_REQUEST_TIME hours.

When choosing the pools, following policies are followed:

1. Pools which errored in the given threshold ERROR_FORGIVING_THRESHOLD in minutes are ignored

2. Openstack pools are preferred

3. Least crowded pool (i.e. pool with lowest number of requests on this instance) is returned.
"""

import datetime
import json

import artemis.db
import artemis.drivers
import artemis.environment
from artemis import Failure
from artemis.api import GuestEventManager, GuestEvent

import gluetool.log
from gluetool.result import Error, Ok, Result

from typing import List, Optional

# Number of seconds an error from pool is accountable, errors which happened later are ignored
ERROR_FORGIVING_THRESHOLD = 10 * 60

# Maximum request time in seconds
MAXIMUM_REQUEST_TIME = 6 * 3600


# Prefer Openstack pools, if available
def _policy_prefer_openstack(
    logger: gluetool.log.ContextAdapter,
    pools: List[artemis.drivers.PoolDriver]
) -> List[artemis.drivers.PoolDriver]:
    openstack_pools = [pool for pool in pools if pool.__class__.__name__ == 'OpenStackDriver']

    if not openstack_pools:
        return pools

    gluetool.log.log_dict(logger.info, 'policy openstack - pools', openstack_pools)

    return openstack_pools


# Returns least crowded pools, i.e. pools which are used the least on this Artemis instance
def _policy_least_crowded(
    logger: gluetool.log.ContextAdapter,
    pools: List[artemis.drivers.PoolDriver]
) -> List[artemis.drivers.PoolDriver]:

    # only one pool
    if len(pools) <= 1:
        return pools

    # get session
    db = artemis.get_db(artemis.get_logger())

    # check pool metrics
    pool_metrics = [
        (pool, pool.metrics(logger, db.get_session())) for pool in pools
    ]

    gluetool.log.log_dict(logger.info, 'policy least crowded - pools metrics', pool_metrics)

    min_usage = min([metrics.current_guest_request_count_per_state for _, metrics in pool_metrics])

    suitable_pools = [
        pool for pool, metrics in pool_metrics
        if metrics.current_guest_request_count_per_state == min_usage
    ]

    gluetool.log.log_dict(logger.info, 'policy least crowded - chosen pools', suitable_pools)

    return suitable_pools


# Get request events
def _get_request_events(
    guest_request: artemis.db.GuestRequest,
) -> List[GuestEvent]:

    # Get list of pools we already tried and ended-up in error state, but ignore old errors
    db = artemis.get_db(artemis.get_logger())
    event_manager = GuestEventManager(db)
    events = event_manager.get_events_by_guestname(guest_request.guestname)

    assert events

    return events


# Ignored errored pools which happened in the given ERROR_THRESHOLD
def _policy_one_attempt_forgiving(
    logger: gluetool.log.ContextAdapter,
    events: List[GuestEvent],
    pools: List[artemis.drivers.PoolDriver]
) -> List[artemis.drivers.PoolDriver]:

    threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=ERROR_FORGIVING_THRESHOLD)

    error_pools = [
        event.details.get('poolname')
        for event in events
        if event.details and event.eventname == 'error' and event.updated > threshold
    ]

    gluetool.log.log_dict(logger.info, 'pools which ended in error from {}'.format(threshold), error_pools)

    return [
        pool for pool in pools if pool.poolname not in error_pools
    ]


# Returns true if request timeout was reached
def _policy_timeout_reached(
    logger: gluetool.log.ContextAdapter,
    events: List[GuestEvent],
) -> bool:

    validity = events[0].updated + datetime.timedelta(seconds=MAXIMUM_REQUEST_TIME)

    logger.info('event created {}, valid until {}'.format(str(events[0].updated), str(validity)))

    if datetime.datetime.utcnow() > validity:
        return True

    return False


def hook_ROUTE(
    logger: Optional[gluetool.log.ContextAdapter] = None,
    guest_request: Optional[artemis.db.GuestRequest] = None,
    pools: Optional[List[artemis.drivers.PoolDriver]] = None
) -> Result[Optional[artemis.drivers.PoolDriver], Failure]:

    assert logger is not None
    assert guest_request is not None
    assert pools is not None

    # Get all events for the request
    events = _get_request_events(guest_request)

    # Check if request timeout reached
    if _policy_timeout_reached(logger, events):
        return Error(Failure('Routing is taking more then {} hours, cannot continue'.format(MAXIMUM_REQUEST_TIME)))

    # Show all available pools
    gluetool.log.log_dict(
        logger.info,
        'available pools',
        [pool.poolname for pool in pools]
    )

    suitable_pools = pools

    # If user defined desired pool driver explicitly, we want to choose only from pools for this specific driver.
    env_as_dict = json.loads(guest_request.environment)
    env = artemis.environment.Environment.unserialize_from_json(env_as_dict)

    if env.compose.is_aws:
        suitable_pools = [pool for pool in pools if pool.__class__.__name__ == 'AWSDriver']

    elif env.compose.is_openstack:
        suitable_pools = [pool for pool in pools if pool.__class__.__name__ == 'OpenStackDriver']

    # NOTE: beaker should be added here later, if Artemis will properly support it

    elif env.snapshots:
        suitable_pools = [pool for pool in pools if pool.pool_config.get('snapshots')]

    gluetool.log.log_dict(logger.info, 'suitable pools', [pool.poolname for pool in suitable_pools])

    # Filter pools which did not yet fail for the request
    suitable_pools = _policy_one_attempt_forgiving(logger, events, suitable_pools)

    # Prefer Openstack pools
    suitable_pools = _policy_prefer_openstack(logger, suitable_pools)

    # If no suitable pools found
    if not suitable_pools:
        return Ok(None)

    # Return least crowded suitable pool
    return Ok(_policy_least_crowded(logger, suitable_pools)[0])
