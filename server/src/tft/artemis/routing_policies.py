import dataclasses
import datetime
import functools
import json
from typing import Callable, List, Tuple, Type, cast

import gluetool.log
import sqlalchemy
from gluetool.log import log_dict
from gluetool.result import Error, Ok, Result
from typing_extensions import Protocol

from . import Failure, Knob
from .db import GuestRequest
from .drivers import PoolCapabilities, PoolDriver, PoolMetrics
from .environment import Environment


@dataclasses.dataclass
class PolicyRuling:
    """
    Container for reporting policy result.
    """

    #: List of pools allowed by this policy
    allowed_pools: List[PoolDriver] = dataclasses.field(default_factory=list)

    #: If set, routing should cancel the guest request.
    cancel: bool = False

    def __repr__(self) -> str:
        return '<PolicyRuling: cancel={} allowed_pools={}>'.format(
            self.cancel,
            gluetool.log.format_dict(self.allowed_pools)
        )


PolicyReturnType = Result[PolicyRuling, Failure]
PolicyType = Callable[
    [
        gluetool.log.ContextAdapter,
        sqlalchemy.orm.session.Session,
        List[PoolDriver],
        GuestRequest
    ],
    PolicyReturnType
]


class PolicyWrapperType(Protocol):
    policy_name: str


#: A time, in seconds, after which a guest request is cancelled if provisioning haven't succeeded.
KNOB_ROUTE_REQUEST_MAX_TIME: Knob[int] = Knob(
    'route.request.max-time',
    has_db=False,
    envvar='ARTEMIS_ROUTE_REQUEST_MAX_TIME',
    envvar_cast=int,
    default=6 * 3600
)

#: A time, in seconds, after which a pool error during a guest provisioning is ignored and pool becomes eligible
#: for said guest request again.
KNOB_ROUTE_POOL_FORGIVING_TIME: Knob[int] = Knob(
    'route.pool.forgiving-time',
    has_db=False,
    envvar='ARTEMIS_ROUTE_POOL_FORGIVING_TIME',
    envvar_cast=int,
    default=10 * 60
)

#: A percentage part of pool resource that, when reached, marks pool as depleted and not eligible for provisioning.
KNOB_ROUTE_POOL_RESOURCE_THRESHOLD: Knob[float] = Knob(
    'route.pool.resource-threshold',
    has_db=False,
    envvar='ARTEMIS_ROUTE_POOL_RESOURCE_THRESHOLD',
    envvar_cast=float,
    default=90.0
)


class PolicyLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, policy_name: str) -> None:
        super(PolicyLogger, self).__init__(logger, {'ctx_policy_name': (50, policy_name)})


def policy_boilerplate(fn: PolicyType) -> PolicyType:
    """
    Wraps a given policy function with a common code that provides unified logging and error handling.
    """

    policy_name = fn.__name__.lower().replace('policy_', '').replace('_', '-')

    @functools.wraps(fn)
    def wrapper(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pools: List[PoolDriver],
        guest_request: GuestRequest
    ) -> PolicyReturnType:
        try:
            policy_logger = PolicyLogger(logger, policy_name)

            log_dict(policy_logger.debug, 'input pools', pools)

            r = fn(policy_logger, session, pools, guest_request)

            if r.is_error:
                return r

            policy_logger.debug('ruling: {}'.format(r.unwrap()))

            return r

        except Exception as exc:
            return Error(Failure.from_exc(
                'routing policy crashed',
                exc,
                routing_policy=policy_name
            ))

    cast(PolicyWrapperType, wrapper).policy_name = policy_name

    return wrapper


def collect_pool_capabilities(pools: List[PoolDriver]) -> Result[List[Tuple[PoolDriver, PoolCapabilities]], Failure]:
    """
    Collect capabilities of given pools. Since pool's :py:meth:`PoolDriver.capabilities` can return a failure,
    we use this helper to simplify writing of policies by gathering capabilities, or returns the failure capturing
    the fact we failed to get capabilities of one or more pools.

    :param pools: list of pools to inspect.
    :return: List of two item tuples, pool and its capabilities.
    """

    r_capabilities = [
        (pool, pool.capabilities())
        for pool in pools
    ]

    errors = [r for _, r in r_capabilities if r.is_error]

    if errors:
        return Error(Failure(
            'failed to get pool capabilities',
            caused_by=errors[0].unwrap_error()
        ))

    return Ok([
        (pool, r.unwrap())
        for pool, r in r_capabilities
    ])


def create_preferrence_filter_by_driver_class(policy_name: str, *preferred_drivers: Type[PoolDriver]) -> PolicyType:
    @policy_boilerplate
    def policy(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pools: List[PoolDriver],
        guest_request: GuestRequest
    ) -> PolicyReturnType:
        preferred_pools: List[PoolDriver] = [
            pool
            for pool in pools
            if isinstance(pool, preferred_drivers)
        ]

        if not preferred_pools:
            return Ok(PolicyRuling(
                allowed_pools=pools
            ))

        return Ok(PolicyRuling(
            allowed_pools=preferred_pools
        ))

    cast(PolicyWrapperType, policy).policy_name = policy_name

    return policy


@policy_boilerplate
def policy_match_pool_name(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    If guest request requires a specific pool by its name, disallow any other pools.
    """

    environment = Environment.unserialize_from_json(json.loads(guest_request.environment))

    if environment.pool:
        return Ok(PolicyRuling(
            allowed_pools=[
                pool
                for pool in pools
                if pool.poolname == environment.pool
            ]
        ))

    return Ok(PolicyRuling(
        allowed_pools=pools
    ))


@policy_boilerplate
def policy_supports_architecture(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Disallow pools that don't support requested architecture.
    """

    environment = Environment.unserialize_from_json(json.loads(guest_request.environment))

    r_capabilities = collect_pool_capabilities(pools)

    if r_capabilities.is_error:
        return Error(r_capabilities.unwrap_error())

    pool_capabilities = r_capabilities.unwrap()

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, capabilities in pool_capabilities
            if capabilities.supports_arch(environment.arch)
        ]
    ))


@policy_boilerplate
def policy_supports_snapshots(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    If guest request requires snapshot support, disallow all pools that lack this capability.
    """

    environment = Environment.unserialize_from_json(json.loads(guest_request.environment))

    if environment.snapshots is not True:
        return Ok(PolicyRuling(
            allowed_pools=pools
        ))

    r_capabilities = collect_pool_capabilities(pools)

    if r_capabilities.is_error:
        return Error(r_capabilities.unwrap_error())

    pool_capabilities = r_capabilities.unwrap()

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, capabilities in pool_capabilities
            if capabilities.supports_snapshots is True
        ]
    ))


@policy_boilerplate
def policy_least_crowded(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Pick the least crowded pools, i.e. pools with the lowest absolute usage.
    """

    if len(pools) <= 1:
        return Ok(PolicyRuling(allowed_pools=pools))

    pool_metrics = [
        (pool, pool.metrics(logger, session))
        for pool in pools
    ]

    log_dict(logger.debug, 'pool metrics', pool_metrics)

    min_usage = min([metrics.current_guest_request_count for _, metrics in pool_metrics])

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, metrics in pool_metrics
            if metrics.current_guest_request_count == min_usage
        ]
    ))


@policy_boilerplate
def policy_one_attempt_forgiving(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Disallow pools that failed to provision the given guest request already, but only if such a failure happened
    in the window of last N seconds - older failures have no effect. The length of this window is controlled by
    :py:data:`KNOB_ROUTE_POOL_FORGIVING_TIME`.
    """

    events = guest_request.fetch_events(session, eventname='error')

    if not events:
        return Ok(PolicyRuling(allowed_pools=pools))

    threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_ROUTE_POOL_FORGIVING_TIME.value)

    error_pools = [
        event.details_unserialized['failure'].get('poolname')
        for event in events
        if event.details and event.details_unserialized.get('failure') and event.updated > threshold
    ]

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool in pools
            if pool.poolname not in error_pools
        ]
    ))


@policy_boilerplate
def policy_timeout_reached(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Cancel the guest request if it reached a certain age. The threshold is controlled by
    :py:data:`KNOB_ROUTE_REQUEST_MAX_TIME`.
    """

    events = guest_request.fetch_events(session, eventname='created')

    if not events:
        return Ok(PolicyRuling(allowed_pools=pools))

    validity = events[0].updated + datetime.timedelta(seconds=KNOB_ROUTE_REQUEST_MAX_TIME.value)

    logger.info('event created {}, valid until {}'.format(str(events[0].updated), str(validity)))

    if datetime.datetime.utcnow() > validity:
        return Ok(PolicyRuling(cancel=True))

    return Ok(PolicyRuling(allowed_pools=pools))


@policy_boilerplate
def policy_enough_resources(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Disallow pools that reached their resource usage quota. The usage threshold is controlled by
    :py:data:`KNOB_ROUTE_POOL_RESOURCE_THRESHOLD`.
    """

    if len(pools) <= 1:
        return Ok(PolicyRuling(allowed_pools=pools))

    pool_metrics = [
        (pool, pool.metrics(logger, session))
        for pool in pools
    ]

    log_dict(logger.info, 'pool metrics', pool_metrics)

    threshold = KNOB_ROUTE_POOL_RESOURCE_THRESHOLD.value / 100.0

    def has_enough(pool: PoolDriver, metrics: PoolMetrics) -> bool:
        def is_enough(metric_name: str, limit: int, usage: int) -> bool:
            # Very crude trim. We could be smarter, but this should be enough to not hit the limit.
            usage_level = usage / limit

            return usage_level < threshold

        resources_depletion = metrics.resources.get_depletion(is_enough)

        if not resources_depletion.is_depleted():
            return True

        for metric_name in sorted(resources_depletion.depleted_resources()):
            logger.warning('{}: "{}" depleted: {} used, {} limit'.format(
                pool.poolname,
                metric_name,
                getattr(metrics.resources.usage, metric_name),
                getattr(metrics.resources.limits, metric_name)
            ))

        return False

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, metrics in pool_metrics
            if has_enough(pool, metrics)
        ]
    ))


def run_routing_policies(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest_request: GuestRequest,
    pools: List[PoolDriver],
    policies: List[PolicyType]
) -> PolicyReturnType:
    """
    Run given list of policies on top of the given set of pools, and return the "ruling": what pools are allowed
    when it comes to provisioning the guest request.

    .. note::

       The answer may very well be "no pools are allowed". That **is** a valid result.

    :param logger: logger to use for logging.
    :param session: DB session to use for DB access.
    :param guest_request: guest request we wish to provision.
    :param pools: initial list of pools. With each policy processed, it's being reduced until the final list
        materializes.
    :param policies: list of policies to run. Policies are executed in the order they appear in this list.
    """

    # Avoiding circular imports (.metrics imports .tasks which imports .ruling_policies)
    from .metrics import RoutingMetrics

    ruling = PolicyRuling()
    ruling.allowed_pools = pools[:]

    for policy in policies:
        policy_name = cast(PolicyWrapperType, policy).policy_name

        r = policy(logger, session, ruling.allowed_pools, guest_request)

        RoutingMetrics.inc_policy_called(session, policy_name)

        if r.is_error:
            return Error(Failure(
                'failed to route guest request',
                caused_by=r.unwrap_error()
            ))

        policy_ruling = r.unwrap()

        if policy_ruling.cancel:
            # Mark all input pools are excluded
            map(lambda x: RoutingMetrics.inc_pool_excluded(session, policy_name, x.poolname), ruling.allowed_pools)

            RoutingMetrics.inc_policy_canceled(session, policy_name)

            ruling.allowed_pools = []
            ruling.cancel = True

            return Ok(ruling)

        # Store ruling metrics before we update ruling container with results from the policy.
        for pool in ruling.allowed_pools:
            if pool in policy_ruling.allowed_pools:
                RoutingMetrics.inc_pool_allowed(session, policy_name, pool.poolname)

            else:
                RoutingMetrics.inc_pool_excluded(session, policy_name, pool.poolname)

        # Now we can update our container with up-to-date results.
        ruling.allowed_pools = policy_ruling.allowed_pools

    return Ok(ruling)
