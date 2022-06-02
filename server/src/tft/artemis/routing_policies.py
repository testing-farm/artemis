# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import functools
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, cast

import gluetool.log
import gluetool.utils
import sqlalchemy
from gluetool.log import log_dict, log_table
from gluetool.result import Error, Ok, Result
from typing_extensions import Protocol, TypedDict

from . import Failure, SerializableContainer, partition
from .db import GuestRequest
from .drivers import PoolCapabilities, PoolDriver, PoolLogger
from .knobs import Knob
from .metrics import PoolMetrics


@dataclasses.dataclass(repr=False)
class PolicyRuling:
    """
    Container for reporting policy result.
    """

    #: List of pools allowed by this policy
    allowed_pools: List[PoolDriver] = dataclasses.field(default_factory=list)

    #: If set, routing should cancel the guest request.
    cancel: bool = False

    def __repr__(self) -> str:
        return f'<PolicyRuling: cancel={self.cancel} allowed_pools={gluetool.log.format_dict(self.allowed_pools)}>'


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


SerializedRulingHistoryItemType = TypedDict(
    'SerializedRulingHistoryItemType',
    {
        'policyname': str,
        'allowed-pools': List[str],
        'cancel': bool,
        'failure': Optional[Dict[str, Any]]
    }
)


@dataclasses.dataclass
class RulingHistoryItem(SerializableContainer):
    policyname: str
    ruling: Optional[PolicyRuling] = None
    failure: Optional[Failure] = None

    def serialize(self) -> SerializedRulingHistoryItemType:  # type: ignore[override]
        serialized: SerializedRulingHistoryItemType = {
            'policyname': self.policyname,
            'allowed-pools': [],
            'cancel': False,
            'failure': None
        }

        if self.ruling is not None:
            serialized['allowed-pools'] = [
                pool.poolname
                for pool in self.ruling.allowed_pools
            ]

            serialized['cancel'] = self.ruling.cancel

        if self.failure is not None:
            serialized['failure'] = self.failure.get_event_details()

        return serialized

    @classmethod
    def unserialize(cls, serialized: SerializedRulingHistoryItemType) -> 'RulingHistoryItem':  # type: ignore[override]
        raise NotImplementedError()


class PolicyWrapperType(Protocol):
    policy_name: str


KNOB_ROUTE_REQUEST_MAX_TIME: Knob[int] = Knob(
    'route.request.max-time',
    'A time, in seconds, after which a guest request is cancelled if provisioning haven\'t succeeded.',
    has_db=True,
    envvar='ARTEMIS_ROUTE_REQUEST_MAX_TIME',
    cast_from_str=int,
    default=6 * 3600
)

KNOB_ROUTE_POOL_FORGIVING_TIME: Knob[int] = Knob(
    'route.pool.forgiving-time',
    """
    A time, in seconds, after which a pool error during a guest provisioning is ignored and pool becomes eligible
    for said guest request again.
    """,
    has_db=True,
    envvar='ARTEMIS_ROUTE_POOL_FORGIVING_TIME',
    cast_from_str=int,
    default=10 * 60
)

KNOB_ROUTE_POOL_RESOURCE_THRESHOLD: Knob[float] = Knob(
    'route.pool.resource-threshold',
    'A percentage part of pool resource that, when reached, marks pool as depleted and not eligible for provisioning.',
    has_db=True,
    envvar='ARTEMIS_ROUTE_POOL_RESOURCE_THRESHOLD',
    cast_from_str=float,
    default=90.0
)

KNOB_ROUTE_POOL_ENABLED: Knob[bool] = Knob(
    'route.pool.enabled',
    'If unset for a pool, the given pool is ignored by the routing.',
    has_db=True,
    per_pool=True,
    envvar='ARTEMIS_ROUTE_POOL_ENABLED',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)


class PolicyLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, policy_name: str) -> None:
        super().__init__(logger, {'ctx_policy_name': (50, policy_name)})

    @property
    def policyname(self) -> str:
        return cast(str, self._contexts['policy_name'][1])


def policy_boilerplate(fn: PolicyType) -> PolicyType:
    """
    Wraps a given policy function with a common code that provides unified logging and error handling.
    """

    policy_name = fn.__name__.lower().replace('policy_', '').replace('_', '-')

    knob_enabled: Knob[bool] = Knob(
        f'route.policy.{policy_name}.enabled',
        'If disabled, routing policy is not applied when routing a guest request.',
        has_db=True,
        default=True,
        cast_from_str=gluetool.utils.normalize_bool_option
    )

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

            r_enabled = knob_enabled.get_value(session=session)

            if r_enabled.is_error:
                return Error(Failure.from_failure(
                    'failed to test policy enablement',
                    r_enabled.unwrap_error()
                ))

            if r_enabled.unwrap() is not True:
                policy_logger.debug('policy disabled, skipping')

                return Ok(PolicyRuling(allowed_pools=pools))

            r = fn(policy_logger, session, pools, guest_request)

            if r.is_error:
                return r

            policy_logger.debug(f'ruling: {r.unwrap()}')

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

    oks, errors = partition(
        lambda result_pair: result_pair[1].is_ok,
        [
            (pool, pool.capabilities())
            for pool in pools
        ]
    )

    first_error_pair = next(iter(errors), None)

    if first_error_pair:
        return Error(Failure.from_failure(
            'failed to get pool capabilities',
            first_error_pair[1].unwrap_error()
        ))

    return Ok([
        (pool, r.unwrap())
        for pool, r in oks
    ])


def collect_pool_can_acquire(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> Result[List[Tuple[PoolDriver, bool]], Failure]:
    r_answers = [
        (
            pool,
            pool.can_acquire(PoolLogger(logger, pool.poolname), session, guest_request)
        )
        for pool in pools
    ]

    errors = [(p, r) for p, r in r_answers if r.is_error]

    if errors:
        pool, result = errors[0]

        return Error(Failure.from_failure(
            'failed to get pool can-acquire answer',
            result.unwrap_error(),
            poolname=pool.poolname,
        ))

    return Ok([
        (pool, r.unwrap())
        for pool, r in r_answers
    ])


def collect_pool_metrics(pools: List[PoolDriver]) -> Result[List[Tuple[PoolDriver, PoolMetrics]], Failure]:
    pool_metrics = [
        (pool, PoolMetrics(pool.poolname))
        for pool in pools
    ]

    for _, metrics in pool_metrics:
        metrics.sync()

    return Ok(pool_metrics)


def create_preferrence_filter_by_driver_class(policy_name: str, *preferred_drivers: Type[PoolDriver]) -> PolicyType:
    # `policy_boilerplate` does some things that depend on its knowledge of the policy name. That name
    # is deduced from the policy function name, but this helper will generate policy functions with the
    # very same name, `policy`, every time for all inputs. We have to patch the `policy.__name__` with
    # the given `policy_name`, and therefore the decorator is applied *after* that patch.

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

    policy.__name__ = policy_name

    return policy_boilerplate(policy)


@policy_boilerplate
def policy_pool_enabled(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Allow only enabled pools, filter out disabled ones.
    """

    allowed_pools = []

    for pool in pools:
        r_enabled = KNOB_ROUTE_POOL_ENABLED.get_value(pool=pool, session=session)

        if r_enabled.is_error:
            return Error(r_enabled.unwrap_error())

        if r_enabled.unwrap():
            allowed_pools.append(pool)

    return Ok(PolicyRuling(allowed_pools=allowed_pools))


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

    if guest_request.environment.pool:
        return Ok(PolicyRuling(
            allowed_pools=[
                pool
                for pool in pools
                if pool.poolname == guest_request.environment.pool
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

    r_capabilities = collect_pool_capabilities(pools)

    if r_capabilities.is_error:
        return Error(r_capabilities.unwrap_error())

    pool_capabilities = r_capabilities.unwrap()

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, capabilities in pool_capabilities
            if capabilities.supports_arch(guest_request.environment.hw.arch)
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

    if guest_request.environment.snapshots is not True:
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
def policy_supports_guest_logs(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    If guest request requires specific log_types to be available, disallow all pools that lack this capability.
    """

    if not guest_request.log_types:
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
            if all(capabilities.supports_guest_log(log[0], log[1]) for log in guest_request.log_types)
        ]
    ))


@policy_boilerplate
def policy_supports_spot_instances(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    If guest request requires spot instance, disallow all pools that lack this capability.
    """

    # If request does not insist on using spot or non-spot instance, we can easily move forward and use any
    # pool we've been given.
    if guest_request.environment.spot_instance is None:
        return Ok(PolicyRuling(
            allowed_pools=pools
        ))

    r_capabilities = collect_pool_capabilities(pools)

    if r_capabilities.is_error:
        return Error(r_capabilities.unwrap_error())

    pool_capabilities = r_capabilities.unwrap()

    # Pick only pools whose spot instance support matches the request - a pool cannot support both kinds at the same
    # time.
    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, capabilities in pool_capabilities
            if capabilities.supports_spot_instances is guest_request.environment.spot_instance
        ]
    ))


@policy_boilerplate
def policy_prefer_spot_instances(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Prefer pools capable of using spot instances to satisfy the request. If there are no such pools, all given pools
    are returned - *prefer*, not *allow only*.
    """

    # If request does insist on using spot or non-spot instance, we should not mess with its request by
    # possibly removing the group it requests. For such environments, do nothing and let other policies
    # apply their magic.
    if guest_request.environment.spot_instance is not None:
        return Ok(PolicyRuling(
            allowed_pools=pools
        ))

    r_capabilities = collect_pool_capabilities(pools)

    if r_capabilities.is_error:
        return Error(r_capabilities.unwrap_error())

    preferred_pools = [
        pool
        for pool, capabilities in r_capabilities.unwrap()
        if capabilities.supports_spot_instances is True
    ]

    if not preferred_pools:
        return Ok(PolicyRuling(
            allowed_pools=pools
        ))

    return Ok(PolicyRuling(
        allowed_pools=preferred_pools
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

    r_pool_metrics = collect_pool_metrics(pools)

    if r_pool_metrics.is_error:
        return Error(r_pool_metrics.unwrap_error())

    pool_metrics = r_pool_metrics.unwrap()

    log_dict(logger.debug, 'pool metrics', pool_metrics)

    min_usage = min(metrics.current_guest_request_count for _, metrics in pool_metrics)

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, metrics in pool_metrics
            if metrics.current_guest_request_count == min_usage
        ]
    ))


@policy_boilerplate
def policy_most_free_addresses(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Pick a pool with most free network addresses.
    """

    if len(pools) <= 1:
        return Ok(PolicyRuling(allowed_pools=pools))

    r_pool_metrics = collect_pool_metrics(pools)

    if r_pool_metrics.is_error:
        return Error(r_pool_metrics.unwrap_error())

    pool_metrics = r_pool_metrics.unwrap()

    # Hold usage report - pools and resources that were checked, and the outcome of the check.
    usage_report: List[List[str]] = []

    def pool_to_free_addresses(pool: PoolDriver, metrics: PoolMetrics) -> int:
        free_addresses = 0

        for network_name, network_limit in metrics.resources.limits.networks.items():
            network_usage = metrics.resources.usage.networks.get(network_name)

            # Networks that don't report any usage are treated as having enough resources - again, pool does not care
            # about this network enough to provide data.
            if network_usage is None or network_usage.addresses is None or network_limit.addresses is None:
                network_free_addresses = 0

            else:
                network_free_addresses = network_limit.addresses - network_usage.addresses

            free_addresses += network_free_addresses

            usage_report.append([
                pool.poolname,
                'network.addresses',
                str(network_limit.addresses) if network_limit else '',
                str(network_usage.addresses) if network_usage else '',
                str(network_free_addresses)
            ])

        return free_addresses

    # Find out how many addresses each pool has...
    pool_addresses = {
        pool: pool_to_free_addresses(pool, metrics)
        for pool, metrics in pool_metrics
    }

    # ... so we could get the biggest amount...
    max_addresses = max(pool_addresses.values())

    log_table(
        logger.info,
        'pool addresses',
        [
            ['Pool', 'Metric', 'Limit', 'Usage', 'Free']
        ] + usage_report,
        headers='firstrow',
        tablefmt='psql'
    )

    # ... and allow all pools with this number of free addresses.
    return Ok(PolicyRuling(allowed_pools=[
        pool
        for pool, addresses in pool_addresses.items()
        if addresses == max_addresses
    ]))


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

    r_events = guest_request.fetch_events(session, eventname='error')

    if r_events.is_error:
        return Error(r_events.unwrap_error())

    events = r_events.unwrap()

    if not events:
        return Ok(PolicyRuling(allowed_pools=pools))

    r_time = KNOB_ROUTE_POOL_FORGIVING_TIME.get_value(session=session)

    if r_time.is_error:
        return Error(r_time.unwrap_error())

    threshold = datetime.datetime.utcnow() - datetime.timedelta(seconds=r_time.unwrap())

    error_pools = [
        event.details['failure'].get('poolname')
        for event in events
        if event.details and event.details.get('failure') and event.updated > threshold
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

    r_events = guest_request.fetch_events(session, eventname='created')

    if r_events.is_error:
        return Error(r_events.unwrap_error())

    events = r_events.unwrap()

    if not events:
        return Ok(PolicyRuling(allowed_pools=pools))

    r_time = KNOB_ROUTE_REQUEST_MAX_TIME.get_value(session=session)

    if r_time.is_error:
        return Error(r_time.unwrap_error())

    validity = events[0].updated + datetime.timedelta(seconds=r_time.unwrap())

    logger.info(f'event created {events[0].updated}, valid until {validity}')

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

    r_pool_metrics = collect_pool_metrics(pools)

    if r_pool_metrics.is_error:
        return Error(r_pool_metrics.unwrap_error())

    pool_metrics = r_pool_metrics.unwrap()

    r_threshold = KNOB_ROUTE_POOL_RESOURCE_THRESHOLD.get_value(session=session)

    if r_threshold.is_error:
        return Error(r_threshold.unwrap_error())

    threshold = r_threshold.unwrap() / 100.0

    # Hold usage report - pools and resources that were checked, and the outcome of the check.
    usage_report: List[List[str]] = []

    def has_enough(pool: PoolDriver, metrics: PoolMetrics) -> bool:
        def is_enough(metric_name: str, limit: int, usage: int) -> bool:
            # Very crude trim. We could be smarter, but this should be enough to not hit the limit.
            usage_level = usage / limit
            answer = usage_level < threshold

            usage_report.append([
                pool.poolname,
                metric_name,
                str(limit),
                str(usage),
                str(limit * threshold),
                str(answer)
            ])

            return answer

        resources_depletion = metrics.resources.get_depletion(is_enough)

        if not resources_depletion.is_depleted():
            return True

        return False

    # Here's the catch - we have to actually call `has_enough()` to get the report we want to log, can't squeeze
    # this into the final `return`.
    allowed_pools = [
        pool
        for pool, metrics in pool_metrics
        if has_enough(pool, metrics)
    ]

    log_table(
        logger.info,
        'pool resources',
        [
            ['Pool', 'Metric', 'Limit', 'Usage', 'Threshold', 'Enough?']
        ] + usage_report,
        headers='firstrow',
        tablefmt='psql'
    )

    return Ok(PolicyRuling(allowed_pools=allowed_pools))


@policy_boilerplate
def policy_can_acquire(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Disallow pools that are already know they cannot acquire the given environment.
    """

    r_answers = collect_pool_can_acquire(logger, session, pools, guest_request)

    if r_answers.is_error:
        return Error(r_answers.unwrap_error())

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool, answer in r_answers.unwrap()
            if answer is True
        ]
    ))


@policy_boilerplate
def policy_use_only_when_addressed(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pools: List[PoolDriver],
    guest_request: GuestRequest
) -> PolicyReturnType:
    """
    Disallow pools that are marked as to be used only when requested by name.
    """

    if guest_request.environment.pool is not None:
        return Ok(PolicyRuling(allowed_pools=pools))

    return Ok(PolicyRuling(
        allowed_pools=[
            pool
            for pool in pools
            if pool.use_only_when_addressed is False
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

    # Collecting all policy rulings along the way.
    history: List[RulingHistoryItem] = []

    def _serialize_history() -> List[SerializedRulingHistoryItemType]:
        return [
            history_item.serialize()
            for history_item in history
        ]

    # Just a tiny helper, to avoid repeating the parameters...
    def _log_history() -> None:
        guest_request.log_event(
            logger,
            session,
            'routing-report',
            history=_serialize_history()
        )

    ruling = PolicyRuling()
    ruling.allowed_pools = pools[:]

    for policy in policies:
        policy_name = cast(PolicyWrapperType, policy).policy_name

        r = policy(logger, session, ruling.allowed_pools, guest_request)

        RoutingMetrics.inc_policy_called(policy_name)

        if r.is_error:
            history.append(RulingHistoryItem(policyname=policy_name, failure=r.unwrap_error()))

            return Error(Failure.from_failure(
                'failed to route guest request',
                r.unwrap_error(),
                environment=guest_request.environment,
                history=_serialize_history()
            ))

        policy_ruling = r.unwrap()

        history.append(RulingHistoryItem(policyname=policy_name, ruling=policy_ruling))

        if policy_ruling.cancel:
            # Mark all input pools are excluded
            map(lambda x: RoutingMetrics.inc_pool_excluded(policy_name, x.poolname), ruling.allowed_pools)

            RoutingMetrics.inc_policy_canceled(policy_name)

            ruling.allowed_pools = []
            ruling.cancel = True

            _log_history()

            return Ok(ruling)

        # Store ruling metrics before we update ruling container with results from the policy.
        for pool in ruling.allowed_pools:
            if pool in policy_ruling.allowed_pools:
                RoutingMetrics.inc_pool_allowed(policy_name, pool.poolname)

            else:
                RoutingMetrics.inc_pool_excluded(policy_name, pool.poolname)

        # Now we can update our container with up-to-date results.
        ruling.allowed_pools = policy_ruling.allowed_pools

    _log_history()

    return Ok(ruling)
