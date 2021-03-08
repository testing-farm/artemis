"""
Classes and functions dealing with metrics.

Our metrics are stored in the database. To transport them through our code, we use dataclasses based on
:py:class:`MetricsBase` class. These are then responsible for loading their data from the database and
conversion to Prometheus-compatible objects, and for providing easy-to-use methods to update metrics
in their area.

Our metrics are split into several sections, grouped together by the subsystem or other shared properties,
and together they form a tree of :py:class:`MetricsBase` classes, starting with :py:class:`Metrics` which
then links to :py:class:`DBMetrics` and other areas. :py:class:`MetricsBase` itself is *not* a dataclass
since it provides only methods, and therefore does not need to be declared as container - that's left
to its offsprings.
"""

import dataclasses
import datetime
import os
import platform
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union, cast

import gluetool.log
import prometheus_client.utils
import redis
import sqlalchemy
import sqlalchemy.orm.session
import sqlalchemy.sql.schema
from gluetool.result import Ok, Result
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest

from . import __VERSION__, DATABASE, SESSION, Failure
from . import db as artemis_db
from . import safe_call
from . import tasks as artemis_tasks
from . import with_context
from .api.middleware import REQUEST_COUNT, REQUESTS_INPROGRESS
from .drivers import PoolMetrics
from .guest import GuestState

# Guest age buckets are not all same, but:
#
# * first hour split into intervals of 5 minutes,
# * next 47 hours, by hour,
# * and the rest.
GUEST_AGE_BUCKETS = \
    list(range(300, 3600, 300)) \
    + list(range(3600, 49 * 3600, 3600)) \
    + [prometheus_client.utils.INF]


# Message processing time buckets, in milliseconds. Spanning from 5 milliseconds up to 900 seconds.
# Taken from the Prometheus middleware Dramatiq provides - not suited for our needs, but the bucket
# setup is not incompatible with our architecture.
MESSAGE_DURATION_BUCKETS = (
    5, 10, 25, 50, 75,
    100, 250, 500, 750,
    1000, 2500, 5000, 7500,
    10000, 30000, 60000,
    600000, 900000,
    prometheus_client.utils.INF
)


def reset_counters(metric: Union[Counter, Gauge]) -> None:
    """
    Reset each existing labeled metric to zero. After that, we can use ``inc()`` again.

    :param metric: metric whose labeled sub-metrics we need to reset.
    """

    for labeled_metric in metric._metrics.values():
        labeled_metric._value.set(0)


class MetricsBase:
    """
    Base class for all containers carrying metrics around.
    """

    def sync(self) -> None:
        """
        Load values from database and update this container with up-to-date values..

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        :raises NotImplementedError: when not implemented by a child class.
        """

        raise NotImplementedError()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        :raises NotImplementedError: when not implemented by a child class.
        """

        raise NotImplementedError()

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        :raises NotImplementedError: when not implemented by a child class.
        """

        raise NotImplementedError()


@dataclasses.dataclass
class DBPoolMetrics(MetricsBase):
    """
    Database connection pool metrics.
    """

    #: Total number of connections allowed to exist in the pool.
    size: int = 0

    #: Number of connections in the use.
    checked_in_connections: int = 0

    #: Number of idle connections.
    checked_out_connections: int = 0

    #: Maximal "overflow" of the pool, i.e. how many connections above the :py:attr:`size` are allowed.
    current_overflow: int = 0

    def sync(self) -> None:
        """
        Load values from database and update this container with up-to-date values..
        """

        db = DATABASE.get()

        if not hasattr(db.engine.pool, 'size'):
            self.size = 0
            self.checked_in_connections = 0
            self.checked_out_connections = 0
            self.current_overflow = 0

            return

        self.size = db.engine.pool.size()
        self.checked_in_connections = db.engine.pool.checkedin()
        self.checked_out_connections = db.engine.pool.checkedout()
        self.current_overflow = db.engine.pool.overflow()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self.POOL_SIZE = Gauge(
            'db_pool_size',
            'Maximal number of connections available in the pool',
            registry=registry
        )

        self.POOL_CHECKED_IN = Gauge(
            'db_pool_checked',
            'Current number of connections checked in',
            registry=registry
        )

        self.POOL_CHECKED_OUT = Gauge(
            'db_pool_checked_out',
            'Current number of connections out',
            registry=registry
        )

        self.POOL_OVERFLOW = Gauge(
            'db_pool_overflow',
            'Current overflow of connections',
            registry=registry
        )

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        self.POOL_SIZE.set(self.size)
        self.POOL_CHECKED_IN.set(self.checked_in_connections)
        self.POOL_CHECKED_OUT.set(self.checked_out_connections)
        self.POOL_OVERFLOW.set(self.current_overflow)


@dataclasses.dataclass
class DBMetrics(MetricsBase):
    """
    Database metrics.
    """

    #: Database connection pool metrics.
    pool: DBPoolMetrics = DBPoolMetrics()

    def sync(self) -> None:
        """
        Load values from database and update this container with up-to-date values..
        """

        self.pool.sync()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self.pool.register_with_prometheus(registry)

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        self.pool.update_prometheus()


@dataclasses.dataclass
class PoolsMetrics(MetricsBase):
    """
    Pool metrics.
    """

    # here is the space left for global pool-related metrics.

    metrics: Dict[str, PoolMetrics] = dataclasses.field(default_factory=dict)

    @with_context
    def sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from database and update this container with up-to-date values..

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        self.metrics = {
            pool.poolname: pool.metrics(logger, session)
            for pool in artemis_tasks.get_pools(logger, session)
        }

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        def _create_pool_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                'pool_resources_{}{}'.format(name, '_{}'.format(unit) if unit else ''),
                'Limits and usage of pool {}'.format(name),
                ['pool', 'dimension'],
                registry=registry
            )

        self.CURRENT_GUEST_REQUEST_COUNT = Gauge(
            'current_guest_request_count',
            'Current number of guest requests being provisioned by pool and state.',
            ['pool', 'state'],
            registry=registry
        )

        self.POOL_RESOURCES_INSTANCES = _create_pool_resource_metric('instances')
        self.POOL_RESOURCES_CORES = _create_pool_resource_metric('cores')
        self.POOL_RESOURCES_MEMORY = _create_pool_resource_metric('memory', unit='bytes')
        self.POOL_RESOURCES_DISKSPACE = _create_pool_resource_metric('diskspace', unit='bytes')
        self.POOL_RESOURCES_SNAPSHOTS = _create_pool_resource_metric('snapshot')

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        for poolname, pool_metrics in self.metrics.items():
            for state in pool_metrics.current_guest_request_count_per_state:
                self.CURRENT_GUEST_REQUEST_COUNT \
                    .labels(poolname, state.value) \
                    .set(pool_metrics.current_guest_request_count_per_state[state])

            for gauge, metric_name in [
                (self.POOL_RESOURCES_INSTANCES, 'instances'),
                (self.POOL_RESOURCES_CORES, 'cores'),
                (self.POOL_RESOURCES_MEMORY, 'memory'),
                (self.POOL_RESOURCES_DISKSPACE, 'diskspace'),
                (self.POOL_RESOURCES_SNAPSHOTS, 'snapshots')
            ]:
                limit = getattr(pool_metrics.resources.limits, metric_name)
                usage = getattr(pool_metrics.resources.usage, metric_name)

                gauge \
                    .labels(pool=poolname, dimension='limit') \
                    .set(limit if limit is not None else float('NaN'))

                gauge \
                    .labels(pool=poolname, dimension='usage') \
                    .set(usage if usage is not None else float('NaN'))


@dataclasses.dataclass
class ProvisioningMetrics(MetricsBase):
    """
    Provisioning metrics.
    """

    _KEY_PROVISIONING_REQUESTED = 'metrics.provisioning.requested'
    _KEY_PROVISIONING_SUCCESS = 'metrics.provisioning.success'
    _KEY_FAILOVER = 'metrics.provisioning.failover'
    _KEY_FAILOVER_SUCCESS = 'metrics.provisioning.failover.success'

    requested: int = 0
    current: int = 0
    success: Dict[str, int] = dataclasses.field(default_factory=dict)
    failover: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    failover_success: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)

    # We want to maybe point fingers on pools where guests are stuck, so include pool name and state as labels.
    guest_ages: List[Tuple[GuestState, Optional[str], datetime.timedelta]] = dataclasses.field(default_factory=list)

    @staticmethod
    @with_context
    def inc_requested(
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`requested` metric by 1.

        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(cache, ProvisioningMetrics._KEY_PROVISIONING_REQUESTED)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_success(
        pool: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`success` metric by 1.

        :param cache: cache instance to use for cache access.
        :param pool: pool that provided the instance.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, ProvisioningMetrics._KEY_PROVISIONING_SUCCESS, pool)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_failover(
        from_pool: str,
        to_pool: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase pool failover metric by 1.

        :param cache: cache instance to use for cache access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, ProvisioningMetrics._KEY_FAILOVER, '{}:{}'.format(from_pool, to_pool))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_failover_success(
        from_pool: str,
        to_pool: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase successfull pool failover meric by 1.

        :param cache: cache instance to use for cache access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, ProvisioningMetrics._KEY_FAILOVER_SUCCESS, '{}:{}'.format(from_pool, to_pool))
        return Ok(None)

    @with_context
    def sync(self, cache: redis.Redis, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from database and update this container with up-to-date values..

        :param session: DB session to use for DB access.
        :param cache: cache instance to use for cache access.
        """

        NOW = datetime.datetime.utcnow()

        current_record = session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))  # type: ignore

        self.current = current_record.scalar()
        self.requested = get_metric(cache, self._KEY_PROVISIONING_REQUESTED) or 0
        self.success = {
            poolname: count
            for poolname, count in get_metric_fields(cache, self._KEY_PROVISIONING_SUCCESS).items()
        }
        # fields are in form `from_pool:to_pool`
        self.failover = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_FAILOVER).items()
        }
        # fields are in form `from_pool:to_pool`
        self.failover_success = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_FAILOVER_SUCCESS).items()
        }
        # Using `query` directly, because we need just limited set of fields, and we need our `Query`
        # and `SafeQuery` to support this functionality (it should be just a matter of correct types).
        self.guest_ages = [
            (record[0], record[1], NOW - record[2])
            for record in cast(
                List[Tuple[GuestState, Optional[str], datetime.datetime]],
                session.query(  # type: ignore
                    artemis_db.GuestRequest.state,
                    artemis_db.GuestRequest.poolname,
                    artemis_db.GuestRequest.ctime
                ).all()
            )
        ]

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self.CURRENT_GUEST_REQUEST_COUNT_TOTAL = Gauge(
            'current_guest_request_count_total',
            'Current total number of guest requests being provisioned.',
            registry=registry
        )

        self.OVERALL_PROVISIONING_COUNT = Counter(
            'overall_provisioning_count',
            'Overall total number of all requested guest requests.',
            registry=registry
        )

        self.OVERALL_SUCCESSFULL_PROVISIONING_COUNT = Counter(
            'overall_successfull_provisioning_count',
            'Overall total number of all successfully provisioned guest requests by pool.',
            ['pool'],
            registry=registry
        )

        self.OVERALL_FAILOVER_COUNT = Counter(
            'overall_failover_count',
            'Overall total number of failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        self.OVERALL_SUCCESSFULL_FAILOVER_COUNT = Counter(
            'overall_successfull_failover_count',
            'Overall total number of successful failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        self.GUEST_AGES = Gauge(
            'guest_request_age',
            'Guest request ages by pool and state.',
            ['pool', 'state', 'age_threshold'],
            registry=registry
        )

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        self.CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(self.current)
        self.OVERALL_PROVISIONING_COUNT._value.set(self.requested)

        for pool, count in self.success.items():
            self.OVERALL_SUCCESSFULL_PROVISIONING_COUNT.labels(pool=pool)._value.set(count)

        for (from_pool, to_pool), count in self.failover.items():
            self.OVERALL_FAILOVER_COUNT.labels(from_pool=from_pool, to_pool=to_pool)._value.set(count)

        for (from_pool, to_pool), count in self.failover_success.items():
            self.OVERALL_SUCCESSFULL_FAILOVER_COUNT.labels(from_pool=from_pool, to_pool=to_pool)._value.set(count)

        reset_counters(self.GUEST_AGES)

        for state, poolname, age in self.guest_ages:
            # Pick the smallest larger bucket threshold (e.g. age == 250 => 300, age == 3599 => 3600, ...)
            # There's always the last threshold, infinity, so the list should never be empty.
            age_threshold = min([threshold for threshold in GUEST_AGE_BUCKETS if threshold > age.total_seconds()])

            self.GUEST_AGES.labels(state=state, pool=poolname, age_threshold=age_threshold).inc()


@dataclasses.dataclass
class RoutingMetrics(MetricsBase):
    """
    Routing metrics.
    """

    _KEY_CALLS = 'metrics.routing.policy.calls'
    _KEY_CANCELLATIONS = 'metrics.routing.policy.cancellations'
    _KEY_RULINGS = 'metrics.routing.policy.rulings'

    policy_calls: Dict[str, int] = dataclasses.field(default_factory=dict)
    policy_cancellations: Dict[str, int] = dataclasses.field(default_factory=dict)
    policy_rulings: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)

    @staticmethod
    @with_context
    def inc_policy_called(
        policy_name: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "policy called to make ruling" metric by 1.

        :param cache: cache instance to use for cache access.
        :param policy_name: policy that was called to make ruling.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, RoutingMetrics._KEY_CALLS, policy_name)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_policy_canceled(
        policy_name: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "policy canceled a guest request" metric by 1.

        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, RoutingMetrics._KEY_CANCELLATIONS, policy_name)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_pool_allowed(
        policy_name: str,
        pool_name: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "pool allowed by policy" metric by 1.

        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was allowed.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, RoutingMetrics._KEY_RULINGS, '{}:{}:yes'.format(policy_name, pool_name))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_pool_excluded(
        policy_name: str,
        pool_name: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "pool excluded by policy" metric by 1.

        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was excluded.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, RoutingMetrics._KEY_RULINGS, '{}:{}:no'.format(policy_name, pool_name))
        return Ok(None)

    @with_context
    def sync(self, cache: redis.Redis) -> None:
        """
        Load values from database and update this container with up-to-date values..

        :param cache: cache instance to use for cache access.
        """

        self.policy_calls = {
            field: count
            for field, count in get_metric_fields(cache, self._KEY_CALLS).items()
        }
        self.policy_cancellations = {
            field: count
            for field, count in get_metric_fields(cache, self._KEY_CANCELLATIONS).items()
        }
        # fields are in form `policy:pool:allowed`
        self.policy_rulings = {
            cast(Tuple[str, str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_RULINGS).items()
        }

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self.OVERALL_POLICY_CALLS_COUNT = Counter(
            'overall_policy_calls_count',
            'Overall total number of policy call by policy name.',
            ['policy'],
            registry=registry
        )

        self.OVERALL_POLICY_CANCELLATIONS_COUNT = Counter(
            'overall_policy_cancellations_count',
            'Overall total number of policy canceling a guest request by policy name.',
            ['policy'],
            registry=registry
        )

        self.OVERALL_POLICY_RULINGS_COUNT = Counter(
            'overall_policy_rulings_count',
            'Overall total number of policy rulings by policy name, pool name and whether the pool was allowed.',
            ['policy', 'pool', 'allowed'],
            registry=registry
        )

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        for policy_name, count in self.policy_calls.items():
            self.OVERALL_POLICY_CALLS_COUNT.labels(policy=policy_name)._value.set(count)

        for policy_name, count in self.policy_cancellations.items():
            self.OVERALL_POLICY_CANCELLATIONS_COUNT.labels(policy=policy_name)._value.set(count)

        for (policy_name, pool_name, allowed), count in self.policy_rulings.items():
            self.OVERALL_POLICY_RULINGS_COUNT \
                .labels(policy=policy_name, pool=pool_name, allowed=allowed) \
                ._value.set(count)


@dataclasses.dataclass
class TaskMetrics(MetricsBase):
    """
    Task and actor metrics.
    """

    overall_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_errored_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_retried_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_rejected_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_delayed_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    message_durations: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)

    _KEY_OVERALL_MESSAGES = 'metrics.tasks.messages.overall'
    _KEY_OVERALL_ERRORED_MESSAGES = 'metrics.tasks.messages.overall.errored'
    _KEY_OVERALL_RETRIED_MESSAGES = 'metrics.tasks.messages.overall.retried'
    _KEY_OVERALL_REJECTED_MESSAGES = 'metrics.tasks.messages.overall.rejected'
    _KEY_CURRENT_MESSAGES = 'metrics.tasks.messages.current'
    _KEY_CURRENT_DELAYED_MESSAGES = 'metrics.tasks.messages.current.delayed'
    _KEY_MESSAGE_DURATIONS = 'metrics.tasks.messages.durations'

    @staticmethod
    @with_context
    def inc_overall_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of all encountered messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_OVERALL_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_overall_errored_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of all errored messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_OVERALL_ERRORED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_overall_retried_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of all retried messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_OVERALL_RETRIED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_overall_rejected_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of all rejected messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_OVERALL_REJECTED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_current_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of messages currently being processed.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_CURRENT_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def dec_current_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Decrement number of all messages currently being processed.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        dec_metric_field(cache, TaskMetrics._KEY_CURRENT_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_current_delayed_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of delayed messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def dec_current_delayed_messages(queue: str, actor: str, cache: redis.Redis) -> Result[None, Failure]:
        """
        Decrement number of delayed messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        dec_metric_field(cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_message_durations(queue: str, actor: str, duration: int, cache: redis.Redis) -> Result[None, Failure]:
        """
        Increment number of messages in a duration bucket by one.

        The bucket is determined by the upper bound of the given ``duration``.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param duration: how long, in milliseconds, took actor to finish the task.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        bucket = min([threshold for threshold in MESSAGE_DURATION_BUCKETS if threshold > duration])

        inc_metric_field(cache, TaskMetrics._KEY_MESSAGE_DURATIONS, '{}:{}:{}'.format(queue, actor, bucket))

        return Ok(None)

    @with_context
    def sync(self, cache: redis.Redis) -> None:
        """
        Load values from database and update this container with up-to-date values..

        :param cache: cache instance to use for cache access.
        """

        # queue:actor => count
        self.overall_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_OVERALL_MESSAGES).items()
        }
        self.overall_errored_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_OVERALL_ERRORED_MESSAGES).items()
        }
        self.overall_retried_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_OVERALL_RETRIED_MESSAGES).items()
        }
        self.overall_rejected_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_OVERALL_REJECTED_MESSAGES).items()
        }
        self.current_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_CURRENT_MESSAGES).items()
        }
        self.current_delayed_message_count = {
            cast(Tuple[str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_CURRENT_DELAYED_MESSAGES).items()
        }
        # queue:actor:bucket => count
        self.message_durations = {
            cast(Tuple[str, str, str], tuple(field.split(':'))): count
            for field, count in get_metric_fields(cache, self._KEY_MESSAGE_DURATIONS).items()
        }

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self.OVERALL_MESSAGE_COUNT = Counter(
            'overall_message_count',
            'Overall total number of messages processed by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.OVERALL_ERRORED_MESSAGE_COUNT = Counter(
            'overall_errored_message_count',
            'Overall total number of errored messages by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.OVERALL_RETRIED_MESSAGE_COUNT = Counter(
            'overall_retried_message_count',
            'Overall total number of retried messages by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.OVERALL_REJECTED_MESSAGE_COUNT = Counter(
            'overall_rejected_message_count',
            'Overall total number of rejected messages by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.CURRENT_MESSAGE_COUNT = Gauge(
            'current_message_count',
            'Current number of messages being processed by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.CURRENT_DELAYED_MESSAGE_COUNT = Gauge(
            'current_delayed_message_count',
            'Current number of messages being delayed by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.MESSAGE_DURATIONS = Histogram(
            'message_duration_milliseconds',
            'The time spent processing messages by queue and actor.',
            ['queue_name', 'actor_name'],
            buckets=MESSAGE_DURATION_BUCKETS,
            registry=registry,
        )

    @with_context
    def update_prometheus(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        def _update_counter(prom_metric: Counter, source: Dict[Tuple[str, str], int]) -> None:
            reset_counters(prom_metric)

            for (queue_name, actor_name), count in source.items():
                prom_metric.labels(queue_name=queue_name, actor_name=actor_name)._value.set(count)

        _update_counter(self.OVERALL_MESSAGE_COUNT, self.overall_message_count)
        _update_counter(self.OVERALL_ERRORED_MESSAGE_COUNT, self.overall_errored_message_count)
        _update_counter(self.OVERALL_REJECTED_MESSAGE_COUNT, self.overall_rejected_message_count)
        _update_counter(self.OVERALL_RETRIED_MESSAGE_COUNT, self.overall_retried_message_count)
        _update_counter(self.CURRENT_MESSAGE_COUNT, self.current_message_count)
        _update_counter(self.CURRENT_DELAYED_MESSAGE_COUNT, self.current_delayed_message_count)

        # Reset all duration buckets and sums first
        for labeled_metric in self.MESSAGE_DURATIONS._metrics.values():
            labeled_metric._sum.set(0)

            for i, _ in enumerate(self.MESSAGE_DURATIONS._upper_bounds):
                labeled_metric._buckets[i].set(0)

        # Then, update each bucket with number of observations, and each sum with (observations * bucket threshold)
        # since we don't track the exact duration, just what bucket it falls into.
        for (queue_name, actor_name, bucket_threshold), count in self.message_durations.items():

            bucket_index = MESSAGE_DURATION_BUCKETS.index(
                prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
            )

            self.MESSAGE_DURATIONS.labels(queue_name, actor_name)._buckets[bucket_index].set(count)
            self.MESSAGE_DURATIONS.labels(queue_name, actor_name)._sum.inc(float(bucket_threshold) * count)


@dataclasses.dataclass
class Metrics(MetricsBase):
    """
    Global metrics that don't fit anywhere else, and also a root of the tree of metrics.
    """

    db: DBMetrics = DBMetrics()
    pools: PoolsMetrics = PoolsMetrics()
    provisioning: ProvisioningMetrics = ProvisioningMetrics()
    routing: RoutingMetrics = RoutingMetrics()
    tasks: TaskMetrics = TaskMetrics()

    # Registry this tree of metrics containers is tied to.
    _registry: Optional[CollectorRegistry] = None

    def sync(self) -> None:
        """
        Load values from database and update this container with up-to-date values..
        """

        self.db.sync()
        self.pools.sync()
        self.provisioning.sync()
        self.routing.sync()
        self.tasks.sync()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry..

        :param registry: Prometheus registry to attach metrics to.
        """

        self._registry = registry

        self.PACKAGE_INFO = Info(
            'artemis_package',
            'Artemis packaging info. Labels provide information about package versions.',
            registry=registry
        )

        self.IDENTITY_INFO = Info(
            'artemis_identity',
            'Artemis identity info. Labels provide information about identity aspects.',
            registry=registry
        )

        registry.register(REQUEST_COUNT)
        registry.register(REQUESTS_INPROGRESS)

        self.db.register_with_prometheus(registry)
        self.pools.register_with_prometheus(registry)
        self.provisioning.register_with_prometheus(registry)
        self.routing.register_with_prometheus(registry)
        self.tasks.register_with_prometheus(registry)

        # Since these values won't ever change, we can already set metrics and be done with it.
        self.PACKAGE_INFO.info({
            'package_version': __VERSION__,
            'image_digest': os.getenv('ARTEMIS_IMAGE_DIGEST', '<undefined>'),
            'image_url': os.getenv('ARTEMIS_IMAGE_URL', '<undefined>')
        })

        self.IDENTITY_INFO.info({
            'api_node': platform.node()
        })

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        self.db.update_prometheus()
        self.pools.update_prometheus()
        self.provisioning.update_prometheus()
        self.routing.update_prometheus()
        self.tasks.update_prometheus()

    @with_context
    def render_prometheus_metrics(self, db: artemis_db.DB) -> bytes:
        """
        Render plaintext output of Prometheus metrics representing values in this tree of metrics.

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        :param db: DB instance to use for DB access.
        :returns: plaintext represenation of Prometheus metrics, encoded as ``bytes``.
        """

        with db.get_session() as session:
            SESSION.set(session)

            self.sync()

        self.update_prometheus()

        return cast(bytes, generate_latest(registry=self._registry))


def upsert_metric(
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any],
    change: int
) -> None:
    """
    Update a stored value of a given metric.

    Wrapper for :py:func:`tft.artemis.db.upsert` to simplify its use when it comes to metrics. With metrics, we work
    with the following assumptions:

    * model (table) has one or more primary keys,
    * model has a "counter" column (called ``count``) which holds the value of the metric specified by primary keys.

    Therefore, this helper focuses on changing the counter, using primary keys to limit the change, or initialize
    the row if it doesn't exist yet.

    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. This mapping is used to limit
        the update to a particular record, or initialize new record if it doesn't exist yet.

        Primary keys - keys of the mapping - should be the columns of the given model.
    :param change: amount to add to ``count``.
    """

    # TODO: actually check if result of upsert was sucessful
    artemis_db.upsert(
        session,
        model,
        primary_keys,
        insert_data={getattr(model, 'count'): 1},
        update_data={'count': getattr(model, 'count') + change}
    )


def upsert_inc_metric(
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any]
) -> None:
    """
    Increment a metric counter by 1.

    Implemented as a thin wrapper for :py:func:`upsert_metric`, therefore the parameters share their meaning.

    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. See :py:func:`upsert_metric`
        for more details.
    """

    upsert_metric(session, model, primary_keys, 1)


def upsert_dec_metric(
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any]
) -> None:
    """
    Decrement a metric counter by 1.

    Implemented as a thin wrapper for :py:func:`upsert_metric`, therefore the parameters share their meaning.

    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. See :py:func:`upsert_metric`
        for more details.
    """

    upsert_metric(session, model, primary_keys, -1)


def inc_metric(
    cache: redis.Redis,
    metric: str
) -> None:
    """
    Increment a metric counter by 1. If metric does not exist yet, it is set to `0` and incremented.

    :param cache: cache instance to use for cache access.
    :param metric: metric to increment.
    """

    safe_call(cast(Callable[[str], None], cache.incr), metric)


def dec_metric(
    cache: redis.Redis,
    metric: str
) -> None:
    """
    Decrement a metric counter by 1. If metric does not exist yet, it is set to `0` and decremented.

    :param cache: cache instance to use for cache access.
    :param metric: metric to decrement.
    """

    safe_call(cast(Callable[[str], None], cache.decr), metric)


def inc_metric_field(
    cache: redis.Redis,
    metric: str,
    field: str
) -> None:
    """
    Increment a metric field counter by 1. If metric field does not exist yet, it is set to `0` and incremented.

    :param cache: cache instance to use for cache access.
    :param metric: parent metric to access.
    :param field: field to increment.
    """

    safe_call(cast(Callable[[str, str, int], None], cache.hincrby), metric, field, 1)


def dec_metric_field(
    cache: redis.Redis,
    metric: str,
    field: str
) -> None:
    """
    Decrement a metric field counter by 1. If metric field does not exist yet, it is set to `0` and decremented.

    :param cache: cache instance to use for cache access.
    :param metric: parent metric to access.
    :param field: field to decrement.
    """

    safe_call(cast(Callable[[str, str, int], None], cache.hincrby), metric, field, -1)


def get_metric(
    cache: redis.Redis,
    metric: str
) -> Optional[int]:
    """
    Return a metric counter for the given metric.

    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :returns: value of the metric.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `get` with `cast` calls.

    value = cast(
        Callable[[str], Optional[bytes]],
        cache.get
    )(metric)

    return value if value is None else int(value)


def set_metric(
    cache: redis.Redis,
    metric: str,
    value: Optional[int] = None
) -> None:
    """
    Set a metric counter for the given metric.

    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :param value: value to set to.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `get` with `cast` calls.

    if value is None:
        safe_call(cast(Callable[[str], None], cache.delete), metric)

    else:
        safe_call(cast(Callable[[str, int], None], cache.set), metric, value)


def get_metric_fields(
    cache: redis.Redis,
    metric: str
) -> Dict[str, int]:
    """
    Return a mapping between fields and corresponding counters representing the given metric.

    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :returns: mapping between field and counters.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `hgetall` with `cast` calls.

    values = cast(
        Callable[[str], Optional[Dict[bytes, bytes]]],
        cache.hgetall
    )(metric)

    if values is None:
        return {}

    return {
        field.decode(): int(count)
        for field, count in values.items()
    }
