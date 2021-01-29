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
from typing import Any, Dict, List, Optional, Tuple, Type, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session
import sqlalchemy.sql.schema
from gluetool.result import Ok, Result
from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest
import prometheus_client.utils

from . import Failure
from . import db as artemis_db
from . import tasks as artemis_tasks
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


class MetricsBase:
    """
    Base class for all containers carrying metrics around.
    """

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'MetricsBase':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :raises NotImplementedError: when not implemented by a child class.
        """

        raise NotImplementedError()

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        :raises NotImplementedError: when not implemented by a child class.
        """

        raise NotImplementedError()


@dataclasses.dataclass
class DBPoolMetrics(MetricsBase):
    """
    Database connection pool metrics.
    """

    #: Total number of connections allowed to exist in the pool.
    size: int

    #: Number of connections in the use.
    checked_in_connections: int

    #: Number of idle connections.
    checked_out_connections: int

    #: Maximal "overflow" of the pool, i.e. how many connections above the :py:attr:`size` are allowed.
    current_overflow: int

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'DBPoolMetrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        if not hasattr(db.engine.pool, 'size'):
            return DBPoolMetrics(
                size=-1,
                checked_in_connections=-1,
                checked_out_connections=-1,
                current_overflow=-1
            )

        return DBPoolMetrics(
            size=db.engine.pool.size(),
            checked_in_connections=db.engine.pool.checkedin(),
            checked_out_connections=db.engine.pool.checkedout(),
            current_overflow=db.engine.pool.overflow()
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        pool_size = Gauge(
            'db_pool_size',
            'Maximal number of connections available in the pool',
            registry=registry
        )

        pool_checked_in = Gauge(
            'db_pool_checked_in',
            'Current number of connections checked in',
            registry=registry
        )

        pool_checked_out = Gauge(
            'db_pool_checked_out',
            'Current number of connections out',
            registry=registry
        )

        pool_overflow = Gauge(
            'db_pool_overflow',
            'Current overflow of connections',
            registry=registry
        )

        pool_size.set(self.size)
        pool_checked_in.set(self.checked_in_connections)
        pool_checked_out.set(self.checked_out_connections)
        pool_overflow.set(self.current_overflow)


@dataclasses.dataclass
class DBMetrics(MetricsBase):
    """
    Database metrics.
    """

    #: Database connection pool metrics.
    pool: DBPoolMetrics

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'DBMetrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        return DBMetrics(
            pool=DBPoolMetrics.load(logger, db, session)
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        self.pool.to_prometheus(registry)


@dataclasses.dataclass
class PoolsMetrics(MetricsBase):
    """
    Pool metrics.
    """

    # here is the space left for global pool-related metrics.

    metrics: Dict[str, PoolMetrics]

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'PoolsMetrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        return PoolsMetrics(
            metrics={
                pool.poolname: pool.metrics(logger, session)
                for pool in artemis_tasks.get_pools(logger, session)
            }
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        def _create_pool_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                'pool_resources_{}{}'.format(name, '_{}'.format(unit) if unit else ''),
                'Limits and usage of pool {}'.format(name),
                ['pool', 'dimension'],
                registry=registry
            )

        current_guest_request_count = Gauge(
            'current_guest_request_count',
            'Current number of guest requests being provisioned by pool and state.',
            ['pool', 'state'],
            registry=registry
        )

        pool_resources_instances = _create_pool_resource_metric('instances')
        pool_resources_cores = _create_pool_resource_metric('cores')
        pool_resources_memory = _create_pool_resource_metric('memory', unit='bytes')
        pool_resources_diskspace = _create_pool_resource_metric('diskspace', unit='bytes')
        pool_resources_snapshots = _create_pool_resource_metric('snapshot')

        for poolname, pool_metrics in self.metrics.items():
            for state in pool_metrics.current_guest_request_count_per_state:
                current_guest_request_count \
                    .labels(poolname, state.value) \
                    .set(pool_metrics.current_guest_request_count_per_state[state])

            for gauge, metric_name in [
                (pool_resources_instances, 'instances'),
                (pool_resources_cores, 'cores'),
                (pool_resources_memory, 'memory'),
                (pool_resources_diskspace, 'diskspace'),
                (pool_resources_snapshots, 'snapshots')
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

    requested: int
    current: int
    success: Dict[str, int]
    failover: Dict[Tuple[str, str], int]
    failover_success: Dict[Tuple[str, str], int]

    # We want to maybe point fingers on pools where guests are stuck, so include pool name and state as labels.
    guest_ages: List[Tuple[GuestState, Optional[str], datetime.timedelta]]

    @staticmethod
    def inc_requested(
        session: sqlalchemy.orm.session.Session
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`requested` metric by 1.

        :param session: DB session to use for DB access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(session, artemis_db.Metrics, {artemis_db.Metrics.metric: 'requested'})
        return Ok(None)

    @staticmethod
    def inc_success(
        session: sqlalchemy.orm.session.Session,
        pool: str
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`success` metric by 1.

        :param session: DB session to use for DB access.
        :param pool: pool that provided the instance.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsProvisioningSuccess,
            {
                artemis_db.MetricsProvisioningSuccess.pool: pool
            }
        )

        return Ok(None)

    @staticmethod
    def inc_failover(
        session: sqlalchemy.orm.session.Session,
        from_pool: str,
        to_pool: str
    ) -> Result[None, Failure]:
        """
        Increase pool failover metric by 1.

        :param session: DB session to use for DB access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsFailover,
            {
                artemis_db.MetricsFailover.from_pool: from_pool,
                artemis_db.MetricsFailover.to_pool: to_pool
            }
        )
        return Ok(None)

    @staticmethod
    def inc_failover_success(
        session: sqlalchemy.orm.session.Session,
        from_pool: str,
        to_pool: str
    ) -> Result[None, Failure]:
        """
        Increase successfull pool failover meric by 1.

        :param session: DB session to use for DB access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsFailoverSuccess,
            {
                artemis_db.MetricsFailoverSuccess.from_pool: from_pool,
                artemis_db.MetricsFailoverSuccess.to_pool: to_pool
            }
        )
        return Ok(None)

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'ProvisioningMetrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        NOW = datetime.datetime.utcnow()

        current_record = session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))  # type: ignore

        requested_record = artemis_db.Query \
            .from_session(session, artemis_db.Metrics) \
            .filter(artemis_db.Metrics.metric == 'requested') \
            .one_or_none()

        return ProvisioningMetrics(
            current=current_record.scalar(),
            requested=requested_record.count if requested_record else 0,
            success={
                record.pool: record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsProvisioningSuccess).all()
            },
            failover={
                (record.from_pool, record.to_pool): record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsFailover).all()
            },
            failover_success={
                (record.from_pool, record.to_pool): record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsFailoverSuccess).all()
            },
            # Using `query` directly, because we need just limited set of fields, and we need our `Query`
            # and `SafeQuery` to support this functionality (it should be just a matter of correct types).
            guest_ages=[
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
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        current_guest_request_count_total = Gauge(
            'current_guest_request_count_total',
            'Current total number of guest requests being provisioned.',
            registry=registry
        )

        overall_provisioning_count = Counter(
            'overall_provisioning_count',
            'Overall total number of all requested guest requests.',
            registry=registry
        )

        overall_successfull_provisioning_count = Counter(
            'overall_successfull_provisioning_count',
            'Overall total number of all successfully provisioned guest requests by pool.',
            ['pool'],
            registry=registry
        )

        overall_failover_count = Counter(
            'overall_failover_count',
            'Overall total number of failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        overall_successfull_failover_count = Counter(
            'overall_successfull_failover_count',
            'Overall total number of successful failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        guest_ages = Gauge(
            'guest_request_age',
            'Guest request ages by pool and state.',
            ['pool', 'state', 'age_threshold'],
            registry=registry
        )

        current_guest_request_count_total.set(self.current)
        overall_provisioning_count.inc(amount=self.requested)

        for pool, count in self.success.items():
            overall_successfull_provisioning_count.labels(pool=pool).inc(amount=count)

        for (from_pool, to_pool), count in self.failover.items():
            overall_failover_count.labels(from_pool=from_pool, to_pool=to_pool).inc(amount=count)

        for (from_pool, to_pool), count in self.failover_success.items():
            overall_successfull_failover_count.labels(from_pool=from_pool, to_pool=to_pool).inc(amount=count)

        for state, poolname, age in self.guest_ages:
            # Pick the smallest larger bucket threshold (e.g. age == 250 => 300, age == 3599 => 3600, ...)
            # There's always the last threshold, infinity, so the list should never be empty.
            age_threshold = min([threshold for threshold in GUEST_AGE_BUCKETS if threshold > age.total_seconds()])

            guest_ages.labels(state=state, pool=poolname, age_threshold=age_threshold).inc()


@dataclasses.dataclass
class RoutingMetrics(MetricsBase):
    """
    Routing metrics.
    """

    policy_calls: Dict[str, int]
    policy_cancellations: Dict[str, int]
    policy_rulings: Dict[Tuple[str, str, bool], int]

    @staticmethod
    def inc_policy_called(
        session: sqlalchemy.orm.session.Session,
        policy_name: str
    ) -> Result[None, Failure]:
        """
        Increase "policy called to make ruling" metric by 1.

        :param session: DB session to use for DB access.
        :param policy_name: policy that was called to make ruling.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsPolicyCalls,
            {
                artemis_db.MetricsPolicyCalls.policy_name: policy_name
            }
        )
        return Ok(None)

    @staticmethod
    def inc_policy_canceled(
        session: sqlalchemy.orm.session.Session,
        policy_name: str
    ) -> Result[None, Failure]:
        """
        Increase "policy canceled a guest request" metric by 1.

        :param session: DB session to use for DB access.
        :param policy_name: policy that made the decision.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsPolicyCancellations,
            {
                artemis_db.MetricsPolicyCancellations.policy_name: policy_name
            }
        )
        return Ok(None)

    @staticmethod
    def inc_pool_allowed(
        session: sqlalchemy.orm.session.Session,
        policy_name: str,
        pool_name: str
    ) -> Result[None, Failure]:
        """
        Increase "pool allowed by policy" metric by 1.

        :param session: DB session to use for DB access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was allowed.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsPolicyRulings,
            {
                artemis_db.MetricsPolicyRulings.policy_name: policy_name,
                artemis_db.MetricsPolicyRulings.pool_name: pool_name,
                artemis_db.MetricsPolicyRulings.allowed: True
            }
        )
        return Ok(None)

    @staticmethod
    def inc_pool_excluded(
        session: sqlalchemy.orm.session.Session,
        policy_name: str,
        pool_name: str
    ) -> Result[None, Failure]:
        """
        Increase "pool excluded by policy" metric by 1.

        :param session: DB session to use for DB access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was excluded.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        upsert_inc_metric(
            session,
            artemis_db.MetricsPolicyRulings,
            {
                artemis_db.MetricsPolicyRulings.policy_name: policy_name,
                artemis_db.MetricsPolicyRulings.pool_name: pool_name,
                artemis_db.MetricsPolicyRulings.allowed: False
            }
        )
        return Ok(None)

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'RoutingMetrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        return RoutingMetrics(
            policy_calls={
                record.policy_name: record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsPolicyCalls).all()
            },
            policy_cancellations={
                record.policy_name: record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsPolicyCancellations).all()
            },
            policy_rulings={
                (record.policy_name, record.pool_name, record.allowed): record.count
                for record in artemis_db.Query.from_session(session, artemis_db.MetricsPolicyRulings).all()
            }
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        overall_policy_calls_count = Counter(
            'overall_policy_calls_count',
            'Overall total number of policy call by policy name.',
            ['policy'],
            registry=registry
        )

        overall_policy_cancellations_count = Counter(
            'overall_policy_cancellations_count',
            'Overall total number of policy canceling a guest request by policy name.',
            ['policy'],
            registry=registry
        )

        overall_policy_rulings_count = Counter(
            'overall_policy_rulings_count',
            'Overall total number of policy rulings by policy name, pool name and whether the pool was allowed.',
            ['policy', 'pool', 'allowed'],
            registry=registry
        )

        for policy_name, count in self.policy_calls.items():
            overall_policy_calls_count.labels(policy=policy_name).inc(amount=count)

        for policy_name, count in self.policy_cancellations.items():
            overall_policy_cancellations_count.labels(policy=policy_name).inc(amount=count)

        for (policy_name, pool_name, allowed), count in self.policy_rulings.items():
            overall_policy_rulings_count \
                .labels(policy=policy_name, pool=pool_name, allowed='yes' if allowed else 'no') \
                .inc(amount=count)


@dataclasses.dataclass
class Metrics(MetricsBase):
    """
    Global metrics that don't fit anywhere else, and also a root of the tree of metrics.
    """

    db: DBMetrics
    pools: PoolsMetrics
    provisioning: ProvisioningMetrics
    routing: RoutingMetrics

    @classmethod
    def load(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
        session: sqlalchemy.orm.session.Session
    ) -> 'Metrics':
        """
        Load values from database, and return the container instance.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: a metrics container instance.
        """

        return Metrics(
            db=DBMetrics.load(logger, db, session),
            pools=PoolsMetrics.load(logger, db, session),
            provisioning=ProvisioningMetrics.load(logger, db, session),
            routing=RoutingMetrics.load(logger, db, session)
        )

    def to_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Transform values in the container into Prometheus metric instances, and attach them to the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        self.db.to_prometheus(registry)
        self.pools.to_prometheus(registry)
        self.provisioning.to_prometheus(registry)
        self.routing.to_prometheus(registry)

    @classmethod
    def render_prometheus_metrics(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB,
    ) -> bytes:
        """
        Render plaintext output of Prometheus metrics representing values in this tree of metrics.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :returns: plaintext represenation of Prometheus metrics, encoded as ``bytes``.
        """

        registry = CollectorRegistry()
        registry.register(REQUEST_COUNT)
        registry.register(REQUESTS_INPROGRESS)

        with db.get_session() as session:
            metrics = Metrics.load(logger, db, session)

        metrics.to_prometheus(registry)

        return cast(bytes, generate_latest(registry=registry))


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
