import dataclasses
import sqlalchemy
import threading

from prometheus_client import Counter, Gauge, CollectorRegistry, generate_latest


import gluetool.log
from gluetool.result import Result, Ok
import sqlalchemy.orm.session
import sqlalchemy.sql.schema

from . import get_db, get_logger, Failure
from . import db as artemis_db
from . import tasks as artemis_tasks
from .api.middleware import REQUEST_COUNT, REQUESTS_INPROGRESS

from typing import cast, Any, Dict, Optional, Tuple, Type

_registry_lock = threading.Lock()


def _create_pool_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
    return Gauge(
        'pool_resources_{}{}'.format(name, '_{}'.format(unit) if unit else ''),
        'Limits and usage of pool {}'.format(name),
        ['pool', 'dimension']
    )


DB_POOL_SIZE = Gauge(
    'db_pool_size',
    'Maximal number of connections available in the pool'
)
DB_POOL_CHECKED_IN = Gauge(
    'db_pool_checked_in',
    'Current number of connections checked in'
)
DB_POOL_CHECKED_OUT = Gauge(
    'db_pool_checked_out',
    'Current number of connections out'
)
DB_POOL_OVERFLOW = Gauge(
    'db_pool_overflow',
    'Current overflow of connections'
)
OVERALL_GUEST_REQUEST_COUNT_TOTAL = Counter(
    'overall_guest_request_count_total',
    'Number of overall guest requests'
)
PROVISION_OK_GUEST_REQUEST_COUNT_TOTAL = Counter(
    'success_guest_request_count_total',
    'Number of succssessfully provisioned guest requests'
)
PROVISION_FAILOVER_GUEST_REQUEST_COUNT = Counter(
    'provision_failover_guest_request_count',
    'Number of provisioned guest requests which were provisioned with failover',
    ['from_pool', 'to_pool']
)
CURRENT_GUEST_REQUEST_COUNT_TOTAL = Gauge(
    'current_guest_request_count_total',
    'Number of current guest requests'
)
CURRENT_GUEST_REQUEST_COUNT = Gauge(
    'current_guest_request_count',
    'Number of current guest requests in pool',
    ['pool', 'state']
)

POOL_RESOURCES_INSTANCES = _create_pool_resource_metric('instances')
POOL_RESOURCES_CORES = _create_pool_resource_metric('cores')
POOL_RESOURCES_MEMORY = _create_pool_resource_metric('memory', unit='bytes')
POOL_RESOURCES_DISKSPACE = _create_pool_resource_metric('diskspace', unit='bytes')
POOL_RESOURCES_SNAPSHOTS = _create_pool_resource_metric('snapshot')


def upsert_metric(
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any],
    change: int
) -> None:
    """
    Wrapper around :py:func:`tft.artemis.db.upsert` to simplify its use when it comes to metrics.

    With metrics, the situation is simpler: we expect the given table has some primary key columns,
    and one column called `count` we want to modify.
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
    Increment a metric counter in DB by 1.
    """

    upsert_metric(session, model, primary_keys, 1)


def upsert_dec_metric(
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any]
) -> None:
    """
    Decrement a metric counter in DB by 1.
    """

    upsert_metric(session, model, primary_keys, -1)


@dataclasses.dataclass
class ProvisioningMetrics:
    requested: int = 0
    success: int = 0
    failover: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)

    @staticmethod
    def inc_requested(
        session: sqlalchemy.orm.session.Session
    ) -> Result[None, Failure]:
        upsert_inc_metric(session, artemis_db.Metrics, {artemis_db.Metrics.metric: 'requested'})
        return Ok(None)

    @staticmethod
    def inc_success(
        session: sqlalchemy.orm.session.Session
    ) -> Result[None, Failure]:
        upsert_inc_metric(session, artemis_db.Metrics, {artemis_db.Metrics.metric: 'success'})
        return Ok(None)

    @staticmethod
    def inc_failover(
        session: sqlalchemy.orm.session.Session,
        from_pool: str,
        to_pool: str
    ) -> Result[None, Failure]:
        upsert_inc_metric(
            session,
            artemis_db.MetricsFailover,
            {
                artemis_db.MetricsFailover.from_pool: from_pool,
                artemis_db.MetricsFailover.to_pool: to_pool
            }
        )
        return Ok(None)


@dataclasses.dataclass
class Metrics:
    ''' Class for storing global, non pool-specific metrics '''
    current_guest_request_count_total: int = 0
    provisioning: ProvisioningMetrics = dataclasses.field(default_factory=ProvisioningMetrics)
    db_pool: artemis_db.DBPoolMetrics = artemis_db.DBPoolMetrics()


def get_global_metrics(
    logger: gluetool.log.ContextAdapter,
    db: artemis_db.DB
) -> Metrics:

    global_metrics = Metrics()

    with db.get_session() as session:
        global_metrics.current_guest_request_count_total = len(session.query(artemis_db.GuestRequest).all())
        requested = session.query(artemis_db.Metrics).get('requested')
        global_metrics.provisioning.requested = requested.count if requested else 0
        provisioned_ok = session.query(artemis_db.Metrics).get('success')
        global_metrics.provisioning.success = provisioned_ok.count if provisioned_ok else 0
        global_metrics.provisioning.failover = {
            (record.from_pool, record.to_pool): record.count
            for record in session.query(artemis_db.MetricsFailover).all()
        }

    global_metrics.db_pool = db.pool_metrics()

    return global_metrics


def generate_metrics() -> bytes:

    logger = get_logger()
    db = get_db(logger)

    with _registry_lock:
        registry = CollectorRegistry()
        registry.register(REQUEST_COUNT)
        registry.register(REQUESTS_INPROGRESS)
        registry.register(OVERALL_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(PROVISION_OK_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(PROVISION_FAILOVER_GUEST_REQUEST_COUNT)
        registry.register(CURRENT_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(CURRENT_GUEST_REQUEST_COUNT)
        registry.register(DB_POOL_SIZE)
        registry.register(DB_POOL_CHECKED_IN)
        registry.register(DB_POOL_CHECKED_OUT)
        registry.register(DB_POOL_OVERFLOW)

        # add pool-specific metrics
        with db.get_session() as session:
            pools = artemis_tasks.get_pools(logger, session)

            for pool in pools:
                pool_metrics = pool.metrics(logger, session)

                for state in pool_metrics.current_guest_request_count_per_state:
                    CURRENT_GUEST_REQUEST_COUNT.labels(pool=pool.poolname, state=state.value) \
                        .set(pool_metrics.current_guest_request_count_per_state[state])

                for metric_instance, metric_name in [
                    (POOL_RESOURCES_INSTANCES, 'instances'),
                    (POOL_RESOURCES_CORES, 'cores'),
                    (POOL_RESOURCES_MEMORY, 'memory'),
                    (POOL_RESOURCES_DISKSPACE, 'diskspace'),
                    (POOL_RESOURCES_SNAPSHOTS, 'snapshots')
                ]:
                    limit = getattr(pool_metrics.resources.limits, metric_name)
                    usage = getattr(pool_metrics.resources.usage, metric_name)

                    metric_instance \
                        .labels(pool=pool.poolname, dimension='limit') \
                        .set(limit if limit is not None else float('NaN'))

                    metric_instance \
                        .labels(pool=pool.poolname, dimension='usage') \
                        .set(usage if usage is not None else float('NaN'))

            # add all guest request count (both current and overall)
            global_metrics = get_global_metrics(logger, db)

            CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.current_guest_request_count_total)
            OVERALL_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.provisioning.requested)
            PROVISION_OK_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.provisioning.success)
            for from_pool, to_pool in global_metrics.provisioning.failover:
                PROVISION_FAILOVER_GUEST_REQUEST_COUNT \
                    .labels(from_pool=from_pool, to_pool=to_pool) \
                    .set(global_metrics.provisioning.failover[(from_pool, to_pool)])
            DB_POOL_SIZE.set(global_metrics.db_pool.size)
            DB_POOL_CHECKED_IN.set(global_metrics.db_pool.checked_in_connections)
            DB_POOL_CHECKED_OUT.set(global_metrics.db_pool.checked_out_connections)
            DB_POOL_OVERFLOW.set(global_metrics.db_pool.current_overflow)

        return cast(bytes, generate_latest())
