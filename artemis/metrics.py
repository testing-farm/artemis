import dataclasses
import threading

from prometheus_client import Gauge, CollectorRegistry, generate_latest

from molten.contrib.prometheus import REQUEST_DURATION, REQUEST_COUNT, REQUESTS_INPROGRESS

import gluetool.log

import artemis
import artemis.db
import artemis.tasks

from typing import cast

_registry_lock = threading.Lock()

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
OVERALL_GUEST_REQUEST_COUNT_TOTAL = Gauge(
    'overall_guest_request_count_total',
    'Number of overall guest requests'
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


@dataclasses.dataclass
class Metrics:
    ''' Class for storing global, non pool-specific metrics '''
    current_guest_request_count_total: int = 0
    overall_guest_request_count_total: int = 0

    db_pool: artemis.db.DBPoolMetrics = artemis.db.DBPoolMetrics()


def get_global_metrics(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB
) -> Metrics:

    global_metrics = Metrics()

    with db.get_session() as session:
        current_count = len(session.query(artemis.db.GuestRequest).all())
        overall_count = session.query(artemis.db.Metrics).get(1).count

    global_metrics.current_guest_request_count_total = current_count
    global_metrics.overall_guest_request_count_total = overall_count

    global_metrics.db_pool = db.pool_metrics()

    return global_metrics


def generate_metrics() -> bytes:

    logger = artemis.get_logger()
    db = artemis.get_db(logger)

    with _registry_lock:
        registry = CollectorRegistry()
        registry.register(REQUEST_DURATION)
        registry.register(REQUEST_COUNT)
        registry.register(REQUESTS_INPROGRESS)
        registry.register(OVERALL_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(CURRENT_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(CURRENT_GUEST_REQUEST_COUNT)
        registry.register(DB_POOL_SIZE)
        registry.register(DB_POOL_CHECKED_IN)
        registry.register(DB_POOL_CHECKED_OUT)
        registry.register(DB_POOL_OVERFLOW)

        # add pool-specific metrics
        with db.get_session() as session:
            pools = artemis.tasks.get_pools(logger, session)
            for pool in pools:
                pool_metrics = pool.metrics(logger, session)
                for state in pool_metrics.current_guest_request_count_per_state:
                    CURRENT_GUEST_REQUEST_COUNT.labels(pool.poolname, state.value) \
                        .set(pool_metrics.current_guest_request_count_per_state[state])

            # add all guest request count (both current and overall)
            global_metrics = get_global_metrics(logger, db)

            CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.current_guest_request_count_total)
            OVERALL_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.overall_guest_request_count_total)

            DB_POOL_SIZE.set(global_metrics.db_pool.size)
            DB_POOL_CHECKED_IN.set(global_metrics.db_pool.checked_in_connections)
            DB_POOL_CHECKED_OUT.set(global_metrics.db_pool.checked_out_connections)
            DB_POOL_OVERFLOW.set(global_metrics.db_pool.current_overflow)

        return cast(bytes, generate_latest())
