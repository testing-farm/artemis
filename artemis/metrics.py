import dataclasses
import threading

from prometheus_client import Gauge, CollectorRegistry, generate_latest

from molten.contrib.prometheus import REQUEST_DURATION, REQUEST_COUNT, REQUESTS_INPROGRESS

import gluetool.log

import artemis
import artemis.tasks

from typing import cast

_registry_lock = threading.Lock()

OPEN_DB_CONNECTIONS_COUNT_TOTAL = Gauge('open_db_connections_count_total',
                                        'Number of open database connections')
OVERALL_GUEST_REQUEST_COUNT_TOTAL = Gauge('overall_guest_request_count_total',
                                          'Number of overall guest requests')
CURRENT_GUEST_REQUEST_COUNT_TOTAL = Gauge('current_guest_request_count_total',
                                          'Number of current guest requests')
CURRENT_GUEST_REQUEST_COUNT = Gauge('current_guest_request_count',
                                    'Number of current guest requests in pool',
                                    ['pool', 'state'])


@dataclasses.dataclass
class Metrics:
    ''' Class for storing global, non pool-specific metrics '''
    open_db_connections_count_total: int = 0
    current_guest_request_count_total: int = 0
    overall_guest_request_count_total: int = 0


def get_global_metrics(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB
) -> Metrics:

    global_metrics = Metrics()

    with db.get_session() as session:
        connections = db._engine.execute('select count(*) from pg_stat_activity')
        current_count = len(session.query(artemis.db.GuestRequest).all())
        overall_count = session.query(artemis.db.Metrics).get(1).count

    global_metrics.open_db_connections_count_total = list(connections)[0][0] + 1
    global_metrics.current_guest_request_count_total = current_count
    global_metrics.overall_guest_request_count_total = overall_count

    return global_metrics


def generate_metrics() -> bytes:

    logger = artemis.get_logger()
    db = artemis.get_db(logger)

    with _registry_lock:
        registry = CollectorRegistry()
        registry.register(REQUEST_DURATION)
        registry.register(REQUEST_COUNT)
        registry.register(REQUESTS_INPROGRESS)
        registry.register(OPEN_DB_CONNECTIONS_COUNT_TOTAL)
        registry.register(OVERALL_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(CURRENT_GUEST_REQUEST_COUNT_TOTAL)
        registry.register(CURRENT_GUEST_REQUEST_COUNT)

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
            OPEN_DB_CONNECTIONS_COUNT_TOTAL.set(global_metrics.open_db_connections_count_total)
            CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.current_guest_request_count_total)
            OVERALL_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.overall_guest_request_count_total)

        return cast(bytes, generate_latest())
