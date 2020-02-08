import dataclasses
import sqlalchemy
import threading

from prometheus_client import Gauge, CollectorRegistry, generate_latest

from molten import Response, HTTP_200
from molten.contrib.prometheus import REQUEST_DURATION, REQUEST_COUNT, REQUESTS_INPROGRESS

import gluetool.log

import artemis
import artemis.tasks

_registry_lock = threading.Lock()

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
    current_guest_request_count_total: int = 0
    overall_guest_request_count_total: int = 0


def get_global_metrics(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Metrics:

    global_metrics = Metrics()

    current_count = len(session.query(artemis.db.GuestRequest).all())
    overall_count = session.query(artemis.db.Metrics).get(1).count
    global_metrics.current_guest_request_count_total = current_count
    global_metrics.overall_guest_request_count_total = overall_count

    return global_metrics


def get_metrics() -> Response:

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

        # add pool-specific metrics
        with db.get_session() as session:
            pools = artemis.tasks.get_pools(logger, session)
        for pool in pools:
            pool_metrics = pool.metrics(logger, session)
            for state in pool_metrics.current_guest_request_count_per_state:
                CURRENT_GUEST_REQUEST_COUNT.labels(pool.poolname, state.value) \
                    .set(pool_metrics.current_guest_request_count_per_state[state])

        # add all guest request count (both current and overall)
        global_metrics = get_global_metrics(logger, session)
        CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.current_guest_request_count_total)
        OVERALL_GUEST_REQUEST_COUNT_TOTAL.set(global_metrics.overall_guest_request_count_total)

        return HTTP_200, generate_latest().decode("utf-8")
