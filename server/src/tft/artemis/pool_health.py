# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Per-pool health tracking, in the shape of a circuit breaker.

Talking to a pool infrastructure may fail - the infrastructure may be slow, unreachable or completely down.
Bounded timeouts limit how much a single failed call costs, but Artemis would still pay that price for every
guest request routed to the broken pool. The circuit breaker adds a pool-level memory of such failures:

* when a pool reports too many failures within a given window, the breaker trips, and the pool is not routed
  to new guest requests until it recovers;
* when enough time passes, the breaker lets a single guest request - a *probe* - through, while all other
  requests keep being routed elsewhere;
* when the probe succeeds, i.e. the pool manages to provision or update a guest request, the breaker closes,
  and the pool is routable again. When the probe fails, the breaker opens again, this time with a longer
  cooldown.

The breaker state lives in the cache, next to the pool metrics, and is maintained from the provisioning tasks:
every pool failure reported by a driver, and every recoverable failure of the provisioning itself, is recorded,
and every successful contact with the pool infrastructure resets the breaker. The routing policy
:py:func:`tft.artemis.routing_policies.policy_pool_health` then keeps guest requests away from pools with
an open breaker.
"""

import enum
import time
from typing import Optional

import gluetool.log
import redis
from gluetool.result import Error, Ok, Result

from . import Failure
from .context import with_context
from .knobs import Knob

KNOB_POOL_HEALTH_THRESHOLD: Knob[int] = Knob(
    'route.pool.health.threshold',
    """
    How many pool failures within the failure window trip the pool health circuit breaker. Once tripped,
    the pool is not routed to new guest requests until it recovers. Set to zero or less to disable
    the circuit breaker.
    """,
    per_entity=True,
    envvar='ARTEMIS_POOL_HEALTH_THRESHOLD',
    cast_from_str=int,
    default=3,
)

KNOB_POOL_HEALTH_WINDOW: Knob[int] = Knob(
    'route.pool.health.window',
    """
    How long, in seconds, do pool failures count towards tripping the pool health circuit breaker.
    """,
    per_entity=True,
    envvar='ARTEMIS_POOL_HEALTH_WINDOW',
    cast_from_str=int,
    default=300,
)

KNOB_POOL_HEALTH_COOLDOWN: Knob[int] = Knob(
    'route.pool.health.cooldown',
    """
    How long, in seconds, does the pool health circuit breaker stay open before letting a probe guest request
    through. Every failed probe doubles the cooldown, up to `route.pool.health.cooldown-max`.
    """,
    per_entity=True,
    envvar='ARTEMIS_POOL_HEALTH_COOLDOWN',
    cast_from_str=int,
    default=300,
)

KNOB_POOL_HEALTH_COOLDOWN_MAX: Knob[int] = Knob(
    'route.pool.health.cooldown-max',
    """
    The maximum cooldown, in seconds, of the pool health circuit breaker, no matter how many probes failed.
    """,
    per_entity=True,
    envvar='ARTEMIS_POOL_HEALTH_COOLDOWN_MAX',
    cast_from_str=int,
    default=3600,
)

KNOB_POOL_HEALTH_PROBE_TIMEOUT: Knob[int] = Knob(
    'route.pool.health.probe-timeout',
    """
    How long, in seconds, to wait for the outcome of a probe guest request before allowing another one.
    This is a safety net - the probe lock is released as soon as the pool reports a success or a failure.
    Set to zero or less to not limit the number of probes at all.
    """,
    per_entity=True,
    envvar='ARTEMIS_POOL_HEALTH_PROBE_TIMEOUT',
    cast_from_str=int,
    default=600,
)


class PoolHealthState(enum.Enum):
    """
    State of the pool health circuit breaker.
    """

    #: The pool is healthy, and routable.
    CLOSED = 'closed'

    #: The pool failed too many times, and is not routable.
    OPEN = 'open'

    #: The pool may have recovered, and a single probe guest request is allowed to find out.
    HALF_OPEN = 'half-open'


class PoolHealth:
    """
    The pool health circuit breaker state, stored in the cache.

    Since the breaker state is derived from, and maintained by, many concurrent workers, it is stored
    in the cache rather than in the database, and is not replicated into the database or metrics beyond
    log messages and routing reports.
    """

    _KEY_FAILURES = 'health.pool.{poolname}:failures'
    _KEY_STATE = 'health.pool.{poolname}:state'
    _KEY_PROBE = 'health.pool.{poolname}:probe'

    @staticmethod
    def _read_raw_state(cache: redis.Redis, poolname: str) -> PoolHealthState:
        """
        Read the state as stored in the cache, without deriving the half-open state from the cooldown.
        """

        state = cache.hget(PoolHealth._KEY_STATE.format(poolname=poolname), 'state')

        if state is None:
            return PoolHealthState.CLOSED

        if isinstance(state, bytes):
            state = state.decode()

        try:
            return PoolHealthState(state)

        except ValueError:
            return PoolHealthState.CLOSED

    @staticmethod
    @with_context
    def record_failure(
        poolname: str,
        *,
        cause: Optional[str] = None,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
    ) -> Result[PoolHealthState, Failure]:
        """
        Record a pool failure, and trip the breaker when there are too many of them within the failure window.

        :param poolname: name of the pool that failed.
        :param cause: optional description of the failure, for debugging.
        :returns: either a valid result, the state of the breaker, or an error with a :py:class:`Failure`
            describing the problem.
        """

        r_threshold = KNOB_POOL_HEALTH_THRESHOLD.get_value(entityname=poolname)

        if r_threshold.is_error:
            return Error(r_threshold.unwrap_error())

        threshold = r_threshold.unwrap()

        # Zero or negative threshold disables the breaker.
        if threshold <= 0:
            return Ok(PoolHealthState.CLOSED)

        r_window = KNOB_POOL_HEALTH_WINDOW.get_value(entityname=poolname)

        if r_window.is_error:
            return Error(r_window.unwrap_error())

        r_cooldown = KNOB_POOL_HEALTH_COOLDOWN.get_value(entityname=poolname)

        if r_cooldown.is_error:
            return Error(r_cooldown.unwrap_error())

        r_cooldown_max = KNOB_POOL_HEALTH_COOLDOWN_MAX.get_value(entityname=poolname)

        if r_cooldown_max.is_error:
            return Error(r_cooldown_max.unwrap_error())

        now = time.time()
        window = r_window.unwrap()

        key_failures = PoolHealth._KEY_FAILURES.format(poolname=poolname)
        key_state = PoolHealth._KEY_STATE.format(poolname=poolname)

        # Record the failure, drop the failures older than the failure window, and keep the failure log
        # around for only a bit longer than the failures may matter.
        cache.zadd(key_failures, {f'{now:.6f}:{cause or "unknown"}': now})
        cache.zremrangebyscore(key_failures, '-inf', now - window)
        cache.expire(key_failures, max(int(window * 2), 1))

        if cache.zcard(key_failures) < threshold:
            return Ok(PoolHealthState.CLOSED)

        current_state = PoolHealth._read_raw_state(cache, poolname)
        cooldown = r_cooldown.unwrap()

        # A repeated trip backs off exponentially, up to the maximum cooldown.
        if current_state is PoolHealthState.OPEN:
            current_cooldown = cache.hget(key_state, 'cooldown')

            if current_cooldown is not None:
                cooldown = min(int(current_cooldown) * 2, r_cooldown_max.unwrap())

        cache.hset(
            key_state,
            mapping={
                'state': PoolHealthState.OPEN.value,
                'opened-at': now,
                'cooldown': cooldown,
            },
        )

        # Keep the state around for only as long as the breaker may stay open.
        cache.expire(key_state, r_cooldown_max.unwrap() + r_threshold.unwrap() * 2 + 7200)

        # A new trip invalidates any probe that may be in flight.
        cache.delete(PoolHealth._KEY_PROBE.format(poolname=poolname))

        if current_state is not PoolHealthState.OPEN:
            logger.warning(
                f'pool health circuit breaker tripped: {cache.zcard(key_failures)} failures '
                f'in the last {window} seconds'
            )

        return Ok(PoolHealthState.OPEN)

    @staticmethod
    @with_context
    def record_success(
        poolname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
    ) -> Result[PoolHealthState, Failure]:
        """
        Record a successful contact with the pool infrastructure, closing the breaker.

        :param poolname: name of the pool that succeeded.
        :returns: either a valid result, the state of the breaker, or an error with a :py:class:`Failure`
            describing the problem.
        """

        current_state = PoolHealth._read_raw_state(cache, poolname)

        cache.delete(PoolHealth._KEY_FAILURES.format(poolname=poolname))
        cache.delete(PoolHealth._KEY_STATE.format(poolname=poolname))
        cache.delete(PoolHealth._KEY_PROBE.format(poolname=poolname))

        if current_state is not PoolHealthState.CLOSED:
            logger.info('pool health circuit breaker closed, pool is routable again')

        return Ok(PoolHealthState.CLOSED)

    @staticmethod
    @with_context
    def get_state(
        poolname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
    ) -> Result[PoolHealthState, Failure]:
        """
        Resolve the current state of the breaker.

        :param poolname: name of the pool.
        :returns: either a valid result, the state of the breaker, or an error with a :py:class:`Failure`
            describing the problem.
        """

        r_threshold = KNOB_POOL_HEALTH_THRESHOLD.get_value(entityname=poolname)

        if r_threshold.is_error:
            return Error(r_threshold.unwrap_error())

        # Zero or negative threshold disables the breaker.
        if r_threshold.unwrap() <= 0:
            return Ok(PoolHealthState.CLOSED)

        raw_state = PoolHealth._read_raw_state(cache, poolname)

        if raw_state is not PoolHealthState.OPEN:
            return Ok(raw_state)

        key_state = PoolHealth._KEY_STATE.format(poolname=poolname)

        opened_at = cache.hget(key_state, 'opened-at')
        cooldown = cache.hget(key_state, 'cooldown')

        if opened_at is None or cooldown is None:
            # Incomplete state - rather fail open than keep the pool unroutable forever.
            return Ok(PoolHealthState.CLOSED)

        try:
            if time.time() - float(opened_at) >= float(cooldown):
                return Ok(PoolHealthState.HALF_OPEN)

        except ValueError:
            return Ok(PoolHealthState.CLOSED)

        return Ok(PoolHealthState.OPEN)

    @staticmethod
    @with_context
    def acquire_probe(
        poolname: str,
        probe_id: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
    ) -> Result[bool, Failure]:
        """
        Try to acquire the right to probe a half-open pool with the given guest request.

        Only one probe may be in flight at a time: while its outcome is unknown, other guest requests
        are not routed to the pool. The lock is released when the pool reports a success or a failure,
        or when it runs out of time.

        :param poolname: name of the pool to probe.
        :param probe_id: identifier of the probe, e.g. the guestname of the probing request.
        :returns: either a valid result, ``True`` when the caller became the probe, or an error with
            a :py:class:`Failure` describing the problem.
        """

        r_probe_timeout = KNOB_POOL_HEALTH_PROBE_TIMEOUT.get_value(entityname=poolname)

        if r_probe_timeout.is_error:
            return Error(r_probe_timeout.unwrap_error())

        probe_timeout = r_probe_timeout.unwrap()

        # Zero or negative timeout disables the probe lock, allowing any number of concurrent probes.
        if probe_timeout <= 0:
            return Ok(True)

        acquired = cache.set(
            PoolHealth._KEY_PROBE.format(poolname=poolname), probe_id, nx=True, ex=max(int(probe_timeout), 1)
        )

        return Ok(bool(acquired))


def record_pool_failure(logger: gluetool.log.ContextAdapter, poolname: str, cause: str) -> None:
    """
    Record a pool failure for the pool health circuit breaker.

    The tracking itself must never break the task reporting the failure, therefore issues with the tracking
    are only logged.

    :param logger: logger to use for logging.
    :param poolname: name of the pool that failed.
    :param cause: description of the failure.
    """

    r_state = PoolHealth.record_failure(poolname, cause=cause)

    if r_state.is_error:
        r_state.unwrap_error().log(logger.warning, label='failed to record pool failure for the health breaker')


def record_pool_success(logger: gluetool.log.ContextAdapter, poolname: str) -> None:
    """
    Record a pool success for the pool health circuit breaker.

    The tracking itself must never break the task reporting the success, therefore issues with the tracking
    are only logged.

    :param logger: logger to use for logging.
    :param poolname: name of the pool that succeeded.
    """

    r_state = PoolHealth.record_success(poolname)

    if r_state.is_error:
        r_state.unwrap_error().log(logger.warning, label='failed to record pool success for the health breaker')
