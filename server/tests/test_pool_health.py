# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import _pytest.monkeypatch
import gluetool.log
import redis
from gluetool.result import Error, Ok

import tft.artemis
import tft.artemis.context
import tft.artemis.pool_health
from tft.artemis.pool_health import PoolHealth, PoolHealthState

from . import MockPatcher


def _cache() -> redis.Redis:
    return tft.artemis.context.CACHE.get()


def test_pool_health_below_threshold(redis: None) -> None:
    for _ in range(2):
        r_state = PoolHealth.record_failure('dummy-pool', cause='test')

        assert r_state.is_ok

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED


def test_pool_health_trips(redis: None) -> None:
    r_state = PoolHealth.record_failure('dummy-pool', cause='test')

    assert r_state.is_ok

    for _ in range(2):
        r_state = PoolHealth.record_failure('dummy-pool', cause='test')

        assert r_state.is_ok

    assert r_state.unwrap() is PoolHealthState.OPEN

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.OPEN


def test_pool_health_recovery(redis: None, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    # Zero cooldown means the breaker is willing to accept a probe right away.
    monkeypatch.setenv('ARTEMIS_POOL_HEALTH_COOLDOWN_dummy_pool', '0')

    for _ in range(3):
        PoolHealth.record_failure('dummy-pool', cause='test')

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.HALF_OPEN

    r_probe = PoolHealth.acquire_probe('dummy-pool', 'dummy-guest')

    assert r_probe.is_ok
    assert r_probe.unwrap() is True

    # While the probe is in flight, no other probe is allowed.
    r_probe = PoolHealth.acquire_probe('dummy-pool', 'another-guest')

    assert r_probe.is_ok
    assert r_probe.unwrap() is False

    # A successful probe closes the breaker.
    r_state = PoolHealth.record_success('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED

    # The failure log was cleared as well: a single new failure does not re-trip the breaker.
    r_state = PoolHealth.record_failure('dummy-pool', cause='test')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED


def test_pool_health_probe_failure_backs_off(redis: None, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    for _ in range(3):
        PoolHealth.record_failure('dummy-pool', cause='test')

    # The initial cooldown is 300 seconds.
    assert _cache().hget('health.pool.dummy-pool:state', 'cooldown') == b'300'

    # A failed probe re-opens the breaker, and doubles the cooldown.
    r_state = PoolHealth.record_failure('dummy-pool', cause='test')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.OPEN

    assert _cache().hget('health.pool.dummy-pool:state', 'cooldown') == b'600'


def test_pool_health_failure_window(redis: None, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    # Failures that are older than the window do not count towards the threshold.
    monkeypatch.setenv('ARTEMIS_POOL_HEALTH_WINDOW_dummy_pool', '0')

    r_state = PoolHealth.record_failure('dummy-pool', cause='test')

    assert r_state.is_ok

    for _ in range(9):
        r_state = PoolHealth.record_failure('dummy-pool', cause='test')

        assert r_state.is_ok

    assert r_state.unwrap() is PoolHealthState.CLOSED

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED


def test_pool_health_disabled(redis: None, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    monkeypatch.setenv('ARTEMIS_POOL_HEALTH_THRESHOLD_dummy_pool', '0')

    for _ in range(10):
        r_state = PoolHealth.record_failure('dummy-pool', cause='test')

        assert r_state.is_ok

    r_state = PoolHealth.get_state('dummy-pool')

    assert r_state.is_ok
    assert r_state.unwrap() is PoolHealthState.CLOSED


def test_pool_health_probe_lock_disabled(redis: None, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    monkeypatch.setenv('ARTEMIS_POOL_HEALTH_PROBE_TIMEOUT_dummy_pool', '0')

    for _ in range(2):
        r_probe = PoolHealth.acquire_probe('dummy-pool', 'dummy-guest')

        assert r_probe.is_ok
        assert r_probe.unwrap() is True


def test_record_pool_helpers_ignore_tracking_errors(
    logger: gluetool.log.ContextAdapter, mockpatch: MockPatcher
) -> None:
    mock_record_failure = mockpatch(tft.artemis.pool_health.PoolHealth, 'record_failure')
    mock_record_failure.return_value = Error(tft.artemis.Failure('dummy failure'))

    mock_record_success = mockpatch(tft.artemis.pool_health.PoolHealth, 'record_success')
    mock_record_success.return_value = Error(tft.artemis.Failure('dummy failure'))

    # Issues with the tracking itself must not break the task reporting the failure or the success.
    tft.artemis.pool_health.record_pool_failure(logger, 'dummy-pool', 'test')
    tft.artemis.pool_health.record_pool_success(logger, 'dummy-pool')

    mock_record_failure.return_value = Ok(PoolHealthState.OPEN)
    mock_record_success.return_value = Ok(PoolHealthState.CLOSED)

    tft.artemis.pool_health.record_pool_failure(logger, 'dummy-pool', 'test')
    tft.artemis.pool_health.record_pool_success(logger, 'dummy-pool')

    mock_record_failure.assert_called_with('dummy-pool', cause='test')
    mock_record_success.assert_called_with('dummy-pool')
