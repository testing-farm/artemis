# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import time
import uuid

import _pytest.logging
import gluetool.log
import pytest
import redis

import tft.artemis.cache
from tests import assert_failure_log


@pytest.fixture(name='lockname')
def fixture_lockname() -> str:
    return f'test-lock-{uuid.uuid4()}'


def test_lock_sanity(logger: gluetool.log.ContextAdapter, cache: redis.Redis, lockname: str) -> None:
    token = tft.artemis.cache.acquire_lock(logger, cache, lockname)

    assert token is not None

    time.sleep(1)

    result = tft.artemis.cache.release_lock(logger, cache, lockname, token)

    assert result is True


def test_lock_ttl_expired(
    logger: gluetool.log.ContextAdapter, cache: redis.Redis, caplog: _pytest.logging.LogCaptureFixture, lockname: str
) -> None:
    token = tft.artemis.cache.acquire_lock(logger, cache, lockname, ttl=5)

    assert token is not None

    time.sleep(10)

    result = tft.artemis.cache.release_lock(logger, cache, lockname, token)

    assert result is False

    assert_failure_log(caplog, 'lock does not exist anymore')


def test_lock_ownership_change(
    logger: gluetool.log.ContextAdapter, cache: redis.Redis, caplog: _pytest.logging.LogCaptureFixture, lockname: str
) -> None:
    token = tft.artemis.cache.acquire_lock(logger, cache, lockname)

    assert token is not None

    # inject "ownership change": lock expired, and another process acquired it before we got to unlock it
    new_token = str(uuid.uuid4())

    tft.artemis.cache.set_cache_value(logger, cache, lockname, str(new_token).encode('utf-8'))

    # now try unlocking what we no longer own
    result = tft.artemis.cache.release_lock(logger, cache, lockname, token)

    assert result is False

    assert_failure_log(caplog, 'lock token changed before release')
