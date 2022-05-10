# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any, List

import _pytest.logging
import dramatiq
import dramatiq.broker
import gluetool.log
import pytest
import redis

from tft.artemis.tasks import Actor, dispatch_sequence, task

from .. import assert_log


@pytest.fixture(name='actor')
def fixture_actor() -> Actor:
    @task()
    def dummy_actor(foo: Any, bar: Any) -> None:
        print(foo, bar)

    return dummy_actor


def test_sequence(
    logger: gluetool.log.ContextAdapter,
    broker: dramatiq.broker.Broker,
    redis: redis.Redis,
    worker: dramatiq.Worker,
    actor: Actor,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    results: List[str] = []

    @task()
    def dummy_actor(foo: Any, bar: Any) -> None:
        print(f'dummy_actor: {foo} {bar}')
        results.append(foo)
        results.append(bar)

    r = dispatch_sequence(
        logger,
        [
            (actor, ('foo1', 'bar1')),
            (actor, ('foo2', 'bar2')),
            (actor, ('foo3', 'bar3')),
        ],
        on_complete=(actor, ('foo4', 'bar4'))
    )

    assert r.is_ok

    assert_log(
        caplog,
        levelno=logging.INFO,
        message="""scheduled sequence:
sequence:
  - actor: dummy_actor
    args:
        foo: foo1
        bar: bar1
  - actor: dummy_actor
    args:
        foo: foo2
        bar: bar2
  - actor: dummy_actor
    args:
        foo: foo3
        bar: bar3
on-complete:
    actor: dummy_actor
    args:
        foo: foo4
        bar: bar4"""
    )

    broker.join(actor.queue_name)
    worker.join()

    assert results == [
        'foo1', 'bar1',
        'foo2', 'bar2',
        'foo3', 'bar3',
        'foo4', 'bar4'
    ]
