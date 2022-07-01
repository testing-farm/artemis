# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import uuid
from typing import Any, List

import _pytest.logging
import _pytest.monkeypatch
import dramatiq
import dramatiq.broker
import gluetool.log
import pytest
import redis

from tft.artemis.tasks import Actor, dispatch_sequence, task

from .. import MATCH, assert_log


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
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    results: List[str] = []
    mock_uuids = ['uuid1', 'uuid2', 'uuid3', 'uuid4']

    def mock_uuid4() -> str:
        return mock_uuids.pop(0)

    monkeypatch.setattr(uuid, 'uuid4', mock_uuid4)

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
        message=MATCH(r"""(?m)scheduled sequence:
sequence:
  - actor: dummy_actor
    args:
        foo: foo1
        bar: bar1
    delay:
    message:
        id: uuid1
        age: [0-9\.]+
        queue: default
        options:
            pipe_ignore: true
    task-request:
        id:
  - actor: dummy_actor
    args:
        foo: foo2
        bar: bar2
    delay:
    message:
        id: uuid2
        age: [0-9\.]+
        queue: default
        options:
            pipe_ignore: true
    task-request:
        id:
  - actor: dummy_actor
    args:
        foo: foo3
        bar: bar3
    delay:
    message:
        id: uuid3
        age: [0-9\.]+
        queue: default
        options:
            pipe_ignore: true
    task-request:
        id:
on-complete:
    actor: dummy_actor
    args:
        foo: foo4
        bar: bar4
    delay:
    message:
        id: uuid4
        age: [0-9\.]+
        queue: default
        options:
            pipe_ignore: true
    task-request:
        id:""")
    )

    broker.join(actor.queue_name)
    worker.join()

    assert results == [
        'foo1', 'bar1',
        'foo2', 'bar2',
        'foo3', 'bar3',
        'foo4', 'bar4'
    ]
