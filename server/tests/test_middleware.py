# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import logging
from typing import Any, List, Tuple, cast
from unittest.mock import ANY, MagicMock

import _pytest.logging
import _pytest.monkeypatch
import dramatiq.broker
import dramatiq.message
import dramatiq.middleware.retries
import pytest
from gluetool.log import ContextAdapter

import tft.artemis.db
import tft.artemis.middleware
import tft.artemis.tasks
import tft.artemis.tasks.update_guest_request
from tft.artemis.tasks import Actor, ActorArgumentType, NamedActorArgumentsType, TaskCall, task

from . import MockPatcher, assert_failure_log, assert_log


@pytest.fixture(name='actor_arguments')
def fixture_actor_arguments() -> List[Tuple[str, ActorArgumentType]]:
    return [
        ('foo', MagicMock(name='argument-foo<mock>')),
        ('bar', MagicMock(name='argument-bar<mock>'))
    ]


@pytest.fixture(name='named_actor_arguments')
def fixture_named_actor_arguments(actor_arguments: List[Tuple[str, ActorArgumentType]]) -> NamedActorArgumentsType:
    return {
        name: value for name, value in actor_arguments
    }


@pytest.fixture(name='message')
def fixture_message(actor_arguments: List[Tuple[str, ActorArgumentType]]) -> dramatiq.broker.MessageProxy:
    message = dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name='dummy_actor',
        args=tuple(value for _, value in actor_arguments),
        # Our actors are not allowed to have keyword parameters
        kwargs={},
        options={}
    )

    return dramatiq.broker.MessageProxy(message)


@pytest.fixture(name='actor')
def fixture_actor() -> Actor:
    @task()
    def dummy_actor(foo: Any, bar: Any) -> None:
        pass

    return dummy_actor


def test_task_call_from_message(
    broker: dramatiq.broker.Broker,
    message: dramatiq.broker.MessageProxy,
    actor: Actor,
    actor_arguments: List[Tuple[str, ActorArgumentType]],
    named_actor_arguments: NamedActorArgumentsType
) -> None:
    task_call = TaskCall.from_message(broker, message)

    assert task_call.actor is actor
    assert task_call.args == tuple(value for _, value in actor_arguments)
    assert task_call.arg_names == tuple(name for name, _ in actor_arguments)
    assert task_call.named_args == named_actor_arguments
    assert task_call.has_tail_handler is False
    assert task_call.tail_handler is None


def test_actor_arguments_signature_mismatch(
    broker: dramatiq.broker.Broker,
    actor: Actor,
    actor_arguments: List[Tuple[str, ActorArgumentType]]
) -> None:
    broken_message = dramatiq.broker.MessageProxy(dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name='dummy_actor',
        args=(
            # Just one argument, not two.
            actor_arguments[0][1],
        ),
        kwargs={},
        options={}
    ))

    with pytest.raises(AssertionError, match='actor signature parameters does not match message content'):
        TaskCall.from_message(broker, broken_message)


def test_get_message_limit_from_message(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['max_retries'] = 79
    actor.options['max_retries'] = 97

    assert tft.artemis.middleware._get_message_limit(message, 'max_retries', 979, actor=actor) == 79


def test_get_message_limit_from_actor(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['max_retries'] = None
    actor.options['max_retries'] = 97

    assert tft.artemis.middleware._get_message_limit(message, 'max_retries', 979, actor=actor) == 97


def test_get_message_limit_from_default(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['max_retries'] = None
    actor.options['max_retries'] = None

    assert tft.artemis.middleware._get_message_limit(message, 'max_retries', 979, actor=actor) == 979


@pytest.mark.parametrize(
    ('retries', 'min_backoff', 'max_backoff', 'lower', 'upper'),
    [
        (1, 15000, 60000, 15000, 30000),
        (2, 15000, 60000, 30000, 60000),
        # max_backoff is 60000 therefore, despite increased retries, the backoff will stay between these limits
        (3, 15000, 60000, 30000, 60000),
        (4, 15000, 60000, 30000, 60000),
        # now increase the max_backoff, that should allow higher backoff
        (3, 15000, 1000000, 60000, 120000),
        (4, 15000, 1000000, 120000, 240000)
    ]
)
def test_message_backoff(
    message: dramatiq.broker.MessageProxy,
    actor: Actor,
    retries: int,
    min_backoff: int,
    max_backoff: int,
    lower: int,
    upper: int
) -> None:
    message.options['min_backoff'] = min_backoff
    message.options['max_backoff'] = max_backoff

    backoff = tft.artemis.middleware._message_backoff(
        message,
        retries,
        actor=actor
    )

    assert lower <= backoff <= upper


def test_retry_message(
    logger: ContextAdapter,
    message: dramatiq.broker.MessageProxy,
    actor: Actor,
    actor_arguments: List[Tuple[str, ActorArgumentType]],
    mockpatch: MockPatcher
) -> None:
    mock_broker = MagicMock(name='broker<mock>')

    mockpatch(tft.artemis.middleware, '_message_backoff').return_value = 79

    task_call = tft.artemis.tasks.TaskCall.from_call(actor, *tuple(str(value) for _, value in actor_arguments))

    tft.artemis.middleware._retry_message(
        logger,
        mock_broker,
        message,
        task_call=task_call
    )

    assert message.options['retries'] == 1
    assert 'traceback' not in message.options

    cast(MagicMock, tft.artemis.middleware._message_backoff).assert_called_once_with(message, 1, actor=actor)
    mock_broker.enqueue.assert_called_once_with(message, delay=79)


def test_fail_message(
    logger: ContextAdapter,
    message: dramatiq.broker.MessageProxy,
    mockpatch: MockPatcher
) -> None:
    mock_failure = mockpatch(tft.artemis, 'Failure')
    mock_failure.return_value = MagicMock(name='failure<mock>')

    mockpatch(message, 'fail', obj_name='message')

    tft.artemis.middleware._fail_message(logger, message, 'dummy error message')

    mock_failure.assert_called_once_with('dummy error message', broker_message=dict(**message.asdict()))
    mock_failure.return_value.handle.assert_called_once_with(logger)
    cast(MagicMock, message.fail).assert_called_once_with()


@pytest.fixture(name='provisioning_actor')
def fixture_provisioning_actor() -> Actor:
    return tft.artemis.tasks.update_guest_request.update_guest_request


@pytest.fixture(name='provisioning_actor_arguments')
def fixture_provisioning_actor_arguments() -> NamedActorArgumentsType:
    return collections.OrderedDict([('guestname', 'dummy-guestname')])


@pytest.fixture(name='provisioning_message')
def fixture_provisioning_message(
    provisioning_actor: Actor,
    provisioning_actor_arguments: NamedActorArgumentsType
) -> dramatiq.broker.MessageProxy:
    message = dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name=provisioning_actor.actor_name,
        args=(
            provisioning_actor_arguments['guestname'],
        ),
        kwargs={},
        options={}
    )

    return dramatiq.broker.MessageProxy(message)


@pytest.fixture(name='logging_actor')
def fixture_logging_actor() -> Actor:
    return tft.artemis.tasks.update_guest_log


@pytest.fixture(name='logging_actor_arguments')
def fixture_logging_actor_arguments() -> NamedActorArgumentsType:
    return collections.OrderedDict([
        ('guestname', 'dummy-guestname'),
        ('logname', 'console'),
        ('contenttype', 'url')
    ])


@pytest.fixture(name='logging_message')
def fixture_logging_message(
    logging_actor: Actor,
    logging_actor_arguments: NamedActorArgumentsType
) -> dramatiq.broker.MessageProxy:
    message = dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name=logging_actor.actor_name,
        args=(
            logging_actor_arguments['guestname'],
            logging_actor_arguments['logname'],
            logging_actor_arguments['contenttype'],
        ),
        kwargs={},
        options={}
    )

    return dramatiq.broker.MessageProxy(message)


def test_handle_tails_missing_guestname(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: ContextAdapter,
    provisioning_message: dramatiq.broker.MessageProxy,
    provisioning_actor: Actor,
    provisioning_actor_arguments: NamedActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.middleware, '_fail_message')
    mockpatch(tft.artemis.middleware, '_retry_message')

    del provisioning_actor_arguments['guestname']

    task_call = tft.artemis.tasks.TaskCall(
        actor=provisioning_actor,
        args=tuple(provisioning_actor_arguments.values()),
        arg_names=tuple(provisioning_actor_arguments.keys())
    )

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        task_call
    ) is True

    cast(MagicMock, tft.artemis.middleware._fail_message).assert_not_called()
    cast(MagicMock, tft.artemis.middleware._retry_message).assert_not_called()

    assert_failure_log(caplog, 'failed to extract actor arguments')


def test_handle_tails_missing_log_params(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: ContextAdapter,
    logging_message: dramatiq.broker.MessageProxy,
    logging_actor: Actor,
    logging_actor_arguments: NamedActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.middleware, '_fail_message')
    mockpatch(tft.artemis.middleware, '_retry_message')

    del logging_actor_arguments['logname']
    del logging_actor_arguments['contenttype']

    task_call = tft.artemis.tasks.TaskCall(
        actor=logging_actor,
        args=tuple(logging_actor_arguments.values()),
        arg_names=tuple(logging_actor_arguments.keys())
    )

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        task_call
    ) is True

    cast(MagicMock, tft.artemis.middleware._fail_message).assert_not_called()
    cast(MagicMock, tft.artemis.middleware._retry_message).assert_not_called()

    assert_failure_log(caplog, 'failed to extract actor arguments')


def test_handle_tails_provisioning(
    db: tft.artemis.db.DB,
    caplog: _pytest.logging.LogCaptureFixture,
    logger: ContextAdapter,
    provisioning_message: dramatiq.broker.MessageProxy,
    provisioning_actor: Actor,
    provisioning_actor_arguments: NamedActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    assert provisioning_actor.options['tail_handler']

    mockpatch(provisioning_actor.options['tail_handler'], 'do_handle_tail').return_value = tft.artemis.tasks.SUCCESS

    task_call = tft.artemis.tasks.TaskCall(
        actor=provisioning_actor,
        args=tuple(provisioning_actor_arguments.values()),
        arg_names=tuple(provisioning_actor_arguments.keys())
    )

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        task_call
    ) is True

    cast(MagicMock, provisioning_actor.options['tail_handler'].do_handle_tail).assert_called_once_with(
        ANY,
        db,
        ANY,
        ANY,
        task_call,
        {
            'guestname': 'dummy-guestname'
        }
    )

    assert_log(caplog, message='successfuly handled the chain tail', levelno=logging.INFO)


def test_handle_tails_logging(
    db: tft.artemis.db.DB,
    caplog: _pytest.logging.LogCaptureFixture,
    logger: ContextAdapter,
    logging_message: dramatiq.broker.MessageProxy,
    logging_actor: Actor,
    logging_actor_arguments: NamedActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    assert logging_actor.options['tail_handler']

    mockpatch(logging_actor.options['tail_handler'], 'do_handle_tail').return_value = tft.artemis.tasks.SUCCESS

    task_call = tft.artemis.tasks.TaskCall(
        actor=logging_actor,
        args=tuple(logging_actor_arguments.values()),
        arg_names=tuple(logging_actor_arguments.keys())
    )

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        task_call
    ) is True

    cast(MagicMock, logging_actor.options['tail_handler'].do_handle_tail).assert_called_once_with(
        ANY,
        db,
        ANY,
        ANY,
        task_call,
        {
            'guestname': 'dummy-guestname',
            'logname': 'console',
            'contenttype': 'url'
        }
    )

    assert_log(caplog, message='successfuly handled the chain tail', levelno=logging.INFO)
