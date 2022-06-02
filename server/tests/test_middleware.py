# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Any, Dict, cast
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
from tft.artemis.middleware import _actor_arguments
from tft.artemis.tasks import Actor, ActorArgumentsType, task

from . import MockPatcher, assert_failure_log, assert_log


@pytest.fixture(name='actor_arguments')
def fixture_actor_arguments() -> Dict[str, MagicMock]:
    return {
        'foo': MagicMock(name='argument-foo<mock>'),
        'bar': MagicMock(name='argument-bar<mock>')
    }


@pytest.fixture(name='message')
def fixture_message(actor_arguments: ActorArgumentsType) -> dramatiq.broker.MessageProxy:
    message = dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name='dummy_actor',
        args=(
            actor_arguments['foo'],
            actor_arguments['bar']
        ),
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


def test_actor_arguments(
    logger: ContextAdapter,
    message: dramatiq.broker.MessageProxy,
    actor: Actor,
    actor_arguments: ActorArgumentsType
) -> None:
    assert _actor_arguments(logger, message, actor) == actor_arguments


def test_actor_arguments_signature_mismatch(
    logger: ContextAdapter,
    actor: Actor,
    actor_arguments: ActorArgumentsType,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    broken_message = dramatiq.broker.MessageProxy(dramatiq.message.Message(
        queue_name='dummy-queue',
        actor_name='dummy_actor',
        args=(
            # Just one argument, not two.
            actor_arguments['foo'],
        ),
        kwargs={},
        options={}
    ))

    assert _actor_arguments(logger, broken_message, actor) == {}
    assert_failure_log(caplog, 'actor signature parameters does not match message content')


def test_get_message_limit_from_message(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['dummy_limit'] = 79
    actor.options['dummy_limit'] = 97

    assert tft.artemis.middleware._get_message_limit(message, actor, 'dummy_limit', 979) == 79


def test_get_message_limit_from_actor(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['dummy_limit'] = None
    actor.options['dummy_limit'] = 97

    assert tft.artemis.middleware._get_message_limit(message, actor, 'dummy_limit', 979) == 97


def test_get_message_limit_from_default(
    message: dramatiq.broker.MessageProxy,
    actor: Actor
) -> None:
    message.options['dummy_limit'] = None
    actor.options['dummy_limit'] = None

    assert tft.artemis.middleware._get_message_limit(message, actor, 'dummy_limit', 979) == 979


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
        actor,
        retries
    )

    assert lower <= backoff <= upper


def test_retry_message(
    logger: ContextAdapter,
    message: dramatiq.broker.MessageProxy,
    actor: Actor,
    mockpatch: MockPatcher
) -> None:
    mock_broker = MagicMock(name='broker<mock>')

    mockpatch(tft.artemis.middleware, '_message_backoff').return_value = 79

    tft.artemis.middleware._retry_message(
        logger,
        mock_broker,
        message,
        actor
    )

    assert message.options['retries'] == 1
    assert 'traceback' not in message.options

    cast(MagicMock, tft.artemis.middleware._message_backoff).assert_called_once_with(message, actor, 1)
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
def fixture_provisioning_actor_arguments() -> ActorArgumentsType:
    return {
        'guestname': 'dummy-guestname'
    }


@pytest.fixture(name='provisioning_message')
def fixture_provisioning_message(
    provisioning_actor: Actor,
    provisioning_actor_arguments: ActorArgumentsType
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
def fixture_logging_actor_arguments() -> ActorArgumentsType:
    return {
        'guestname': 'dummy-guestname',
        'logname': 'console',
        'contenttype': 'url'
    }


@pytest.fixture(name='logging_message')
def fixture_logging_message(
    logging_actor: Actor,
    logging_actor_arguments: ActorArgumentsType
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
    provisioning_actor_arguments: ActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.middleware, '_fail_message')
    mockpatch(tft.artemis.middleware, '_retry_message')

    del provisioning_actor_arguments['guestname']

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        provisioning_actor,
        provisioning_actor_arguments
    ) is True

    cast(MagicMock, tft.artemis.middleware._fail_message).assert_not_called()
    cast(MagicMock, tft.artemis.middleware._retry_message).assert_not_called()

    assert_failure_log(caplog, 'failed to extract actor arguments')


def test_handle_tails_missing_log_params(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: ContextAdapter,
    logging_message: dramatiq.broker.MessageProxy,
    logging_actor: Actor,
    logging_actor_arguments: ActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.middleware, '_fail_message')
    mockpatch(tft.artemis.middleware, '_retry_message')

    del logging_actor_arguments['logname']
    del logging_actor_arguments['contenttype']

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        logging_actor,
        logging_actor_arguments
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
    provisioning_actor_arguments: ActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(provisioning_actor.options['tail_handler'], 'do_handle_tail').return_value = tft.artemis.tasks.SUCCESS

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        provisioning_actor,
        provisioning_actor_arguments
    ) is True

    cast(MagicMock, provisioning_actor.options['tail_handler'].do_handle_tail).assert_called_once_with(
        ANY,
        db,
        ANY,
        ANY,
        provisioning_actor,
        provisioning_actor_arguments,
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
    logging_actor_arguments: ActorArgumentsType,
    mockpatch: MockPatcher
) -> None:
    mockpatch(logging_actor.options['tail_handler'], 'do_handle_tail').return_value = tft.artemis.tasks.SUCCESS

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        logging_actor,
        logging_actor_arguments
    ) is True

    cast(MagicMock, logging_actor.options['tail_handler'].do_handle_tail).assert_called_once_with(
        ANY,
        db,
        ANY,
        ANY,
        logging_actor,
        logging_actor_arguments,
        {
            'guestname': 'dummy-guestname',
            'logname': 'console',
            'contenttype': 'url'
        }
    )

    assert_log(caplog, message='successfuly handled the chain tail', levelno=logging.INFO)
