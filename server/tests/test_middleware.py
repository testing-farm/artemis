import logging

import dramatiq.broker
import dramatiq.message
import dramatiq.middleware.retries
import pytest
from mock import ANY, MagicMock

import tft.artemis.db
import tft.artemis.middleware
import tft.artemis.tasks
from tft.artemis.middleware import _actor_arguments
from tft.artemis.tasks import task

from . import assert_failure_log, assert_log


@pytest.fixture(name='actor_arguments')
def fixture_actor_arguments():
    return {
        'foo': MagicMock(name='argument-foo<mock>'),
        'bar': MagicMock(name='argument-bar<mock>')
    }


@pytest.fixture(name='message')
def fixture_message(actor_arguments):
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
def fixture_actor():
    @task()
    def dummy_actor(foo, bar):
        pass

    return dummy_actor


def test_actor_arguments(logger, message, actor, actor_arguments):
    assert _actor_arguments(logger, message, actor) == actor_arguments


def test_actor_arguments_signature_mismatch(logger, actor, actor_arguments, caplog):
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


def test_get_message_limit_from_message(message, actor):
    message.options['dummy_limit'] = 79
    actor.options['dummy_limit'] = 97

    assert tft.artemis.middleware._get_message_limit(message, actor, 'dummy_limit', 979) == 79


def test_get_message_limit_from_actor(message, actor):
    message.options['dummy_limit'] = None
    actor.options['dummy_limit'] = 97

    assert tft.artemis.middleware._get_message_limit(message, actor, 'dummy_limit', 979) == 97


def test_get_message_limit_from_default(message, actor):
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
def test_message_backoff(message, actor, retries, min_backoff, max_backoff, lower, upper):
    message.options['min_backoff'] = min_backoff
    message.options['max_backoff'] = max_backoff

    backoff = tft.artemis.middleware._message_backoff(
        message,
        actor,
        retries
    )

    assert lower <= backoff <= upper


def test_retry_message(logger, message, actor, monkeypatch):
    mock_broker = MagicMock(name='broker<mock>')
    mock_message_backoff = MagicMock(return_value=79)

    monkeypatch.setattr(tft.artemis.middleware, '_message_backoff', mock_message_backoff)

    tft.artemis.middleware._retry_message(
        logger,
        mock_broker,
        message,
        actor
    )

    assert message.options['retries'] == 1
    assert 'traceback' not in message.options

    mock_message_backoff.assert_called_once_with(message, actor, 1)
    mock_broker.enqueue.assert_called_once_with(message, delay=79)


def test_fail_message(logger, message, monkeypatch):
    mock_failure = MagicMock(
        name='Failure<mock>',
        return_value=MagicMock(name='failure<mock>')
    )

    monkeypatch.setattr(tft.artemis, 'Failure', mock_failure)

    mock_fail = MagicMock(name='message.fail<mock>')
    monkeypatch.setattr(message, 'fail', mock_fail)

    tft.artemis.middleware._fail_message(logger, message, 'dummy error message')

    mock_failure.assert_called_once_with('dummy error message')
    mock_failure.return_value.handle.assert_called_once_with(logger)
    mock_fail.assert_called_once_with()


@pytest.fixture(name='provisioning_actor')
def fixture_provisioning_actor():
    return tft.artemis.tasks.update_guest_request


@pytest.fixture(name='provisioning_actor_arguments')
def fixture_provisioning_actor_arguments():
    return {
        'guestname': 'dummy-guestname'
    }


@pytest.fixture(name='provisioning_message')
def fixture_provisioning_message(provisioning_actor, provisioning_actor_arguments):
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
def fixture_logging_actor():
    return tft.artemis.tasks.update_guest_log


@pytest.fixture(name='logging_actor_arguments')
def fixture_logging_actor_arguments():
    return {
        'guestname': 'dummy-guestname',
        'logname': 'console',
        'contenttype': 'url'
    }


@pytest.fixture(name='logging_message')
def fixture_logging_message(logging_actor, logging_actor_arguments):
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


def test_handle_tails_missing_guestname(logger, provisioning_message, provisioning_actor, provisioning_actor_arguments, monkeypatch):
    mock_fail_message = MagicMock(name='_fail_message<mock>')
    monkeypatch.setattr(tft.artemis.middleware, '_fail_message', mock_fail_message)

    del provisioning_actor_arguments['guestname']

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        provisioning_actor,
        provisioning_actor_arguments
    ) is True

    mock_fail_message.assert_called_once_with(
        ANY,
        provisioning_message,
        'cannot handle chain tail with undefined guestname'
    )


def test_handle_tails_missing_log_params(logger, logging_message, logging_actor, logging_actor_arguments, monkeypatch):
    mock_fail_message = MagicMock(name='_fail_message<mock>')
    monkeypatch.setattr(tft.artemis.middleware, '_fail_message', mock_fail_message)

    del logging_actor_arguments['logname']
    del logging_actor_arguments['contenttype']

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        logging_actor,
        logging_actor_arguments
    ) is True

    mock_fail_message.assert_called_once_with(
        ANY,
        logging_message,
        'cannot handle logging chain tail with undefined logname or contenttype'
    )


def test_handle_tails_provisioning(db, caplog, logger, provisioning_message, provisioning_actor, provisioning_actor_arguments, monkeypatch):
    mock_handle_tail = MagicMock(name='handle_provisioning_chain_tail<mock>')
    monkeypatch.setattr(tft.artemis.tasks, 'handle_provisioning_chain_tail', mock_handle_tail)

    assert tft.artemis.middleware._handle_tails(
        logger,
        provisioning_message,
        provisioning_actor,
        provisioning_actor_arguments
    ) is True

    mock_handle_tail.assert_called_once_with(
        ANY,
        db,
        ANY,
        provisioning_actor_arguments['guestname'],
        provisioning_actor,
    )

    assert_log(caplog, message='successfuly handled the provisioning tail', levelno=logging.INFO)


def test_handle_tails_logging(db, caplog, logger, logging_message, logging_actor, logging_actor_arguments, monkeypatch):
    mock_handle_tail = MagicMock(name='handle_logging_chain_tail<mock>')
    monkeypatch.setattr(tft.artemis.tasks, 'handle_logging_chain_tail', mock_handle_tail)

    assert tft.artemis.middleware._handle_tails(
        logger,
        logging_message,
        logging_actor,
        logging_actor_arguments
    ) is True

    mock_handle_tail.assert_called_once_with(
        ANY,
        db,
        ANY,
        logging_actor_arguments['guestname'],
        logging_actor_arguments['logname'],
        tft.artemis.db.GuestLogContentType(logging_actor_arguments['contenttype']),
        logging_actor,
    )

    assert_log(caplog, message='successfuly handled the logging tail', levelno=logging.INFO)


def test_handle_tails_unknown(db, caplog, logger, message, actor, actor_arguments, monkeypatch):
    mock_fail_message = MagicMock(name='_fail_message<mock>')
    monkeypatch.setattr(tft.artemis.middleware, '_fail_message', mock_fail_message)

    actor_arguments['guestname'] = 'dummy-guestname'

    assert tft.artemis.middleware._handle_tails(
        logger,
        message,
        actor,
        actor_arguments
    ) is False

    mock_fail_message.assert_not_called()

    assert_log(caplog, message='failed to handle the chain tail', levelno=logging.ERROR)
