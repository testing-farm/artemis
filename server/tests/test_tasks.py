import pytest
import threading
import gluetool.log
import gluetool.utils

from mock import MagicMock

import tft.artemis
import tft.artemis.tasks
import dramatiq
import dramatiq.brokers.stub


@pytest.fixture
def logger():
    return gluetool.log.Logging.get_logger()


@pytest.fixture
def server_config(logger):
    return gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger)


@pytest.fixture
def db(logger, monkeypatch):
    monkeypatch.setenv('ARTEMIS_DB_URL', 'sqlite://')

    return tft.artemis.get_db(logger)


@pytest.fixture
def cancel():
    return threading.Event()


@pytest.fixture
def broker():
    broker = dramatiq.get_broker()
    broker.flush_all()

    return broker


@pytest.fixture
def worker(broker):
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()

    yield worker

    worker.stop()


def test_run_doer(logger, db, cancel):
    def foo(_logger, _db, _session, _cancel, bar):
        return bar

    with db.get_session() as session:
        assert tft.artemis.tasks.run_doer(logger, db, session, cancel, foo, 79) == 79


def test_run_doer_exception(logger, db, cancel):
    def foo(_logger, _db, _session, _cancel):
        raise Exception('foo')

    with db.get_session() as session:
        with pytest.raises(Exception, match=r'foo'):
            assert tft.artemis.tasks.run_doer(logger, db, session, cancel, foo) == 79


def test_dispatch_task(logger, monkeypatch):
    mock_safe_call = MagicMock(return_value=gluetool.result.Ok(79))
    mock_fn = MagicMock()

    monkeypatch.setattr(tft.artemis.tasks, 'safe_call', mock_safe_call)

    r = tft.artemis.tasks._dispatch_task(logger, mock_fn, 79)

    assert r.is_ok
    mock_safe_call.assert_called_once_with(mock_fn.send, 79)


def test_dispatcher_task_exception(logger, monkeypatch):
    mock_safe_call = MagicMock(
        return_value=gluetool.result.Error(
            tft.artemis.Failure('dummy failure')
        )
    )

    mock_fn = MagicMock(
        __str__=lambda x: 'dummy_task'
    )

    monkeypatch.setattr(tft.artemis.tasks, 'safe_call', mock_safe_call)

    r = tft.artemis.tasks._dispatch_task(logger, mock_fn)

    assert r.is_error
    assert isinstance(r.error, tft.artemis.Failure)
    assert r.error.message == 'failed to dispatch task'
    mock_safe_call.assert_called_once_with(mock_fn.send)


# def test_foo(db, broker, worker):
#     with db.get_session() as session:
#         print(session.query(tft.artemis.db.Guest).all())
#
#    tft.artemis.tasks.foo_task.send()
#
#    broker.join(tft.artemis.tasks.foo_task.queue_name, fail_fast=True, timeout=5000)
#    worker.join()
#
#    with db.get_session() as session:
#        print(session.query(tft.artemis.db.Guest).all())
#
#    assert False
