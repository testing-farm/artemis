import pytest
import gluetool.log
import gluetool.utils

from mock import MagicMock

import artemis
import artemis.tasks
import dramatiq
import dramatiq.brokers.stub


@pytest.fixture
def logger():
    return gluetool.log.Logging.get_logger()


@pytest.fixture
def server_config(logger):
    return gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger)


@pytest.fixture
def db(logger, monkeypatch, server_config):
    monkeypatch.setenv('ARTEMIS_DB_URL', 'sqlite://')

    return artemis.get_db(logger, server_config)


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


def test_run_doer(logger):
    async def do(foo):
        return foo

    assert artemis.tasks.run_doer(logger, do, 79) == 79


def test_run_doer_exception(logger):
    async def do():
        raise Exception('foo')

    with pytest.raises(Exception, match=r'foo'):
        assert artemis.tasks.run_doer(logger, do) == 79


def test_dispatch_task(logger, monkeypatch):
    mock_safe_call = MagicMock(return_value=gluetool.result.Ok(79))
    mock_fn = MagicMock()

    monkeypatch.setattr(artemis.tasks, 'safe_call', mock_safe_call)

    r = artemis.tasks._dispatch_task(logger, mock_fn, 79)

    assert r.is_ok
    mock_safe_call.assert_called_once_with(mock_fn.send, 79)


def test_dispatcher_task_exception(logger, monkeypatch):
    mock_safe_call = MagicMock(return_value=gluetool.result.Error(79))
    mock_fn = MagicMock()

    monkeypatch.setattr(artemis.tasks, 'safe_call', mock_safe_call)

    r = artemis.tasks._dispatch_task(logger, mock_fn)

    assert r.is_error
    assert r.error == 79
    mock_safe_call.assert_called_once_with(mock_fn.send)


# def test_foo(db, broker, worker):
#     with db.get_session() as session:
#         print(session.query(artemis.db.Guest).all())
#
#    artemis.tasks.foo_task.send()
#
#    broker.join(artemis.tasks.foo_task.queue_name, fail_fast=True, timeout=5000)
#    worker.join()
#
#    with db.get_session() as session:
#        print(session.query(artemis.db.Guest).all())
#
#    assert False
