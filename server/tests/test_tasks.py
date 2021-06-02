import logging
import threading

import dramatiq
import dramatiq.brokers.stub
import gluetool.log
import gluetool.utils
import pytest
from mock import ANY, MagicMock, call

import tft.artemis
import tft.artemis.tasks

from . import MATCH, assert_log


@pytest.fixture
def server_config(logger):
    return gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger)


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

    r = tft.artemis.tasks.dispatch_task(logger, mock_fn, 79)

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

    r = tft.artemis.tasks.dispatch_task(logger, mock_fn)

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


@pytest.fixture
def task_core_args(logger, monkeypatch):
    task_logger = tft.artemis.tasks.TaskLogger(logger, 'dummy-task')

    cancel = threading.Event()

    run_doer = MagicMock(name='mock_run_doer')
    doer = MagicMock(name='mock_doer')
    doer_args = (
        MagicMock(name='mock_doer_arg1'),
        MagicMock(name='mock_doer_arg2')
    )
    doer_kwargs = {
        'kwarg1': MagicMock(name='mock_doer_kwarg1'),
        'kwarg2': MagicMock(name='mock_doer_kwarg2')
    }

    monkeypatch.setattr(tft.artemis.tasks, 'run_doer', run_doer)

    return task_logger, cancel, run_doer, doer, doer_args, doer_kwargs


def test_task_core_ok(logger, db, session, caplog, monkeypatch, task_core_args):
    task_logger, cancel, run_doer, doer, doer_args, doer_kwargs = task_core_args

    tft.artemis.tasks.task_core(
        doer,
        task_logger,
        db=db,
        session=session,
        cancel=cancel,
        doer_args=doer_args,
        doer_kwargs=doer_kwargs
    )

    run_doer.assert_has_calls([
        call(task_logger, db, session, cancel, doer, *doer_args, **doer_kwargs),
        call().is_ok.__bool__(),
        call().unwrap()
    ])

    assert_log(caplog, message='beginning', levelno=logging.INFO)
    assert_log(caplog, message='finished', levelno=logging.INFO)


def test_task_core_failure(logger, db, session, caplog, monkeypatch, task_core_args):
    task_logger, cancel, run_doer, doer, doer_args, doer_kwargs = task_core_args

    run_doer.return_value = gluetool.result.Error(tft.artemis.Failure('dummy failure'))

    with pytest.raises(Exception, match=r'message processing failed: dummy failure'):
        tft.artemis.tasks.task_core(
            doer,
            task_logger,
            db=db,
            session=session,
            cancel=cancel,
            doer_args=doer_args,
            doer_kwargs=doer_kwargs
        )

    assert_log(caplog, message='beginning', levelno=logging.INFO)


def test_task_core_raises(logger, db, session, caplog, monkeypatch, task_core_args):
    task_logger, cancel, run_doer, doer, doer_args, doer_kwargs = task_core_args

    run_doer.side_effect = ValueError('dummy exception')

    with pytest.raises(Exception, match=r'message processing failed: unhandled doer exception'):
        tft.artemis.tasks.task_core(
            doer,
            task_logger,
            db=db,
            session=session,
            cancel=cancel,
            doer_args=doer_args,
            doer_kwargs=doer_kwargs
        )

    assert_log(caplog, message='beginning', levelno=logging.INFO)
    assert_log(
        caplog,
        message=MATCH(r'(?m)failure\n\nmessage: unhandled doer exception\n(?:.*\n)+    ValueError: dummy exception'),
        levelno=logging.ERROR
    )


def test_task_core_reschedule(logger, db, session, caplog, monkeypatch, task_core_args):
    task_logger, cancel, run_doer, doer, doer_args, doer_kwargs = task_core_args

    run_doer.return_value = tft.artemis.tasks.RESCHEDULE

    with pytest.raises(Exception, match=r'message processing requested reschedule'):
        tft.artemis.tasks.task_core(
            doer,
            task_logger,
            db=db,
            doer_args=doer_args,
            doer_kwargs=doer_kwargs
        )

    assert_log(caplog, message='beginning', levelno=logging.INFO)
