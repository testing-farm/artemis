import logging
import threading
from typing import Dict, Generator, Tuple, cast

import _pytest.logging
import _pytest.monkeypatch
import dramatiq
import dramatiq.brokers.stub
import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy.orm.session
from dramatiq.broker import Broker
from mock import MagicMock, call

import tft.artemis
import tft.artemis.db
import tft.artemis.tasks

from . import MATCH, assert_log


@pytest.fixture
def server_config(logger: gluetool.log.ContextAdapter) -> tft.artemis.JSONType:
    return cast(tft.artemis.JSONType, gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger))


@pytest.fixture
def cancel() -> threading.Event:
    return threading.Event()


@pytest.fixture
def broker() -> dramatiq.broker.Broker:
    broker = dramatiq.get_broker()
    broker.flush_all()

    return broker


@pytest.fixture
def worker(broker: Broker) -> Generator[dramatiq.Worker, None, None]:
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()

    yield worker

    worker.stop()


def test_run_doer(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    cancel: threading.Event
) -> None:
    def foo(
        _logger: gluetool.log.ContextAdapter,
        _db: tft.artemis.db.DB,
        _session: sqlalchemy.orm.session.Session,
        _cancel: threading.Event,
        bar: int
    ) -> tft.artemis.tasks.DoerReturnType:
        assert bar == 79

        return tft.artemis.tasks.RESCHEDULE

    with db.get_session() as session:
        assert tft.artemis.tasks.run_doer(
            logger,
            db,
            session,
            cancel,
            cast(tft.artemis.tasks.DoerType, foo),
            'test_run_doer',
            79
        ) == tft.artemis.tasks.RESCHEDULE


def test_run_doer_exception(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    cancel: threading.Event
) -> None:
    def foo(
        _logger: gluetool.log.ContextAdapter,
        _db: tft.artemis.db.DB,
        _session: sqlalchemy.orm.session.Session,
        _cancel: threading.Event
    ) -> tft.artemis.tasks.DoerReturnType:
        raise Exception('foo')

    with db.get_session() as session:
        with pytest.raises(Exception, match=r'foo'):
            tft.artemis.tasks.run_doer(
                logger,
                db,
                session,
                cancel,
                cast(tft.artemis.tasks.DoerType, foo),
                'test_run_doer_exception'
            )


def test_dispatch_task(
    logger: gluetool.log.ContextAdapter,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    mock_safe_call = MagicMock(return_value=gluetool.result.Ok(79))
    mock_fn = MagicMock()

    monkeypatch.setattr(tft.artemis.tasks, 'safe_call', mock_safe_call)

    r = tft.artemis.tasks.dispatch_task(logger, mock_fn, 79)

    assert r.is_ok
    mock_safe_call.assert_called_once_with(mock_fn.send, 79)


def test_dispatcher_task_exception(
    logger: gluetool.log.ContextAdapter,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
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

TaskCoreArgsType = Tuple[
    tft.artemis.tasks.TaskLogger,
    threading.Event,
    MagicMock,
    MagicMock,
    Tuple[MagicMock, MagicMock],
    Dict[str, MagicMock]
]


@pytest.fixture
def task_core_args(
    logger: gluetool.log.ContextAdapter,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> TaskCoreArgsType:
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


def test_task_core_ok(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    task_core_args: TaskCoreArgsType
) -> None:
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
        call(task_logger, db, session, cancel, doer, 'test_task_core_ok', *doer_args, **doer_kwargs),
        call().is_ok.__bool__(),
        call().unwrap()
    ])

    assert_log(caplog, message='beginning', levelno=logging.INFO)
    assert_log(caplog, message='finished', levelno=logging.INFO)


def test_task_core_failure(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    task_core_args: TaskCoreArgsType
) -> None:
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


def test_task_core_raises(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    task_core_args: TaskCoreArgsType
) -> None:
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


def test_task_core_reschedule(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    task_core_args: TaskCoreArgsType
) -> None:
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
