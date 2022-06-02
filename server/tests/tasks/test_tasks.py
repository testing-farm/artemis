# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import threading
from typing import Dict, Tuple, cast
from unittest.mock import MagicMock, call

import _pytest.logging
import _pytest.monkeypatch
import dramatiq
import dramatiq.brokers.stub
import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy.orm.session

import tft.artemis
import tft.artemis.db
import tft.artemis.guest
import tft.artemis.middleware
import tft.artemis.tasks
import tft.artemis.tasks.route_guest_request

from .. import MATCH, SEARCH, MockPatcher, assert_log


@pytest.fixture
def server_config(logger: gluetool.log.ContextAdapter) -> tft.artemis.JSONType:
    return cast(tft.artemis.JSONType, gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger))


@pytest.fixture
def cancel() -> threading.Event:
    return threading.Event()


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
        bar: str
    ) -> tft.artemis.tasks.DoerReturnType:
        assert bar == '79'

        return tft.artemis.tasks.RESCHEDULE

    with db.get_session() as session:
        assert tft.artemis.tasks.run_doer(
            logger,
            db,
            session,
            cancel,
            cast(tft.artemis.tasks.DoerType, foo),
            'test_run_doer',
            '79'
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
    mockpatch: MockPatcher
) -> None:
    mock_fn = MagicMock()

    mockpatch(tft.artemis.tasks, 'safe_call').return_value = gluetool.result.Ok(79)

    r = tft.artemis.tasks.dispatch_task(logger, mock_fn, '79')

    assert r.is_ok
    cast(MagicMock, tft.artemis.tasks.safe_call).assert_called_once_with(  # type: ignore[attr-defined]
        mock_fn.send,
        '79'
    )


def test_dispatcher_task_exception(
    logger: gluetool.log.ContextAdapter,
    mockpatch: MockPatcher
) -> None:
    mock_fn = MagicMock(
        __str__=lambda x: 'dummy_task'
    )

    mockpatch(tft.artemis.tasks, 'safe_call').return_value = gluetool.result.Error(
        tft.artemis.Failure('dummy failure')
    )

    r = tft.artemis.tasks.dispatch_task(logger, mock_fn)

    assert r.is_error
    assert isinstance(r.error, tft.artemis.Failure)
    assert r.error.message == 'failed to dispatch task'
    cast(MagicMock, tft.artemis.tasks.safe_call).assert_called_once_with(mock_fn.send)  # type: ignore[attr-defined]


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
    mockpatch: MockPatcher
) -> TaskCoreArgsType:
    task_logger = tft.artemis.tasks.TaskLogger(logger, 'dummy-task')

    cancel = threading.Event()

    run_doer = mockpatch(tft.artemis.tasks, 'run_doer')
    doer = MagicMock(name='mock_doer')
    doer_args = (
        MagicMock(name='mock_doer_arg1'),
        MagicMock(name='mock_doer_arg2')
    )
    doer_kwargs = {
        'kwarg1': MagicMock(name='mock_doer_kwarg1'),
        'kwarg2': MagicMock(name='mock_doer_kwarg2')
    }

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


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy
) -> tft.artemis.tasks.Workspace:
    return tft.artemis.tasks.Workspace(
        logger,
        session,
        threading.Event(),
        'dummy-guest',
        db=db
    )


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_mark_note_poolname(
    mockpatch: MockPatcher,
    workspace: tft.artemis.tasks.Workspace
) -> None:
    assert workspace.gr

    mockpatch(tft.artemis.middleware, 'set_message_note')

    assert workspace.mark_note_poolname() is workspace

    cast(MagicMock, tft.artemis.middleware.set_message_note).assert_called_once_with(
        tft.artemis.middleware.NOTE_POOLNAME,
        workspace.gr.poolname
    )

    assert workspace.spice_details['poolname'] == workspace.gr.poolname


def test_mark_note_poolname_error_noop(
    mockpatch: MockPatcher,
    workspace: tft.artemis.tasks.Workspace
) -> None:
    workspace.result = tft.artemis.tasks.RESCHEDULE

    mockpatch(tft.artemis.middleware, 'set_message_note')

    assert workspace.mark_note_poolname() is workspace

    cast(MagicMock, tft.artemis.middleware.set_message_note).assert_not_called()


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_update_guest_state_and_request_task(
    #    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    workspace: tft.artemis.tasks.Workspace,
    caplog: _pytest.logging.LogCaptureFixture,
    mockpatch: MockPatcher
) -> None:
    assert workspace.update_guest_state_and_request_task(
        tft.artemis.guest.GuestState.PROVISIONING,
        tft.artemis.tasks.acquire_guest_request,
        'dummy-guest',
        'dummy-pool-name',
        delay=79,
        current_state=tft.artemis.guest.GuestState.ROUTING,
        set_values={
            'poolname': 'dummy-pool-name'
        },
        poolname='dummy-pool-name'
    ) is workspace

    assert workspace.result is None

    assert_log(caplog, message=SEARCH(r'state switch: routing => provisioning'), levelno=logging.INFO)
    assert_log(caplog, message=SEARCH(r'state switched routing => provisioning'), levelno=logging.INFO)
    assert_log(
        caplog,
        message=SEARCH(r'requested task #1 acquire_guest_request\(dummy-guest, dummy-pool-name, delay=79\)'),
        levelno=logging.INFO
    )

    with db.get_session() as new_session:
        r_tasks = tft.artemis.db.SafeQuery \
            .from_session(new_session, tft.artemis.db.TaskRequest) \
            .all()

        assert r_tasks.is_ok

        tasks = [task for task in r_tasks.unwrap()]

        assert len(tasks) == 1

        task = tasks[0]

        assert task.id == 1
        assert task.taskname == 'acquire_guest_request'
        assert task.arguments == ['dummy-guest', 'dummy-pool-name']
        assert task.delay == 79

        r_guests = tft.artemis.db.SafeQuery \
            .from_session(new_session, tft.artemis.db.GuestRequest) \
            .all()

        assert r_guests.is_ok

        guests = [guest for guest in r_guests.unwrap()]

        assert len(guests) == 1

        guest = guests[0]

        assert guest.poolname == 'dummy-pool-name'
        assert guest.state == tft.artemis.guest.GuestState.PROVISIONING  # type: ignore[comparison-overlap]


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_update_guest_state_and_request_task_no_such_guest(
    #    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    workspace: tft.artemis.tasks.Workspace,
    caplog: _pytest.logging.LogCaptureFixture,
    mockpatch: MockPatcher
) -> None:
    workspace.guestname = 'not-so-dummy-guest'

    assert workspace.update_guest_state_and_request_task(
        tft.artemis.guest.GuestState.PROVISIONING,
        tft.artemis.tasks.acquire_guest_request,
        'not-so-dummy-guest',
        'dummy-pool-name',
        delay=79,
        current_state=tft.artemis.guest.GuestState.ROUTING,
        set_values={
            'poolname': 'dummy-pool-name'
        },
        poolname='dummy-pool-name'
    ) is workspace

    assert workspace.result is not None
    assert workspace.result.is_error

    failure = workspace.result.unwrap_error()

    assert failure.message == 'failed to switch guest state'
    assert failure.details['current_state'] == 'routing'
    assert failure.details['new_state'] == 'provisioning'
    assert failure.details['task_name'] == 'acquire_guest_request'
    assert failure.details['task_args'] == ('not-so-dummy-guest', 'dummy-pool-name')
    assert failure.details['poolname'] == 'dummy-pool-name'
    assert failure.details['guestname'] == 'not-so-dummy-guest'
    assert failure.recoverable is True

    assert failure.caused_by is not None

    assert failure.caused_by.message == 'unexpected number of affected rows'
    assert failure.caused_by.details['affected_rows'] == 0
    assert failure.caused_by.details['expected_affected_rows'] == 1
    assert failure.caused_by.details['statement'].startswith('UPDATE')

    assert_log(caplog, message=SEARCH(r'state switch: routing => provisioning'), levelno=logging.INFO)
    # assert_log(caplog, message=SEARCH(r'state switched routing => provisioning'), levelno=logging.INFO)
    # assert_log(
    #    caplog,
    #    message=SEARCH(r'requested task #1 acquire_guest_request\(dummy-guest, dummy-pool-name, delay=79\)'),
    #    levelno=logging.INFO
    # )

    with db.get_session() as new_session:
        r_tasks = tft.artemis.db.SafeQuery \
            .from_session(new_session, tft.artemis.db.TaskRequest) \
            .all()

        assert r_tasks.is_ok

        tasks = [task for task in r_tasks.unwrap()]

        assert not tasks

        r_guests = tft.artemis.db.SafeQuery \
            .from_session(new_session, tft.artemis.db.GuestRequest) \
            .all()

        assert r_guests.is_ok

        guests = [guest for guest in r_guests.unwrap()]

        assert len(guests) == 1

        guest = guests[0]

        assert guest.poolname is None
        assert guest.state == tft.artemis.guest.GuestState.ROUTING  # type: ignore[comparison-overlap]
