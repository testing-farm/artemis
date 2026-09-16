# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
from typing import Any, Generator, cast
from unittest.mock import MagicMock, mock_open, patch

import dramatiq
import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok

import tft.artemis.context
import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.environment
import tft.artemis.guest
import tft.artemis.tasks as tasks_mod
import tft.artemis.tasks.prepare_kickstart as prepare_kickstart_mod
from tft.artemis.db import GuestLog, GuestLogState, GuestRequest, SafeQuery, TaskRequest, Transaction
from tft.artemis.drivers import CLIOutput, PoolDriver
from tft.artemis.guest import GuestState
from tft.artemis.tasks import SUCCESS
from tft.artemis.tasks.prepare_kickstart import KS_LOGNAME, Workspace

from .. import MockPatcher

# Save a reference to the real ``open`` before any ``mock_open`` patches are applied.
# Used both in the ``mock_copy_from_remote`` helper (which must create real files inside a
# ``TemporaryDirectory``) and in the selective open wrapper that only intercepts the
# kickstart template path.
_real_open = open


def _selective_open_mock(*args: Any, **kwargs: Any) -> Any:
    """Intercept ``open()`` calls for the kickstart template file only;
    delegate everything else to the real ``open``.

    The template file path ends with the knob default (``artemis-kickstart.ks.j2``).
    When a test calls ``Workspace.prepare_kickstart``, the code opens this template
    and passes its content to ``render_template`` which is already mocked, so the
    content itself doesn't matter -- we just need the call not to fail."""

    path_arg = str(args[0]) if args else str(kwargs.get('file', ''))
    if 'artemis-kickstart' in path_arg:
        return mock_open(read_data='dummy template content')(*args, **kwargs)
    return _real_open(*args, **kwargs)


def _create_process_output(stdout: str = '', stderr: str = '', exit_code: int = 0) -> gluetool.utils.ProcessOutput:
    return gluetool.utils.ProcessOutput(
        cmd=['dummy'],
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        kwargs={},
    )


@pytest.fixture(autouse=True)
def _set_session_context(session: sqlalchemy.orm.session.Session) -> Generator[None, None, None]:
    """Set the SESSION context variable so that ``@with_context`` decorated helpers
    (e.g. ``_get_ssh_key``) can resolve it without a running worker."""
    token = tft.artemis.context.SESSION.set(session)
    yield
    tft.artemis.context.SESSION.reset(token)


@pytest.fixture
def kickstart_mocks(mockpatch: MockPatcher) -> dict[str, MagicMock]:
    """
    Set up common mocks required for prepare-kickstart execution.
    """

    # 0. Mock pool loading so we don't need real pool config or full context variable setup
    mock_pool = MagicMock()
    mock_pool.poolname = 'dummy-pool'
    mock_pool.ssh_options = []
    mock_pool.error_cause_extractor = None
    mockpatch(PoolDriver, 'load').return_value = Ok(mock_pool)

    # 0b. Mock SSH key lookup -- there is no ``artemis/master-key`` in the test DB
    mock_ssh_key = MagicMock(name='mock-master-key')
    mockpatch(tasks_mod, '_get_ssh_key').return_value = Ok(mock_ssh_key)

    # 1. Mock remote file fetch (populate a dummy repo file into local destination).
    def mock_copy_from_remote(logger: Any, gr: Any, pattern: str, dst: str, **kwargs: Any) -> Ok[None]:
        if 'yum.repos.d' in pattern:
            os.makedirs(dst, exist_ok=True)
            with _real_open(os.path.join(dst, 'test.repo'), 'w') as f:
                f.write('[baseos]\nname=BaseOS\nenabled=1\nbaseurl=http://example.com/repo\n')
        return Ok(None)

    mockpatch(prepare_kickstart_mod, 'copy_from_remote').side_effect = mock_copy_from_remote

    # 2. Mock compose pattern map matching
    pattern_map = MagicMock()
    pattern_map.match.return_value = 'baseos'
    mockpatch(prepare_kickstart_mod, 'get_pattern_map').return_value = Ok(pattern_map)

    # 3. Mock kickstart validator tool
    mockpatch(prepare_kickstart_mod, 'run_cli_tool').return_value = Ok(
        CLIOutput(process_output=_create_process_output(), stdout='')
    )

    # 4. Mock remote file upload
    mockpatch(prepare_kickstart_mod, 'copy_to_remote').return_value = Ok(None)

    # 5. Mock template rendering
    mockpatch(prepare_kickstart_mod, 'render_template').return_value = Ok('dummy-rendered-kickstart')

    # 6. Mock remote commands dispatcher
    def mock_run_remote(logger: Any, gr: Any, command: list[str], **kwargs: Any) -> Any:
        # Check /.ksinstall existence (initially not found)
        if command == ['/bin/ls', '/.ksinstall']:
            return Error(
                tft.artemis.Failure(
                    'file not found',
                    command_output=_create_process_output(
                        stderr="cannot access '/.ksinstall': No such file or directory", exit_code=1
                    ),
                )
            )

        # rpm package listing
        if command[0] == '/usr/bin/rpm':
            return Ok(CLIOutput(process_output=_create_process_output(), stdout='kernel.x86_64\nbash.x86_64'))

        # kexec initiation script execution
        if command[0] == '/bin/bash':
            return Ok(CLIOutput(process_output=_create_process_output(), stdout='kexec armed successfully'))

        return Ok(CLIOutput(process_output=_create_process_output(), stdout=''))

    mock_run = mockpatch(prepare_kickstart_mod, 'run_remote')
    mock_run.side_effect = mock_run_remote

    return {
        'run_remote': mock_run,
        'copy_from_remote': cast(MagicMock, prepare_kickstart_mod.copy_from_remote),
        'copy_to_remote': cast(MagicMock, prepare_kickstart_mod.copy_to_remote),
        'render_template': cast(MagicMock, prepare_kickstart_mod.render_template),
    }


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_prepare_kickstart_success(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
    kickstart_mocks: dict[str, MagicMock],
) -> None:
    """
    Test standard successful execution of prepare-kickstart:
    - Kickstart script is copied and executed via kexec.
    - Follow-up task prepare-kickstart-wait is scheduled.
    - Kickstart script log is persisted.
    """
    # Set guest state to PREPARING
    session.execute(
        sqlalchemy.update(GuestRequest)
        .where(GuestRequest.guestname == 'dummy-guest')
        .values(state=GuestState.PREPARING, poolname='dummy-pool')
    )
    session.commit()

    with patch('builtins.open', _selective_open_mock):
        res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    assert res == SUCCESS

    with db.get_session(logger) as new_session:
        # Verify prepare-kickstart-wait task request was committed
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        tasks = list(r_tasks.unwrap())
        assert len(tasks) == 1
        assert tasks[0].taskname == 'prepare_kickstart_wait'
        assert tasks[0].arguments == ['dummy-guest']

        # Verify ks.cfg:dump log was stored
        r_logs = (
            SafeQuery.from_session(new_session, GuestLog)
            .filter(GuestLog.guestname == 'dummy-guest')
            .filter(GuestLog.logname == KS_LOGNAME)
            .one_or_none()
        )
        assert r_logs.is_ok
        log = r_logs.unwrap()
        assert log is not None
        assert log.state == GuestLogState.COMPLETE


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_prepare_kickstart_log_failure_ignored(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
    kickstart_mocks: dict[str, MagicMock],
    mockpatch: MockPatcher,
) -> None:
    """
    Test TFT-5003 scenario: failure to save the kickstart log in _store_kickstart_log
    must not fail the task or drop the follow-up task request.
    """
    session.execute(
        sqlalchemy.update(GuestRequest)
        .where(GuestRequest.guestname == 'dummy-guest')
        .values(state=GuestState.PREPARING, poolname='dummy-pool')
    )
    session.commit()

    # Force log storage failure inside _store_kickstart_log
    mockpatch(GuestLog, 'create').return_value = Error(tft.artemis.Failure('simulated db log error'))

    with patch('builtins.open', _selective_open_mock):
        res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    # Task should still succeed
    assert res == SUCCESS

    with db.get_session(logger) as new_session:
        # Follow-up task MUST be scheduled and committed
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        tasks = list(r_tasks.unwrap())
        assert len(tasks) == 1
        assert tasks[0].taskname == 'prepare_kickstart_wait'
        assert tasks[0].arguments == ['dummy-guest']


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_prepare_kickstart_already_reinstalled(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
    kickstart_mocks: dict[str, MagicMock],
) -> None:
    """
    Test re-run path when the guest already has /.ksinstall present:
    - Logs 'already-reinstalled'.
    - Dispatches prepare-kickstart-wait immediately.
    """
    session.execute(
        sqlalchemy.update(GuestRequest)
        .where(GuestRequest.guestname == 'dummy-guest')
        .values(state=GuestState.PREPARING, poolname='dummy-pool')
    )
    session.commit()

    # Simulate /.ksinstall already exists on remote guest
    kickstart_mocks['run_remote'].side_effect = None
    kickstart_mocks['run_remote'].return_value = Ok(
        CLIOutput(process_output=_create_process_output(stdout='/.ksinstall'), stdout='/.ksinstall')
    )

    res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    assert res == SUCCESS

    with db.get_session(logger) as new_session:
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        tasks = list(r_tasks.unwrap())
        assert len(tasks) == 1
        assert tasks[0].taskname == 'prepare_kickstart_wait'
        assert tasks[0].arguments == ['dummy-guest']


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_prepare_kickstart_kexec_failure(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
    kickstart_mocks: dict[str, MagicMock],
) -> None:
    """
    Test kexec failure:
    - Task returns Error.
    - Follow-up task is not requested.
    """
    session.execute(
        sqlalchemy.update(GuestRequest)
        .where(GuestRequest.guestname == 'dummy-guest')
        .values(state=GuestState.PREPARING, poolname='dummy-pool')
    )
    session.commit()

    def mock_run_remote(logger: Any, gr: Any, command: list[str], **kwargs: Any) -> Any:
        if command == ['/bin/ls', '/.ksinstall']:
            return Error(
                tft.artemis.Failure(
                    'file not found',
                    command_output=_create_process_output(
                        stderr="cannot access '/.ksinstall': No such file or directory", exit_code=1
                    ),
                )
            )
        if command[0] == '/usr/bin/rpm':
            return Ok(CLIOutput(process_output=_create_process_output(), stdout='kernel.x86_64'))
        if command[0] == '/bin/bash':
            return Error(tft.artemis.Failure('kexec execution failed on guest'))
        return Ok(CLIOutput(process_output=_create_process_output(), stdout=''))

    kickstart_mocks['run_remote'].side_effect = mock_run_remote

    with patch('builtins.open', _selective_open_mock):
        res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    assert res.is_error
    assert res.unwrap_error().message == 'kexec execution failed on guest'

    with db.get_session(logger) as new_session:
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        assert len(list(r_tasks.unwrap())) == 0


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_prepare_kickstart_main_txn_abort_after_kexec(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
    kickstart_mocks: dict[str, MagicMock],
) -> None:
    """
    Test TFT-5003 core scenario: the main transaction aborts *after* kexec has been
    successfully submitted (e.g. a DB commit-time failure). The follow-up task
    ``prepare-kickstart-wait`` must still be scheduled in its own transaction, and
    the task must succeed.
    """
    session.execute(
        sqlalchemy.update(GuestRequest)
        .where(GuestRequest.guestname == 'dummy-guest')
        .values(state=GuestState.PREPARING, poolname='dummy-pool')
    )
    session.commit()

    # Patch ``Transaction._on_success`` to simulate a commit-time failure on the
    # first (main) transaction only.  The main transaction body executes normally
    # (``kexec_submitted`` is set to ``True``), but the commit fails.  Subsequent
    # transactions (follow-up task, log storage) must commit normally.
    #
    # We patch at the class level and track which ``Transaction`` instance is the
    # first one to have ``_on_success`` called.
    original_on_success = Transaction._on_success
    aborted_txn: list[Transaction] = []

    call_count = 0

    def failing_on_success(self: Transaction) -> None:
        nonlocal call_count
        call_count += 1

        # Call 1 is from ``begin()`` which logs "entered-task".
        # Call 2 is from the main ``Transaction.go`` in ``run()`` -- this is the one
        # we want to abort to simulate a commit-time failure after kexec.
        if call_count == 2:
            aborted_txn.append(self)
            from tft.artemis import Failure

            # Roll back as a real commit failure would, then mark the transaction.
            self.session.rollback()
            self.session.expunge_all()
            self.complete = False
            self.failure = Failure('simulated commit-time failure')
            return

        original_on_success(self)

    with patch('builtins.open', _selective_open_mock), \
         patch.object(Transaction, '_on_success', failing_on_success):
        res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    # Task should still succeed: the follow-up was committed in a separate transaction.
    assert res == SUCCESS

    with db.get_session(logger) as new_session:
        # Follow-up task MUST be present despite the main transaction aborting.
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        tasks = list(r_tasks.unwrap())
        assert len(tasks) == 1
        assert tasks[0].taskname == 'prepare_kickstart_wait'
        assert tasks[0].arguments == ['dummy-guest']
