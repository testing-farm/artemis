# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
from typing import Any, cast
from unittest.mock import MagicMock, mock_open, patch

import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok

import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.environment
import tft.artemis.guest
import tft.artemis.tasks.prepare_kickstart as prepare_kickstart_mod
from tft.artemis.db import GuestLog, GuestLogState, GuestRequest, SafeQuery, TaskRequest
from tft.artemis.drivers import CLIOutput
from tft.artemis.guest import GuestState
from tft.artemis.tasks import SUCCESS
from tft.artemis.tasks.prepare_kickstart import KS_LOGNAME, Workspace

from .. import MockPatcher


def _create_process_output(stdout: str = '', stderr: str = '', exit_code: int = 0) -> gluetool.utils.ProcessOutput:
    return gluetool.utils.ProcessOutput(
        command=['dummy'],
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.fixture
def kickstart_mocks(mockpatch: MockPatcher) -> dict[str, MagicMock]:
    """
    Set up common mocks required for prepare-kickstart execution.
    """

    # 1. Mock remote file fetch (populate a dummy repo file into local destination)
    def mock_copy_from_remote(logger: Any, gr: Any, pattern: str, dst: str, **kwargs: Any) -> Ok[None]:
        if 'yum.repos.d' in pattern:
            os.makedirs(dst, exist_ok=True)
            with open(os.path.join(dst, 'test.repo'), 'w') as f:
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

    with patch('builtins.open', mock_open(read_data='dummy template content')):
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

    with patch('builtins.open', mock_open(read_data='dummy template content')):
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

    with patch('builtins.open', mock_open(read_data='dummy template content')):
        res = Workspace.prepare_kickstart(logger, db, session, 'dummy-guest')

    assert res.is_error
    assert res.unwrap_error().message == 'failed to run the installer'

    with db.get_session(logger) as new_session:
        r_tasks = SafeQuery.from_session(new_session, TaskRequest).all()
        assert r_tasks.is_ok
        assert len(list(r_tasks.unwrap())) == 0
