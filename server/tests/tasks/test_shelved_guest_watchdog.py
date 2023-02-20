# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import threading
from typing import Iterable, Optional, Tuple, cast
from unittest.mock import MagicMock

import _pytest.logging
import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Ok

import tft.artemis
import tft.artemis.db
import tft.artemis.drivers
from tft.artemis.tasks.shelved_guest_watchdog import Workspace

from .. import SEARCH, MockPatcher, assert_log
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(logger, session, threading.Event(), 'dummy-guest')


@pytest.fixture(name='mock_entities')
def fixture_mock_entities(
) -> Tuple[tft.artemis.db.GuestRequest, tft.artemis.drivers.PoolDriver, tft.artemis.db.SSHKey]:
    return (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            poolname='dummy-pool',
            ssh_keyname='dummy-key'
        )),
        cast(tft.artemis.drivers.PoolDriver, MagicMock(
            spec=tft.artemis.drivers.PoolDriver,
            poolname='dummy-pool',
            ssh_options='dummy-options',
            cli_error_cause_extractor=cast(tft.artemis.drivers.CLIErrorCauseExtractor, MagicMock())
        )),
        cast(tft.artemis.db.SSHKey, MagicMock(spec=tft.artemis.db.SSHKey, keyname='dummy-key'))
    )


def test_entry(workspace: Workspace, mockpatch: MockPatcher) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_guest_request')
    mockpatch(workspace, 'load_gr_pool')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest',
        state=tft.artemis.guest.GuestState.SHELVED
    )
    cast(MagicMock, workspace.load_gr_pool).assert_called_once_with()


@pytest.mark.parametrize('gr, result, log_messages', [
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(spec=tft.artemis.db.GuestRequest, skip_prepare_verify_ssh=True)),
        tft.artemis.tasks.SUCCESS,
        [('SSH ping is disabled, watchdog will not continue', logging.WARN)]
    ),
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(spec=tft.artemis.db.GuestRequest, skip_prepare_verify_ssh=False)),
        None,
        []
    )
])
def test_end_if_ssh_disabled(
    workspace: Workspace,
    caplog: _pytest.logging.LogCaptureFixture,
    gr: tft.artemis.db.GuestRequest,
    result: Optional[tft.artemis.tasks.DoerReturnType],
    log_messages: Iterable[Tuple[str, int]]
) -> None:
    workspace.gr = gr

    assert workspace.end_if_ssh_disabled() is workspace
    assert workspace.result is result

    for message, level in log_messages:
        assert_log(caplog, message=SEARCH(message), levelno=logging.WARN)


def test_load_ssh_timeout(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.tasks.shelved_guest_watchdog.KNOB_SHELVED_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT, 'get_value') \
        .return_value = Ok(12)
    workspace.pool = cast(
        tft.artemis.drivers.PoolDriver,
        MagicMock(spec=tft.artemis.drivers.PoolDriver, poolname='dummypool')
    )

    assert workspace.load_ssh_timeout() is workspace
    assert workspace.result is None

    assert workspace.ssh_connect_timeout == 12


def test_run_watchdog(
    workspace: Workspace,
    mock_entities: Tuple[tft.artemis.db.GuestRequest, tft.artemis.drivers.PoolDriver, tft.artemis.db.SSHKey],
    mockpatch: MockPatcher
) -> None:
    mock_gr, mock_pool, mock_sshkey = mock_entities

    workspace.gr = mock_gr
    workspace.pool = mock_pool
    workspace.master_key = mock_sshkey
    workspace.ssh_connect_timeout = 13
    mock_ping_shell = mockpatch(tft.artemis.tasks.shelved_guest_watchdog, 'ping_shell_remote')
    mock_ping_shell.return_value = Ok(True)

    assert workspace.run_watchdog() is workspace
    assert workspace.result is None

    mock_ping_shell.assert_called_once_with(
        workspace.logger,
        mock_gr,
        key=mock_sshkey,
        ssh_timeout=13,
        ssh_options=mock_pool.ssh_options,
        poolname=mock_pool.poolname,
        commandname=f'{Workspace.TASKNAME}.shell-ping',
        cause_extractor=mock_pool.cli_error_cause_extractor
    )


def test_schedule_followup(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    tft.artemis.tasks.shelved_guest_watchdog.KNOB_SHELVED_GUEST_WATCHDOG_DISPATCH_PERIOD.value = 14
    mockpatch(workspace, 'dispatch_task')

    assert workspace.schedule_followup() is workspace
    assert workspace.result is None

    cast(MagicMock, workspace.dispatch_task).assert_called_once_with(
        tft.artemis.tasks.shelved_guest_watchdog.shelved_guest_watchdog,
        'dummy-guest',
        delay=14
    )


def test_exit(
    workspace: Workspace
) -> None:
    assert workspace.exit() is workspace

    assert workspace.result is tft.artemis.tasks.SUCCESS


def test_doer(
    mockpatch: MockPatcher,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> None:
    mockpatch(Workspace, 'entry')

    result = Workspace.shelved_guest_watchdog(logger, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'end_if_ssh_disabled()',
        'load_ssh_timeout()',
        'run_watchdog()',
        'dispatch_release()',
        'schedule_followup()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.shelved_guest_watchdog, 'task_core')

    tail_handler = tft.artemis.tasks.shelved_guest_watchdog.shelved_guest_watchdog.options['tail_handler']

    assert isinstance(tail_handler, tft.artemis.tasks.ProvisioningTailHandler)
    assert tail_handler.current_state == tft.artemis.guest.GuestState.READY
    assert tail_handler.new_state == tft.artemis.guest.GuestState.ERROR

    tft.artemis.tasks.shelved_guest_watchdog.shelved_guest_watchdog('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        Workspace.TASKNAME,
        cast(tft.artemis.tasks.DoerType, Workspace.shelved_guest_watchdog),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
