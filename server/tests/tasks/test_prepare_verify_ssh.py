# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import cast
from unittest.mock import MagicMock

import dramatiq
import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Error, Ok

import tft.artemis
import tft.artemis.db
import tft.artemis.guest
import tft.artemis.tasks
import tft.artemis.tasks.prepare_verify_ssh
from tft.artemis.tasks.prepare_verify_ssh import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy
) -> Workspace:
    return Workspace.create(logger, db, session, threading.Event(), 'dummy-guest-name')


def test_entry(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_guest_request')
    mockpatch(workspace, 'load_gr_pool')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest-name',
        state=tft.artemis.guest.GuestState.PREPARING
    )
    cast(MagicMock, workspace.load_gr_pool).assert_called_once_with()


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_load_ssh_timeout(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.tasks.prepare_verify_ssh.KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT, 'get_value') \
        .return_value = Ok(79)

    assert workspace.pool is not None
    assert workspace.load_ssh_timeout() is workspace

    assert workspace.ssh_connect_timeout == 79

    cast(MagicMock, tft.artemis.tasks.prepare_verify_ssh.KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value) \
        .assert_called_once_with(session=workspace.session, poolname=workspace.pool.poolname)


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_load_ssh_timeout_error(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_failure = tft.artemis.Failure('dummy failure')

    mockpatch(tft.artemis.tasks.prepare_verify_ssh.KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT, 'get_value') \
        .return_value = Error(mock_failure)

    assert workspace.load_ssh_timeout() is workspace

    assert workspace.result is not None
    assert workspace.result.is_error
    assert workspace.result.unwrap_error() is mock_failure


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool', 'dummy_master_key')
def test_ping(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mockpatch(tft.artemis.tasks.prepare_verify_ssh, 'ping_shell_remote').return_value = Ok(None)
    workspace.ssh_connect_timeout = MagicMock(name='dummy-ssh-connect-timeout')

    assert workspace.ping() is workspace

    cast(
        MagicMock,
        tft.artemis.tasks.prepare_verify_ssh.ping_shell_remote  # type: ignore[attr-defined]
    ).assert_called_once_with(
        workspace.logger,
        workspace.gr,
        key=workspace.master_key,
        ssh_timeout=workspace.ssh_connect_timeout,
        ssh_options=workspace.pool.ssh_options,
        poolname=workspace.pool.poolname,
        commandname='prepare-verify-ssh.shell-ping',
        cause_extractor=workspace.pool.cli_error_cause_extractor
    )


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool', 'dummy_master_key')
def test_ping_error(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mock_failure = tft.artemis.Failure('dummy failure')

    mockpatch(tft.artemis.tasks.prepare_verify_ssh, 'ping_shell_remote').return_value = Error(mock_failure)
    workspace.ssh_connect_timeout = MagicMock(name='dummy-ssh-connect-timeout')

    assert workspace.ping() is workspace

    cast(
        MagicMock,
        tft.artemis.tasks.prepare_verify_ssh.ping_shell_remote  # type: ignore[attr-defined]
    ).assert_called_once_with(
        workspace.logger,
        workspace.gr,
        key=workspace.master_key,
        ssh_timeout=workspace.ssh_connect_timeout,
        ssh_options=workspace.pool.ssh_options,
        poolname=workspace.pool.poolname,
        commandname='prepare-verify-ssh.shell-ping',
        cause_extractor=workspace.pool.cli_error_cause_extractor
    )

    assert workspace.result is not None
    assert workspace.result.is_error

    failure = workspace.result.unwrap_error()

    assert failure.message == 'failed to verify SSH'
    assert failure.caused_by is mock_failure


def test_exit(
    workspace: Workspace
) -> None:
    assert workspace.exit() is workspace
    assert workspace.result is tft.artemis.tasks.SUCCESS


def test_doer(
    mockpatch: MockPatcher,
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> None:
    mockpatch(Workspace, 'entry')

    result = Workspace.prepare_verify_ssh(logger, db, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'mark_note_poolname()',
        'load_ssh_timeout()',
        'load_master_ssh_key()',
        'ping()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.prepare_verify_ssh, 'task_core')

    tail_handler = tft.artemis.tasks.prepare_verify_ssh.prepare_verify_ssh.options['tail_handler']

    assert isinstance(tail_handler, tft.artemis.tasks.ProvisioningTailHandler)
    assert tail_handler.current_state == tft.artemis.guest.GuestState.PREPARING
    assert tail_handler.new_state == tft.artemis.guest.GuestState.ROUTING

    tft.artemis.tasks.prepare_verify_ssh.prepare_verify_ssh('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        'prepare-verify-ssh',
        cast(tft.artemis.tasks.DoerType, Workspace.prepare_verify_ssh),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
