# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import Any, List, cast
from unittest.mock import MagicMock

import dramatiq
import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Error, Ok

import tft.artemis
import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.guest
import tft.artemis.routing_policies
import tft.artemis.tasks
import tft.artemis.tasks.update_guest_request
from tft.artemis.api import GuestRequest
from tft.artemis.middleware import NOTE_POOLNAME, get_metric_note
from tft.artemis.tasks.update_guest_request import Workspace, update_guest_request

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


@pytest.fixture(name='dummy_guest_request')
def fixture_dummy_guest_request(workspace: Workspace) -> MagicMock:
    workspace.gr = MagicMock(name='dummy-guest-request')

    return workspace.gr


@pytest.fixture(name='dummy_pool')
def fixture_dummy_pool(
    logger: gluetool.log.ContextAdapter,
    workspace: Workspace,
    dummy_guest_request: GuestRequest
) -> tft.artemis.drivers.PoolDriver:
    assert workspace.gr

    workspace.gr.poolname = 'dummy-pool'
    workspace.pool = tft.artemis.drivers.PoolDriver(logger, 'dummy-pool', {})

    return workspace.pool


@pytest.fixture(name='dummy_current_pool_data')
def fixture_dummy_current_pool_data(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> tft.artemis.drivers.PoolData:
    workspace.current_pool_data = tft.artemis.drivers.PoolData()

    mockpatch(workspace.current_pool_data, 'serialize').return_value = MagicMock(name='current_pool_data.serialize()')

    return workspace.current_pool_data


@pytest.fixture(name='complete_provisioning_progress')
def fixture_complete_provisioning_progress(workspace: Workspace) -> tft.artemis.drivers.ProvisioningProgress:
    workspace.provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.COMPLETE,
        pool_data=tft.artemis.drivers.PoolData(),
        delay_update=MagicMock()
    )

    return workspace.provisioning_progress


@pytest.fixture(name='pending_provisioning_progress')
def fixture_pending_provisioning_progress(workspace: Workspace) -> tft.artemis.drivers.ProvisioningProgress:
    workspace.provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.PENDING,
        pool_data=tft.artemis.drivers.PoolData(),
        delay_update=MagicMock()
    )

    return workspace.provisioning_progress


@pytest.fixture(name='cancel_provisioning_progress')
def fixture_cancel_provisioning_progress(workspace: Workspace) -> tft.artemis.drivers.ProvisioningProgress:
    workspace.provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.CANCEL,
        pool_data=tft.artemis.drivers.PoolData(),
        delay_update=MagicMock()
    )

    return workspace.provisioning_progress


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
        state=tft.artemis.guest.GuestState.PROMISED
    )
    cast(MagicMock, workspace.load_gr_pool).assert_called_once_with()


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_save_current_data(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mockpatch(workspace.pool.pool_data_class, 'unserialize').return_value = MagicMock(name='pool_data<mock>')

    assert workspace.save_current_data() is workspace

    assert get_metric_note(NOTE_POOLNAME) == 'dummy-pool'

    assert workspace.spice_details['poolname'] == 'dummy-pool'
    assert workspace.current_pool_data is cast(MagicMock, workspace.pool.pool_data_class.unserialize).return_value


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_query_driver(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mock_provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.COMPLETE,
        pool_data=tft.artemis.drivers.PoolData()
    )

    mockpatch(workspace.pool, 'update_guest').return_value = Ok(mock_provisioning_progress)

    assert workspace.query_driver() is workspace

    cast(MagicMock, workspace.pool.update_guest).assert_called_once_with(
        workspace.logger, workspace.session, workspace.gr
    )

    assert workspace.provisioning_progress is mock_provisioning_progress
    assert workspace.new_guest_data == {
        'pool_data': mock_provisioning_progress.pool_data.serialize()
    }


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_query_driver_propagate_ssh_info(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mock_provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.COMPLETE,
        pool_data=tft.artemis.drivers.PoolData(),
        ssh_info=tft.artemis.drivers.PoolImageSSHInfo(
            username='dummy-user',
            port=79
        )
    )

    mockpatch(workspace.pool, 'update_guest').return_value = Ok(mock_provisioning_progress)

    assert workspace.query_driver() is workspace

    cast(MagicMock, workspace.pool.update_guest).assert_called_once_with(
        workspace.logger, workspace.session, workspace.gr
    )

    assert workspace.provisioning_progress is mock_provisioning_progress
    assert workspace.new_guest_data == {
        'pool_data': mock_provisioning_progress.pool_data.serialize(),
        'ssh_username': 'dummy-user',
        'ssh_port': 79
    }


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_query_driver_propagate_address(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mock_provisioning_progress = tft.artemis.drivers.ProvisioningProgress(
        state=tft.artemis.drivers.ProvisioningState.COMPLETE,
        pool_data=tft.artemis.drivers.PoolData(),
        address='dummy-address'
    )

    mockpatch(workspace.pool, 'update_guest').return_value = Ok(mock_provisioning_progress)

    assert workspace.query_driver() is workspace

    cast(MagicMock, workspace.pool.update_guest).assert_called_once_with(
        workspace.logger, workspace.session, workspace.gr
    )

    assert workspace.provisioning_progress is mock_provisioning_progress
    assert workspace.new_guest_data == {
        'pool_data': mock_provisioning_progress.pool_data.serialize(),
        'address': 'dummy-address'
    }


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_query_driver_fail(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    assert workspace.pool

    mock_failure = tft.artemis.Failure('dummy failure')
    mock_error: tft.artemis.tasks.DoerReturnType = Error(mock_failure)

    mockpatch(workspace.pool, 'update_guest').return_value = mock_error

    mockpatch(workspace, 'handle_error').return_value = Error(mock_failure)

    assert workspace.query_driver() is workspace

    cast(MagicMock, workspace.pool.update_guest).assert_called_once_with(
        workspace.logger, workspace.session, workspace.gr
    )

    cast(MagicMock, workspace.handle_error).assert_called_once_with(mock_error, 'failed to update guest')

    assert workspace.result is not None
    assert workspace.result.is_error
    assert workspace.result.unwrap_error() is mock_failure


@pytest.mark.usefixtures('pending_provisioning_progress')
def test_log_minor_failures(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_failures = [MagicMock(), MagicMock()]

    workspace.provisioning_progress.pool_failures = cast(List[tft.artemis.Failure], mock_failures)

    mockpatch(workspace, 'handle_failure')

    assert workspace.log_minor_failures() is workspace

    for mock_failure in mock_failures:
        cast(MagicMock, workspace.handle_failure).assert_any_call(
            mock_failure,
            'pool encountered failure during update'
        )


@pytest.mark.usefixtures('dummy_guest_request', 'pending_provisioning_progress', 'dummy_current_pool_data')
def test_handle_pending(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    workspace.new_guest_data = MagicMock('new-guest-data')

    mockpatch(workspace, 'update_guest_state')

    assert workspace.handle_pending() is workspace

    cast(MagicMock, workspace.update_guest_state).assert_called_once_with(
        tft.artemis.guest.GuestState.PROMISED,
        current_state=tft.artemis.guest.GuestState.PROMISED,
        set_values=workspace.new_guest_data,
        current_pool_data=cast(MagicMock, workspace.current_pool_data.serialize).return_value
    )

    assert workspace.result is None


@pytest.mark.usefixtures('complete_provisioning_progress')
def test_handle_pending_skip(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'update_guest_state')

    assert workspace.handle_cancel() is workspace
    assert workspace.result is None
    cast(MagicMock, workspace.update_guest_state).assert_not_called()


@pytest.mark.usefixtures('dummy_guest_request', 'cancel_provisioning_progress')
def test_handle_cancel(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_tail_handler = MagicMock(
        handle_tail=MagicMock(
            return_value=True
        )
    )

    mockpatch(tft.artemis.tasks.update_guest_request, 'ProvisioningTailHandler').return_value = mock_tail_handler

    assert workspace.handle_cancel() is workspace
    assert workspace.result is tft.artemis.tasks.SUCCESS


@pytest.mark.usefixtures('complete_provisioning_progress')
def test_handle_cancel_skip(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.tasks.update_guest_request, 'ProvisioningTailHandler')

    assert workspace.handle_cancel() is workspace
    assert workspace.result is None
    cast(
        MagicMock,
        tft.artemis.tasks.update_guest_request.ProvisioningTailHandler  # type: ignore[attr-defined]
    ).assert_not_called()


@pytest.mark.usefixtures('dummy_guest_request', 'cancel_provisioning_progress')
def test_handle_fail(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_tail_handler = MagicMock(
        handle_tail=MagicMock(
            return_value=False
        )
    )

    mockpatch(tft.artemis.tasks.update_guest_request, 'ProvisioningTailHandler').return_value = mock_tail_handler

    assert workspace.handle_cancel() is workspace
    assert workspace.result is tft.artemis.tasks.RESCHEDULE


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_current_pool_data', 'complete_provisioning_progress')
def test_handle_complete(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    workspace.new_guest_data = MagicMock('new-guest-data')

    mockpatch(workspace, 'update_guest_state')

    assert workspace.handle_complete() is workspace

    cast(MagicMock, workspace.update_guest_state).assert_called_once_with(
        tft.artemis.guest.GuestState.PREPARING,
        current_state=tft.artemis.guest.GuestState.PROMISED,
        set_values=workspace.new_guest_data,
        current_pool_data=cast(MagicMock, workspace.current_pool_data.serialize).return_value
    )


@pytest.mark.usefixtures('cancel_provisioning_progress')
def test_handle_complete_skip(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.tasks.update_guest_request, 'ProvisioningTailHandler')

    assert workspace.handle_complete() is workspace
    assert workspace.result is None
    cast(
        MagicMock,
        tft.artemis.tasks.update_guest_request.ProvisioningTailHandler  # type: ignore[attr-defined]
    ).assert_not_called()


@pytest.mark.usefixtures('pending_provisioning_progress')
def test_dispatch_followup_pending(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'dispatch_task')
    mockpatch(workspace, 'ungrab_guest_request')

    assert workspace.dispatch_followup() is workspace

    cast(MagicMock, workspace.dispatch_task).assert_called_once_with(
        update_guest_request,
        workspace.guestname,
        delay=workspace.provisioning_progress.delay_update
    )

    cast(MagicMock, workspace.ungrab_guest_request).assert_not_called()


@pytest.mark.usefixtures('complete_provisioning_progress')
def test_dispatch_followup_preparing(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.tasks.update_guest_request, 'dispatch_preparing_pre_connect')
    mockpatch(workspace, 'ungrab_guest_request')

    assert workspace.dispatch_followup() is workspace

    cast(
        MagicMock,
        tft.artemis.tasks.update_guest_request.dispatch_preparing_pre_connect  # type: ignore[attr-defined]
    ).assert_called_once_with(
        workspace.logger,
        workspace
    )

    cast(MagicMock, workspace.ungrab_guest_request).assert_not_called()


@pytest.mark.usefixtures('pending_provisioning_progress')
def test_dispatch_followup_fail_dispatch(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_error: tft.artemis.tasks.DoerReturnType = Error(tft.artemis.Failure('mock error'))

    def mock_dispatch_task(*args: Any, **kwargs: Any) -> None:
        workspace.result = mock_error

    mockpatch(workspace, 'dispatch_task').side_effect = mock_dispatch_task
    mockpatch(workspace, 'ungrab_guest_request')

    assert workspace.dispatch_followup() is workspace

    cast(MagicMock, workspace.ungrab_guest_request).assert_called_once_with(
        tft.artemis.guest.GuestState.PREPARING,
        tft.artemis.guest.GuestState.PROMISED
    )


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

    result = Workspace.update_guest_request(logger, db, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'save_current_data()',
        'query_driver()',
        'log_minor_failures()',
        'handle_pending()',
        'handle_cancel()',
        'handle_complete()',
        'dispatch_followup()',
        'exit()',
        'final_result'
    ])


def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.update_guest_request, 'task_core')

    tail_handler = tft.artemis.tasks.update_guest_request.update_guest_request.options['tail_handler']

    assert isinstance(tail_handler, tft.artemis.tasks.ProvisioningTailHandler)
    assert tail_handler.current_state == tft.artemis.guest.GuestState.PROMISED
    assert tail_handler.new_state == tft.artemis.guest.GuestState.ROUTING

    tft.artemis.tasks.update_guest_request.update_guest_request('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        'update-guest-request',
        cast(tft.artemis.tasks.DoerType, Workspace.update_guest_request),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
