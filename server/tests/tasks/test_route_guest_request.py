# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import Any, Optional, cast
from unittest.mock import MagicMock

import _pytest.logging
import _pytest.monkeypatch
import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Error

import tft.artemis
import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.guest
import tft.artemis.routing_policies
import tft.artemis.tasks
import tft.artemis.tasks.route_guest_request
from tft.artemis.tasks.route_guest_request import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace(logger, session, threading.Event(), guestname='dummy-guest-name', task='route-guest-request')


def patch(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    obj: Any,
    member_name: str,
    obj_name: Optional[str] = None
) -> MagicMock:
    mock = MagicMock(name=f'{member_name}<mock>' if obj_name is None else f'{obj_name}.{member_name}<mock>')

    monkeypatch.setattr(obj, member_name, mock)

    return mock


def test_entry(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    patch(monkeypatch, workspace, 'handle_success')
    patch(monkeypatch, workspace, 'load_guest_request')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest-name',
        state=tft.artemis.guest.GuestState.ROUTING
    )


def test_query_policies(
    workspace: Workspace,
    session: sqlalchemy.orm.session.Session,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    workspace.gr = MagicMock(name='workspace.gr<mock>')
    workspace.pools = []

    mock_ruling = tft.artemis.routing_policies.PolicyRuling()

    patch(monkeypatch, workspace, 'run_hook').return_value = mock_ruling

    assert workspace.query_policies() is workspace

    assert workspace.result is None
    assert workspace.ruling is mock_ruling

    cast(MagicMock, workspace.run_hook).assert_called_once_with(
        'ROUTE',
        session=session,
        guest_request=workspace.gr,
        pools=workspace.pools
    )


def test_evaluate_ruling(
    workspace: Workspace
) -> None:
    workspace.ruling = tft.artemis.routing_policies.PolicyRuling.from_pools([
        MagicMock(poolname='pool1'),
        MagicMock(poolname='pool2')
    ])

    assert workspace.evaluate_ruling() is workspace

    assert workspace.result is None
    assert workspace.new_pool is workspace.ruling.allowed_rulings[0].pool


@pytest.mark.usefixtures('_schema_actual')
def test_evaluate_ruling_cancel(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    patch(monkeypatch, workspace, 'handle_success').return_value = tft.artemis.tasks.SUCCESS
    patch(monkeypatch, workspace, 'update_guest_state')

    workspace.ruling = tft.artemis.routing_policies.PolicyRuling.from_pools([
        MagicMock(poolname='pool1'),
        MagicMock(poolname='pool2')
    ])
    workspace.ruling.cancel = True

    assert workspace.evaluate_ruling() is workspace

    assert workspace.result is tft.artemis.tasks.SUCCESS
    assert workspace.new_pool is None

    cast(MagicMock, workspace.update_guest_state).assert_called_once_with(
        tft.artemis.guest.GuestState.ERROR,
        current_state=tft.artemis.guest.GuestState.ROUTING
    )

    cast(MagicMock, workspace.handle_success).assert_any_call('routing-cancelled')
    cast(MagicMock, workspace.handle_success).assert_any_call('finished-task')


@pytest.mark.usefixtures('_schema_actual')
def test_evaluate_ruling_cancel_fail_state_change(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    patch(monkeypatch, workspace, 'handle_success')

    mock_error: tft.artemis.tasks.DoerReturnType = Error(tft.artemis.Failure('mock error'))

    def mock_update_guest_state(*args: Any, **kwargs: Any) -> None:
        workspace.result = mock_error

    patch(monkeypatch, workspace, 'update_guest_state').side_effect = mock_update_guest_state

    workspace.ruling = tft.artemis.routing_policies.PolicyRuling.from_pools([
        MagicMock(poolname='pool1'),
        MagicMock(poolname='pool2')
    ])
    workspace.ruling.cancel = True

    assert workspace.evaluate_ruling() is workspace

    assert workspace.result is mock_error
    assert workspace.new_pool is None

    cast(MagicMock, workspace.update_guest_state).assert_called_once_with(
        tft.artemis.guest.GuestState.ERROR,
        current_state=tft.artemis.guest.GuestState.ROUTING
    )

    cast(MagicMock, workspace.handle_success).assert_called_once_with('routing-cancelled')


def test_evaluate_ruling_empty(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    patch(monkeypatch, workspace, 'handle_success')
    patch(monkeypatch, workspace, 'update_guest_state')

    workspace.ruling = tft.artemis.routing_policies.PolicyRuling()

    assert workspace.evaluate_ruling() is workspace

    assert workspace.result is tft.artemis.tasks.RESCHEDULE
    assert workspace.new_pool is None

    cast(MagicMock, workspace.handle_success).assert_not_called()
    cast(MagicMock, workspace.update_guest_state).assert_not_called()


def test_switch_to_provisioning(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    workspace.gr = MagicMock(name='dummy-guest-request')
    workspace.new_pool = MagicMock(name='dummy-pool')

    mockpatch(workspace, 'update_guest_state_and_request_task')

    assert workspace.switch_to_provisioning() is workspace

    cast(MagicMock, workspace.update_guest_state_and_request_task).assert_called_once_with(
        tft.artemis.guest.GuestState.PROVISIONING,
        tft.artemis.tasks.acquire_guest_request,
        workspace.guestname,
        workspace.new_pool.poolname,
        current_state=tft.artemis.guest.GuestState.ROUTING,
        set_values={
            'poolname': workspace.new_pool.poolname
        },
        poolname=workspace.new_pool.poolname
    )


def test_exit(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    patch(
        monkeypatch,
        tft.artemis.tasks.route_guest_request.metrics.ProvisioningMetrics,  # type: ignore[attr-defined]
        'inc_failover'
    )

    assert workspace.exit() is workspace

    assert workspace.result is tft.artemis.tasks.SUCCESS
    cast(
        MagicMock,
        tft.artemis.tasks.route_guest_request.metrics.ProvisioningMetrics.inc_failover  # type: ignore[attr-defined]
    ).assert_not_called()


def test_exit_failover(
    workspace: Workspace,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    workspace.current_poolname = 'pool1'
    workspace.new_pool = MagicMock(name='pool2', poolname='pool2')
    workspace.gr = MagicMock(name='workspace.gr<mock>')

    patch(
        monkeypatch,
        tft.artemis.tasks.route_guest_request.metrics.ProvisioningMetrics,  # type: ignore[attr-defined]
        'inc_failover'
    )

    assert workspace.exit() is workspace

    assert workspace.result is tft.artemis.tasks.SUCCESS

    cast(
        MagicMock,
        workspace.gr.log_event
    ).assert_called_once_with(
        workspace.logger,
        workspace.session,
        'routing-failover',
        current_pool='pool1',
        new_pool='pool2'
    )

    cast(
        MagicMock,
        tft.artemis.tasks.route_guest_request.metrics.ProvisioningMetrics.inc_failover  # type: ignore[attr-defined]
    ).assert_called_once_with('pool1', 'pool2')


def test_doer(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> None:
    patch(monkeypatch, Workspace, 'entry')

    result = Workspace.route_guest_request(logger, db, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<mock>()',
        'load_pools()',
        'query_policies()',
        'evaluate_ruling()',
        'switch_to_provisioning()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    mock_task_core = patch(monkeypatch, tft.artemis.tasks.route_guest_request, 'task_core')

    tail_handler = tft.artemis.tasks.route_guest_request.route_guest_request.options['tail_handler']

    assert isinstance(tail_handler, tft.artemis.tasks.ProvisioningTailHandler)
    assert tail_handler.current_state == tft.artemis.guest.GuestState.ROUTING
    assert tail_handler.new_state == tft.artemis.guest.GuestState.ERROR

    tft.artemis.tasks.route_guest_request.route_guest_request('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        'route-guest-request',
        cast(tft.artemis.tasks.DoerType, Workspace.route_guest_request),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
