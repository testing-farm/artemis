# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import Any, List, Optional, cast
from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Error

import tft.artemis
import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.drivers.beaker
import tft.artemis.drivers.localhost
import tft.artemis.guest
import tft.artemis.routing_policies
import tft.artemis.tasks
import tft.artemis.tasks.refresh_pool_avoid_groups_hostnames_dispatcher
from tft.artemis.tasks.refresh_pool_avoid_groups_hostnames_dispatcher import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace(logger, session, threading.Event(), guestname='dummy-guest-name', task=Workspace.TASKNAME)


@pytest.fixture(name='mock_pools')
def fixture_pools(
    logger: gluetool.log.ContextAdapter,
) -> List[tft.artemis.drivers.PoolDriver]:
    return [
        tft.artemis.drivers.localhost.LocalhostDriver(logger, 'localhost', {}),
        tft.artemis.drivers.beaker.BeakerDriver(logger, 'beaker', {})
    ]


def test_entry(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'handle_success')

    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')


def test_dispatch_refresh(
    workspace: Workspace,
    mockpatch: MockPatcher,
    mock_pools: List[tft.artemis.drivers.PoolDriver]
) -> None:
    mockpatch(workspace, 'dispatch_task')
    workspace.pools = mock_pools

    assert workspace.dispatch_refresh() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.dispatch_task).assert_called_once()

    _, args, kwargs = cast(MagicMock, workspace.dispatch_task).mock_calls[0]

    assert args == (tft.artemis.tasks.refresh_pool_avoid_groups_hostnames, 'beaker')

    logger = cast(Optional[tft.artemis.tasks.TaskLogger], kwargs.get('logger'))

    assert logger is not None
    assert isinstance(logger, tft.artemis.tasks.TaskLogger)
    assert isinstance(logger._logger, tft.artemis.drivers.PoolLogger)
    assert logger._logger.poolname == 'beaker'


def test_dispatch_refresh_failure(
    workspace: Workspace,
    mockpatch: MockPatcher,
    mock_pools: List[tft.artemis.drivers.PoolDriver]
) -> None:
    error: tft.artemis.tasks.DoerReturnType = Error(tft.artemis.Failure('dummy failure'))

    def inject_error(*args: Any, **kwargs: Any) -> tft.artemis.tasks.DoerReturnType:
        workspace.result = error

        return error

    mockpatch(workspace, 'dispatch_task').side_effect = inject_error
    workspace.pools = [mock_pools[1], mock_pools[1]]

    assert workspace.dispatch_refresh() is workspace

    assert workspace.result is error

    cast(MagicMock, workspace.dispatch_task).assert_called_once()


def test_dispatch_refresh_no_beaker(
    workspace: Workspace,
    mockpatch: MockPatcher,
    mock_pools: List[tft.artemis.drivers.PoolDriver]
) -> None:
    mockpatch(workspace, 'dispatch_task')
    workspace.pools = [mock_pools[0]]

    assert workspace.dispatch_refresh() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.dispatch_task).assert_not_called()


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

    result = Workspace.refresh_pool_avoid_groups_hostnames_dispatcher(
        logger,
        db,
        session,
        threading.Event()
    )

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'load_pools()',
        'dispatch_refresh()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.refresh_pool_avoid_groups_hostnames_dispatcher, 'task_core')

    tft.artemis.tasks.refresh_pool_avoid_groups_hostnames_dispatcher.refresh_pool_avoid_groups_hostnames_dispatcher()

    assert_task_core_call(
        mock_task_core,
        Workspace.TASKNAME,
        cast(tft.artemis.tasks.DoerType, Workspace.refresh_pool_avoid_groups_hostnames_dispatcher)
    )
