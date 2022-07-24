# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import json
import threading
from typing import cast
from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy

import tft.artemis
import tft.artemis.db
import tft.artemis.drivers
import tft.artemis.guest
import tft.artemis.routing_policies
import tft.artemis.tasks
import tft.artemis.tasks.release_guest_request
from tft.artemis.tasks.release_guest_request import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(logger, db, session, threading.Event(), 'dummy-guest-name')


def test_entry(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_guest_request')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest-name',
        state=tft.artemis.guest.GuestState.CONDEMNED
    )


@pytest.mark.usefixtures('dummy_guest_request')
def test_load_pool(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'mark_note_poolname')
    mockpatch(workspace, 'load_gr_pool')

    assert workspace.gr

    workspace.gr.poolname = 'dummy-pool'
    workspace.gr.pool_data = json.dumps({"dummy-data": False})

    assert workspace.load_pool() is workspace

    cast(MagicMock, workspace.mark_note_poolname).assert_called_once_with()
    cast(MagicMock, workspace.load_gr_pool).assert_called_once_with()


@pytest.mark.usefixtures('dummy_guest_request')
def test_load_pool_no_pool(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'mark_note_poolname')
    mockpatch(workspace, 'load_gr_pool')

    assert workspace.gr

    workspace.gr.poolname = None
    workspace.gr.pool_data = json.dumps({'dummy-data': False})

    assert workspace.load_pool() is workspace

    cast(MagicMock, workspace.mark_note_poolname).assert_not_called()
    cast(MagicMock, workspace.load_gr_pool).assert_not_called()


@pytest.mark.usefixtures('dummy_guest_request')
def test_load_pool_no_pool_data(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'mark_note_poolname')
    mockpatch(workspace, 'load_gr_pool')

    assert workspace.gr

    workspace.gr.poolname = 'dummy-pool'
    workspace.gr.pool_data = json.dumps({})

    assert workspace.load_pool() is workspace

    cast(MagicMock, workspace.mark_note_poolname).assert_not_called()
    cast(MagicMock, workspace.load_gr_pool).assert_not_called()


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

    result = Workspace.release_guest_request(logger, db, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'load_pool()',
        'handle_pool_resources()',
        'remove_guest_request()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.release_guest_request, 'task_core')

    assert tft.artemis.tasks.release_guest_request.release_guest_request.options['tail_handler'] is None

    tft.artemis.tasks.release_guest_request.release_guest_request('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        'release-guest-request',
        cast(tft.artemis.tasks.DoerType, Workspace.release_guest_request),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
