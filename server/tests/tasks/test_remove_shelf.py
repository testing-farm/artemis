# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import Any, List, cast
from unittest.mock import MagicMock, call

import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Ok

import tft.artemis
import tft.artemis.db
import tft.artemis.guest
import tft.artemis.tasks
import tft.artemis.tasks.release_guest_request
from tft.artemis.tasks.remove_shelf import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='_schema_initialized_actual_shelf_condemned')
def fixture_schema_initialized_actual_shelf_condemned(
    session: sqlalchemy.orm.session.Session,
    # Workaround for limitation around using `usefixture` for a fixture
    _schema_initialized_actual: Any
) -> None:
    session.execute(
        sqlalchemy.update(tft.artemis.db.GuestShelf.__table__)
        .where(tft.artemis.db.GuestShelf.shelfname == 'dummy-shelf')
        .values(state=tft.artemis.guest.GuestState.CONDEMNED)
    )


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(logger, db, session, threading.Event(), 'dummy-shelf')


def test_entry(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_shelf')

    assert workspace.shelfname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_shelf).assert_called_once_with(
        'dummy-shelf',
        state=tft.artemis.guest.GuestState.CONDEMNED
    )


@pytest.mark.usefixtures('_schema_initialized_actual_shelf_condemned')
def test_load_shelved_guests(
    workspace: Workspace
) -> None:
    workspace.shelfname = 'dummy-shelf'

    assert workspace.load_shelved_guests() is workspace
    assert workspace.result is None

    assert len(workspace.shelved_guests) == 1
    assert workspace.shelved_guests[0].guestname == 'dummy-shelved-guest'


def test_schedule_release_of_shelved_gr(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_logger = MagicMock(spec=tft.artemis.tasks.TaskLogger, name='mock-logger')
    mock_get_guest_logger = mockpatch(tft.artemis.tasks.remove_shelf, 'get_guest_logger')
    mock_get_guest_logger.return_value = cast(tft.artemis.tasks.TaskLogger, mock_logger)
    mock_update_gr_and_reqest_task = mockpatch(tft.artemis.tasks.remove_shelf, '_update_guest_state_and_request_task')
    mock_update_gr_and_reqest_task.return_value = Ok(True)

    mock_guests = [
        MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            poolname='dummy-pool',
            shelfname='dummy-shelf'
        )
    ]

    workspace.shelved_guests = cast(List[tft.artemis.db.GuestRequest], mock_guests)

    assert workspace.schedule_release_of_shelved_gr() is workspace
    assert workspace.result is None

    mock_update_gr_and_reqest_task.assert_has_calls([
        call(
            mock_logger,
            workspace.session,
            guest.guestname,
            tft.artemis.guest.GuestState.CONDEMNED,
            tft.artemis.tasks.release_guest_request.release_guest_request,
            guest.guestname,
            current_state=tft.artemis.guest.GuestState.SHELVED,
            set_values={
                'shelfname': None
            },
            poolname='dummy-pool'
        )
        for guest in mock_guests
    ])

    mock_get_guest_logger.assert_has_calls([
        call(
            Workspace.TASKNAME,
            workspace.logger,
            guest.guestname
        )
        for guest in mock_guests
    ])


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_remove_shelf_from_active_gr(
    workspace: Workspace,
    db: tft.artemis.db.DB,
    mockpatch: MockPatcher
) -> None:
    assert workspace.remove_shelf_from_active_gr() is workspace
    assert workspace.result is None

    with db.get_session() as session:
        r_guests = tft.artemis.db.SafeQuery \
            .from_session(session, tft.artemis.db.GuestRequest) \
            .filter(tft.artemis.db.GuestRequest.state != tft.artemis.guest.GuestState.SHELVED) \
            .filter(tft.artemis.db.GuestRequest.shelfname == 'dummy-shelf') \
            .all()

        assert r_guests.is_ok

        assert len(r_guests.unwrap()) == 0


@pytest.mark.usefixtures('_schema_initialized_actual_shelf_condemned')
def test_delete_shelf(
    workspace: Workspace,
    db: tft.artemis.db.DB,
    mockpatch: MockPatcher
) -> None:
    assert workspace.delete_shelf() is workspace
    assert workspace.result is None

    with db.get_session() as session:
        r_shelves = tft.artemis.db.SafeQuery \
            .from_session(session, tft.artemis.db.GuestShelf) \
            .filter(tft.artemis.db.GuestShelf.shelfname == 'dummy-shelf') \
            .all()

        assert r_shelves.is_ok

        assert len(r_shelves.unwrap()) == 0


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

    result = Workspace.remove_shelf(logger, db, session, threading.Event(), 'dummy-shelf')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `__repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'load_shelved_guests()',
        'schedule_release_of_shelved_gr()',
        'remove_shelf_from_active_gr()',
        'delete_shelf()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.remove_shelf, 'task_core')

    assert tft.artemis.tasks.remove_shelf.remove_shelf.options['tail_handler'] is None

    tft.artemis.tasks.remove_shelf.remove_shelf('dummy-shelf')

    assert_task_core_call(
        mock_task_core,
        'remove-shelf',
        cast(tft.artemis.tasks.DoerType, Workspace.remove_shelf),
        'dummy-shelf'
    )
