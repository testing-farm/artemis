# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import threading
from typing import Optional, Tuple, cast
from unittest.mock import MagicMock, call

import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Ok

import tft.artemis
import tft.artemis.db
from tft.artemis.tasks.return_guest_to_shelf import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(
        logger,
        session,
        threading.Event(),
        'dummy-guest',
        tft.artemis.guest.GuestState.CONDEMNED
    )


def test_entry(workspace: Workspace, mockpatch: MockPatcher) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_guest_request')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest',
        state=tft.artemis.guest.GuestState.CONDEMNED
    )


@pytest.mark.parametrize('shelfname, has_result', [
    ('dummy-shelf', True),
    (None, False),
    ('shelf-not-found', False)
])
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_load_valid_shelf(
    workspace: Workspace,
    shelfname: str,
    has_result: bool
) -> None:
    workspace.gr = cast(
        tft.artemis.db.GuestRequest,
        MagicMock(guestname='dummy-guest-name', shelfname=shelfname)
    )

    assert workspace.load_valid_shelf() is workspace

    assert workspace.result is None

    if has_result:
        assert type(workspace.shelf) is tft.artemis.db.GuestShelf
        assert workspace.shelf.shelfname == shelfname
    else:
        assert workspace.shelf is None


@pytest.mark.parametrize('shelf, guest_count', [
    (cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dummy-shelf')), 1),
    (None, None)
])
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_load_shelved_count(
    workspace: Workspace,
    shelf: tft.artemis.db.GuestShelf,
    guest_count: Optional[int]
) -> None:
    workspace.shelf = shelf

    assert workspace.load_shelved_count() is workspace

    assert workspace.result is None

    if guest_count is not None:
        assert workspace.shelved_count == guest_count


def test_load_shelf_max_guests(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.knobs.KNOB_SHELF_MAX_GUESTS, 'get_value') \
        .return_value = Ok(6)
    workspace.shelf = cast(
        tft.artemis.db.GuestShelf,
        MagicMock(shelfname='dummy-shelf')
    )

    assert workspace.load_shelf_max_guests() is workspace

    cast(MagicMock, tft.artemis.knobs.KNOB_SHELF_MAX_GUESTS.get_value) \
        .assert_called_once_with(session=workspace.session, entityname='dummy-shelf')

    assert workspace.result is None

    assert workspace.shelf_max_guests == 6


@pytest.mark.parametrize('guest_request, shelf, guest_counts, is_shelved', [
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='dummy-arch'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ),
            post_install_script=None
        )),
        cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dummy-shelf')),
        (1, 6),
        True
    ),
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='dummy-arch'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ),
            post_install_script=None
        )),
        cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dummy-shelf')),
        (4, 4),
        False
    ),
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='dummy-arch'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ),
            post_install_script=None
        )),
        None,
        None,
        False
    ),
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='dummy-arch', constraints={'constraint': 'value'}),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ),
            post_install_script=None
        )),
        cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dummy-shelf')),
        (1, 6),
        False
    ),
    (
        cast(tft.artemis.db.GuestRequest, MagicMock(
            spec=tft.artemis.db.GuestRequest,
            guestname='dummy-guest',
            shelfname='dummy-shelf',
            environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='dummy-arch'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ),
            post_install_script='dummy-script'
        )),
        cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dummy-shelf')),
        (1, 6),
        False
    ),
], ids=['valid', 'shelf-full', 'no-shelf', 'hw-constraints', 'post-install-script'])
def test_return_guest(
    workspace: Workspace,
    mockpatch: MockPatcher,
    guest_request: tft.artemis.db.GuestRequest,
    shelf: Optional[tft.artemis.db.GuestShelf],
    guest_counts: Optional[Tuple[int, ...]],
    is_shelved: bool
) -> None:
    mock_update_guest_state_and_request_task = mockpatch(workspace, 'update_guest_state_and_request_task')

    workspace.gr = guest_request
    workspace.shelf = shelf
    if guest_counts is not None:
        workspace.shelved_count, workspace.shelf_max_guests = guest_counts

    assert workspace.return_guest() is workspace

    if is_shelved:
        mock_update_guest_state_and_request_task.assert_called_once_with(
            tft.artemis.guest.GuestState.SHELVED,
            tft.artemis.tasks.shelved_guest_watchdog.shelved_guest_watchdog,
            'dummy-guest',
            current_state=tft.artemis.guest.GuestState.CONDEMNED
        )

        assert workspace.result is tft.artemis.tasks.SUCCESS
    else:
        assert workspace.result is None

        mock_update_guest_state_and_request_task.assert_not_called()


@pytest.mark.parametrize('current_state,update_state', [
    (tft.artemis.guest.GuestState.CONDEMNED, False),
    (tft.artemis.guest.GuestState.READY, True)
])
def test_dispatch_release(
    workspace: Workspace,
    current_state: tft.artemis.guest.GuestState,
    update_state: bool,
    mockpatch: MockPatcher
) -> None:
    mock_request_task = mockpatch(workspace, 'request_task')
    mock_update_guest_state_and_request_task = mockpatch(workspace, 'update_guest_state_and_request_task')

    workspace.current_state = current_state

    if update_state:
        executed, skipped = mock_update_guest_state_and_request_task, mock_request_task
        expected_call = call(
            tft.artemis.guest.GuestState.CONDEMNED,
            tft.artemis.tasks.release_guest_request.release_guest_request,
            workspace.guestname,
            current_state=current_state
        )
    else:
        executed, skipped = mock_request_task, mock_update_guest_state_and_request_task
        expected_call = call(
            tft.artemis.tasks.release_guest_request.release_guest_request,
            workspace.guestname
        )

    assert workspace.dispatch_release() is workspace

    assert executed.call_count == 1
    executed.assert_has_calls([expected_call])
    skipped.assert_not_called()

    assert workspace.result is None


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

    result = Workspace.return_guest_to_shelf(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-guest',
        tft.artemis.guest.GuestState.CONDEMNED.value
    )

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'load_valid_shelf()',
        'load_shelved_count()',
        'load_shelf_max_guests()',
        'return_guest()',
        'dispatch_release()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.return_guest_to_shelf, 'task_core')

    assert tft.artemis.tasks.return_guest_to_shelf.return_guest_to_shelf.options['tail_handler'] is None

    tft.artemis.tasks.return_guest_to_shelf.return_guest_to_shelf(
        'dummy-guest',
        tft.artemis.guest.GuestState.CONDEMNED.value
    )

    assert_task_core_call(
        mock_task_core,
        'return-guest-to-shelf',
        cast(tft.artemis.tasks.DoerType, Workspace.return_guest_to_shelf),
        'dummy-guest',
        tft.artemis.guest.GuestState.CONDEMNED.value,
        test_guest_logger='dummy-guest'
    )
