# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import random
import threading
from typing import List, Optional, cast
from unittest.mock import MagicMock

import gluetool.log
import pytest
import sqlalchemy

import tft.artemis
import tft.artemis.db
from tft.artemis.tasks.guest_shelf_lookup import Workspace

from .. import MockPatcher
from . import assert_task_core_call


def _create_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(logger, session, threading.Event(), 'dummy-guest-name')


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return _create_workspace(logger, session)


def test_entry(workspace: Workspace, mockpatch: MockPatcher) -> None:
    mockpatch(workspace, 'handle_success')
    mockpatch(workspace, 'load_guest_request')

    assert workspace.guestname is not None
    assert workspace.entry() is workspace

    assert workspace.result is None

    cast(MagicMock, workspace.handle_success).assert_called_once_with('entered-task')
    cast(MagicMock, workspace.load_guest_request).assert_called_once_with(
        'dummy-guest-name',
        state=tft.artemis.guest.GuestState.SHELF_LOOKUP
    )


@pytest.mark.parametrize('shelfname, guests_expected', [
    ('dummy-shelf', ['dummy-shelved-guest']),
    (None, [])
])
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_shelf_query(
    workspace: Workspace,
    shelfname: str,
    guests_expected: List[str]
) -> None:
    workspace.gr = cast(
        tft.artemis.db.GuestRequest,
        MagicMock(guestname='mock_guest_request', shelfname=shelfname)
    )

    assert workspace.shelf_query() is workspace

    assert workspace.result is None

    assert len(workspace.shelved_guests) == len(guests_expected)
    assert all(
        guest.shelfname == shelfname and guest.guestname in guests_expected
        for guest in workspace.shelved_guests
    )


@pytest.mark.parametrize('guest_request, shelved_guests, expected', [
    (
        MagicMock(guestname='mock_guest_request', environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            kickstart=tft.artemis.environment.Kickstart()
        ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None),
        [
            MagicMock(guestname='mock_shelved_guest', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None)
        ],
        'mock_shelved_guest'
    ),
    (
        MagicMock(guestname='mock_guest_request', environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            kickstart=tft.artemis.environment.Kickstart()
        ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None),
        [
            MagicMock(guestname='mock_shelved_guest_1', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='aarch64'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None),
            MagicMock(guestname='mock_shelved_guest_2', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
                os=tft.artemis.environment.OsRequirements(compose='different-dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None),
            MagicMock(guestname='mock_shelved_guest_3', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='another-dummy-key', log_types=[], post_install_script=None),
            MagicMock(guestname='mock_shelved_guest_4', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[
                ('logtype', tft.artemis.db.GuestLogContentType.URL)
            ], post_install_script=None),
            MagicMock(guestname='mock_shelved_guest_5', environment=tft.artemis.environment.Environment(
                hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
                os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
                kickstart=tft.artemis.environment.Kickstart()
            ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script='script')
        ],
        None
    ),
    (
        MagicMock(guestname='mock_guest_request', environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            kickstart=tft.artemis.environment.Kickstart()
        ), skip_prepare_verify_ssh=False, ssh_keyname='dummy-key', log_types=[], post_install_script=None),
        [],
        None
    )
], ids=['valid', 'no-match', 'empty'])
def test_select_guest(
    workspace: Workspace,
    guest_request: MagicMock,
    shelved_guests: List[MagicMock],
    expected: Optional[str],
    mockpatch: MockPatcher
) -> None:
    mockpatch(random, 'randrange').return_value = 0
    workspace.shelved_guests = cast(List[tft.artemis.db.GuestRequest], shelved_guests)
    workspace.gr = guest_request

    assert workspace.select_guest() is workspace

    if expected is not None:
        assert workspace.selected_guest is not None
        assert workspace.selected_guest.guestname == expected
    else:
        assert workspace.selected_guest is None

    assert workspace.result is None


def test_use_guest(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mockpatch(workspace, 'update_guest_state_and_request_task')
    mockguest = MagicMock(
        spec=tft.artemis.db.GuestRequest,
        guestname='dummy-selected-guest',
        poolname='dummy-pool',
        address='dummy-address',
        ssh_port=123,
        ssh_username='dummy-user',
        pool_data='dummy-pool-data'
    )
    workspace.guestname = 'dummy-guest'
    workspace.selected_guest = cast(
        tft.artemis.db.GuestRequest,
        mockguest
    )

    assert workspace.use_guest() is workspace

    cast(MagicMock, workspace.update_guest_state_and_request_task).assert_called_once_with(
        tft.artemis.guest.GuestState.PREPARING,
        tft.artemis.tasks.guest_request_prepare_finalize_pre_connect,
        'dummy-guest',
        current_state=tft.artemis.guest.GuestState.SHELF_LOOKUP,
        set_values={
            'poolname': 'dummy-pool',
            'address': 'dummy-address',
            'ssh_port': 123,
            'ssh_username': 'dummy-user',
            'pool_data': 'dummy-pool-data'
        }
    )

    assert workspace.result is None


@pytest.mark.usefixtures('_schema_initialized_actual')
def test_remove_shelved_gr(
    db: tft.artemis.db.DB,
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    workspace.selected_guest = cast(
        tft.artemis.db.GuestRequest,
        MagicMock(spec=tft.artemis.db.GuestRequest, guestname='dummy-shelved-guest')
    )

    assert workspace.remove_shelved_gr() is workspace

    assert workspace.result is tft.artemis.tasks.SUCCESS

    with db.get_session() as session:
        r_guests = tft.artemis.db.SafeQuery \
            .from_session(session, tft.artemis.db.GuestRequest) \
            .all()

        assert r_guests.is_ok

        guests = r_guests.unwrap()

        assert len(guests) == 2
        assert all([guest.guestname != 'dummy-shelved-guest' for guest in guests])


def test_shelf_miss(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    workspace.gr = MagicMock(name='dummy-guest-request')
    mockpatch(workspace, 'update_guest_state_and_request_task')

    assert workspace.shelf_miss() is workspace

    cast(MagicMock, workspace.update_guest_state_and_request_task).assert_called_once_with(
        tft.artemis.guest.GuestState.ROUTING,
        tft.artemis.tasks.route_guest_request.route_guest_request,
        'dummy-guest-name',
        current_state=tft.artemis.guest.GuestState.SHELF_LOOKUP
    )

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

    result = Workspace.guest_shelf_lookup(logger, db, session, threading.Event(), 'dummy-guest')

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `_repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'shelf_query()',
        'select_guest()',
        'use_guest()',
        'remove_shelved_gr()',
        'shelf_miss()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.guest_shelf_lookup, 'task_core')

    tail_handler = tft.artemis.tasks.guest_shelf_lookup.guest_shelf_lookup.options['tail_handler']

    assert isinstance(tail_handler, tft.artemis.tasks.ProvisioningTailHandler)
    assert tail_handler.current_state == tft.artemis.guest.GuestState.SHELF_LOOKUP
    assert tail_handler.new_state == tft.artemis.guest.GuestState.SHELF_LOOKUP

    tft.artemis.tasks.guest_shelf_lookup.guest_shelf_lookup('dummy-guest')

    assert_task_core_call(
        mock_task_core,
        Workspace.TASKNAME,
        cast(tft.artemis.tasks.DoerType, Workspace.guest_shelf_lookup),
        'dummy-guest',
        test_guest_logger='dummy-guest'
    )
