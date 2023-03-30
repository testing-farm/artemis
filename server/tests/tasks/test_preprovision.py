# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple, cast
from unittest.mock import MagicMock, call

import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Ok

import tft.artemis
import tft.artemis.db
import tft.artemis.environment
import tft.artemis.guest
import tft.artemis.tasks
import tft.artemis.tasks.guest_shelf_lookup
import tft.artemis.tasks.release_guest_request
from tft.artemis.tasks.preprovision import Workspace

from .. import MockPatcher
from . import assert_task_core_call


@pytest.fixture(name='guest_template')
def fixture() -> tft.artemis.api.GuestRequest:
    return tft.artemis.api.GuestRequest(
        keyname='dummy-key',
        environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            kickstart=tft.artemis.environment.Kickstart()
        ).serialize(),
        priority_group=None,
        shelfname=None,
        user_data=None,
        post_install_script=None,
        log_types=None,
        watchdog_dispatch_delay=None,
        watchdog_period_delay=None
    )


@pytest.fixture(name='workspace')
def fixture_workspace(
    guest_template: tft.artemis.api.GuestRequest,
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> Workspace:
    return Workspace.create(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-shelf',
        json.dumps(dataclasses.asdict(guest_template)),
        "3"
    )


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
        state=tft.artemis.guest.GuestState.READY
    )


def test_parse_environemnt(
    workspace: Workspace,
    mockpatch: MockPatcher
) -> None:
    mock_env = MagicMock()
    workspace.guest_template.environment = cast(Dict[str, Optional[Any]], mock_env)
    mock_environment = mockpatch(tft.artemis.environment.Environment, 'unserialize')

    assert workspace.parse_environment() is workspace

    assert workspace.result is None

    mock_environment.assert_called_once_with(mock_env)


@pytest.mark.parametrize('log_types,expected,error', [
    (None, [], False),
    (
        [('logtype', 'blob'), ('another_logtype', 'url')],
        [
            ('logtype', tft.artemis.db.GuestLogContentType.BLOB),
            ('another_logtype', tft.artemis.db.GuestLogContentType.URL)
        ],
        False
    ),
    ([('console', 'incorrect_log_type')], None, True)
])
def test_parse_log_types(
    workspace: Workspace,
    log_types: List[Tuple[str, ...]],
    expected: List[Tuple[str, tft.artemis.db.GuestLogContentType]],
    error: bool
) -> None:
    workspace.guest_template.log_types = log_types

    assert workspace.parse_log_types() is workspace

    if error:
        assert workspace.result is not None

    else:
        assert workspace.result is None
        assert workspace.log_types == expected


def test_create_guests(
    workspace: Workspace,
    guest_template: tft.artemis.api.GuestRequest,
    mockpatch: MockPatcher
) -> None:
    workspace.shelfname = 'dummy-shelf'
    workspace.shelf = cast(tft.artemis.db.GuestShelf, MagicMock(shelfname='dumy-shelf', ownername='dummy-user'))
    mockpatch(uuid, 'uuid4').return_value = uuid.UUID('a1f3591e-2e18-4bfe-b380-2a496390a7ad')
    mock_env = workspace.environment = cast(
        tft.artemis.environment.Environment,
        MagicMock(tft.artemis.environment.Environment)
    )
    cast(MagicMock, mock_env.serialize).return_value = 'serialized environment'
    mock_log_types = workspace.log_types = cast(List[Tuple[str, tft.artemis.db.GuestLogContentType]], MagicMock())
    mock_stmt = MagicMock(sqlalchemy.insert)
    mock_gr_create_query = mockpatch(tft.artemis.db.GuestRequest, 'create_query')
    mock_gr_create_query.return_value = mock_stmt
    mock_execute_db_statement = mockpatch(tft.artemis.tasks.preprovision, 'execute_db_statement')
    mock_execute_db_statement.return_value = Ok(None)
    mock_request_task = mockpatch(workspace, 'request_task')
    mock_guest_log_event = mockpatch(tft.artemis.db.GuestRequest, 'log_event_by_guestname')

    assert workspace.create_guests() is workspace
    assert workspace.result is None

    assert mock_gr_create_query.mock_calls == [call(
        guestname='a1f3591e-2e18-4bfe-b380-2a496390a7ad',
        environment=mock_env,
        ownername='dummy-user',
        shelfname='dummy-shelf',
        ssh_keyname='dummy-key',
        ssh_port=tft.artemis.api.DEFAULT_SSH_PORT,
        ssh_username=tft.artemis.api.DEFAULT_SSH_USERNAME,
        priorityname=guest_template.priority_group,
        user_data=guest_template.user_data,
        skip_prepare_verify_ssh=guest_template.skip_prepare_verify_ssh,
        post_install_script=guest_template.post_install_script,
        log_types=mock_log_types,
        watchdog_dispatch_delay=guest_template.watchdog_dispatch_delay,
        watchdog_period_delay=guest_template.watchdog_period_delay,
        bypass_shelf_lookup=True,
        on_ready=[(
            tft.artemis.tasks.return_guest_to_shelf.return_guest_to_shelf,
            [tft.artemis.guest.GuestState.READY.value]
        )]
    ) for _ in range(3)]

    assert mock_execute_db_statement.mock_calls == [call(
        workspace.logger,
        workspace.session,
        mock_stmt
    ) for _ in range(3)]
    assert mock_request_task.mock_calls == [call(
        tft.artemis.tasks.guest_shelf_lookup.guest_shelf_lookup,
        'a1f3591e-2e18-4bfe-b380-2a496390a7ad'
    ) for _ in range(3)]
    assert mock_guest_log_event.mock_calls == [call(
        workspace.logger,
        workspace.session,
        'a1f3591e-2e18-4bfe-b380-2a496390a7ad',
        'created',
        environment='serialized environment',
        user_data=guest_template.user_data
    ) for _ in range(3)]


def test_exit(
    workspace: Workspace
) -> None:
    assert workspace.exit() is workspace
    assert workspace.result is tft.artemis.tasks.SUCCESS


def test_doer(
    guest_template: tft.artemis.api.GuestRequest,
    mockpatch: MockPatcher,
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session
) -> None:
    mockpatch(Workspace, 'entry')

    result = Workspace.preprovision(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-shelf',
        json.dumps(dataclasses.asdict(guest_template)),
        str(3)
    )

    # Read the full name of the the final mock, we can easily compare it and prove the sequence of calls.
    # The method is not part of the public API, it's used by `__repr__()`, therefore it's risky, but let's see.
    assert cast(MagicMock, result)._extract_mock_name() == '.'.join([
        'entry<M>()',
        'parse_environment()',
        'parse_log_types()',
        'create_guests()',
        'exit()',
        'final_result'
    ])


@pytest.mark.usefixtures('current_message')
def test_task(
    guest_template: tft.artemis.api.GuestRequest,
    mockpatch: MockPatcher
) -> None:
    mock_task_core = mockpatch(tft.artemis.tasks.preprovision, 'task_core')

    assert tft.artemis.tasks.preprovision.preprovision.options['tail_handler'] is None

    tft.artemis.tasks.preprovision.preprovision(
        'dummy-shelf',
        json.dumps(dataclasses.asdict(guest_template)),
        str(3)
    )

    assert_task_core_call(
        mock_task_core,
        'preprovision',
        cast(tft.artemis.tasks.DoerType, Workspace.preprovision),
        'dummy-shelf',
        json.dumps(dataclasses.asdict(guest_template)),
        str(3)
    )
