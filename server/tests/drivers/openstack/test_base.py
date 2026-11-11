# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
from unittest.mock import MagicMock

import _pytest.monkeypatch
import gluetool.log
import keystoneauth1.session
from gluetool.result import Ok

import tft.artemis.drivers.openstack

from ... import MockPatcher


def test_run_os_deadline(
    logger: gluetool.log.ContextAdapter,
    openstack_pool: tft.artemis.drivers.openstack.OpenStackDriver,
    mockpatch: MockPatcher,
) -> None:
    mock_run_cli_tool = mockpatch(tft.artemis.drivers.openstack, 'run_cli_tool')
    mock_run_cli_tool.return_value = Ok(MagicMock(json={}, stdout=''))

    r_output = openstack_pool._run_os(['server', 'show', 'dummy-instance'], commandname='openstack.server.show')

    assert r_output.is_ok

    assert mock_run_cli_tool.call_args.kwargs['deadline'] == datetime.timedelta(seconds=300)


def test_run_os_slow_command_deadline(
    logger: gluetool.log.ContextAdapter,
    openstack_pool: tft.artemis.drivers.openstack.OpenStackDriver,
    mockpatch: MockPatcher,
) -> None:
    mock_run_cli_tool = mockpatch(tft.artemis.drivers.openstack, 'run_cli_tool')
    mock_run_cli_tool.return_value = Ok(MagicMock(json={}, stdout=''))

    r_output = openstack_pool._run_os(['server', 'delete', '--wait', 'dummy-instance'], commandname='os.server-delete')

    assert r_output.is_ok

    assert mock_run_cli_tool.call_args.kwargs['deadline'] == datetime.timedelta(seconds=900)


def test_login_session_timeout(
    logger: gluetool.log.ContextAdapter,
    openstack_pool: tft.artemis.drivers.openstack.OpenStackDriver,
    mockpatch: MockPatcher,
) -> None:
    mock_session_class = mockpatch(keystoneauth1.session, 'Session')
    mock_session_class.return_value = MagicMock()

    r_session = openstack_pool.login_session(logger)

    assert r_session.is_ok

    assert mock_session_class.call_args.kwargs['timeout'] == 60
    assert mock_session_class.call_args.kwargs['connect_retries'] == 0


def test_login_session_timeout_disabled(
    logger: gluetool.log.ContextAdapter,
    openstack_pool: tft.artemis.drivers.openstack.OpenStackDriver,
    mockpatch: MockPatcher,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    monkeypatch.setenv('ARTEMIS_OPENSTACK_API_TIMEOUT_dummy_openstack_pool', '0')

    mock_session_class = mockpatch(keystoneauth1.session, 'Session')
    mock_session_class.return_value = MagicMock()

    r_session = openstack_pool.login_session(logger)

    assert r_session.is_ok

    assert mock_session_class.call_args.kwargs['timeout'] is None


def test_login_session_connect_retries(
    logger: gluetool.log.ContextAdapter,
    openstack_pool: tft.artemis.drivers.openstack.OpenStackDriver,
    mockpatch: MockPatcher,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    monkeypatch.setenv('ARTEMIS_OPENSTACK_API_CONNECT_RETRIES_dummy_openstack_pool', '3')

    mock_session_class = mockpatch(keystoneauth1.session, 'Session')
    mock_session_class.return_value = MagicMock()

    r_session = openstack_pool.login_session(logger)

    assert r_session.is_ok

    assert mock_session_class.call_args.kwargs['connect_retries'] == 3
