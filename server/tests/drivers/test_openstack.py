import mock
from mock import MagicMock
from gluetool.result import Error

import tft.artemis.drivers.openstack

from . import do_test_release_pool_resources_item, do_test_release_pool_resources_item_propagate_error


#
# OpenStack._run_os tests
#
def test_run_os(logger, openstack_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = {}

    monkeypatch.setattr(tft.artemis.drivers.openstack, 'run_cli_tool', mock_run_cli_tool)

    r = openstack_driver._run_os(['dummy-os-options'])

    assert r.is_ok
    assert r.unwrap() == {}

    mock_run_cli_tool.assert_called_once_with(
        logger,
        openstack_driver._os_cmd_base + ['dummy-os-options', '-f', 'json'],
        json_output=True,
        command_scrubber=mock.ANY
    )


def test_run_os_raw(logger, openstack_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = 'dummy output'

    monkeypatch.setattr(tft.artemis.drivers.openstack, 'run_cli_tool', mock_run_cli_tool)

    r = openstack_driver._run_os(['dummy-os-options'], json_format=False)

    assert r.is_ok
    assert r.unwrap() == 'dummy output'

    mock_run_cli_tool.assert_called_once_with(
        logger,
        openstack_driver._os_cmd_base + ['dummy-os-options'],
        json_output=False,
        command_scrubber=mock.ANY
    )


def test_run_os_handle_error(logger, openstack_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.openstack, 'run_cli_tool', mock_run_cli_tool)

    r = openstack_driver._run_os([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is True


def test_run_os_handle_no_instance_with_id(logger, openstack_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_failure.details = {
        'command_output': MagicMock(
            stderr=b'No server with a name or ID dummy-instance-id\nsome other text'
        )
    }

    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.openstack, 'run_cli_tool', mock_run_cli_tool)

    r = openstack_driver._run_os([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is False


#
# OpenStackDriver.release_pool_resources tests
#
def test_release_pool_resources_instance(logger, openstack_driver, monkeypatch):
    do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        openstack_driver,
        {'instance_id': 'dummy-instance-id'},
        '_run_os',
        [['server', 'delete', '--wait', 'dummy-instance-id']],
        {'json_format': False}
    )


def test_release_pool_resources_instance_propagate_error(logger, openstack_driver, monkeypatch):
    do_test_release_pool_resources_item_propagate_error(
        logger,
        monkeypatch,
        openstack_driver,
        {'instance_id': 'dummy-instance-id'},
        '_run_os'
    )
