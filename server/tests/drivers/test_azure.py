import pytest

import mock
from mock import MagicMock
from gluetool.result import Error

import tft.artemis.drivers.azure

from . import do_test_release_pool_resources_item, do_test_release_pool_resources_item_propagate_error


#
# AzureDriver._run_cmd tests
#
def test_run_cmd(logger, azure_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = {}

    monkeypatch.setattr(tft.artemis.drivers.azure, 'run_cli_tool', mock_run_cli_tool)

    r = azure_driver._run_cmd(['dummy-az-options'])

    assert r.is_ok
    assert r.unwrap() == {}

    mock_run_cli_tool.assert_called_once_with(
        logger,
        ['az', 'dummy-az-options'],
        json_output=True,
        command_scrubber=mock.ANY
    )


def test_run_cmd_raw(logger, azure_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = 'dummy output'

    monkeypatch.setattr(tft.artemis.drivers.azure, 'run_cli_tool', mock_run_cli_tool)

    r = azure_driver._run_cmd(['dummy-az-options'], json_format=False)

    assert r.is_ok
    assert r.unwrap() == 'dummy output'

    mock_run_cli_tool.assert_called_once_with(
        logger,
        ['az', 'dummy-az-options'],
        json_output=False,
        command_scrubber=mock.ANY
    )


def test_run_cmd_handle_error(logger, azure_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.azure, 'run_cli_tool', mock_run_cli_tool)

    r = azure_driver._run_cmd([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is True


@pytest.mark.skip('Unsupported, must be implemented')
def test_run_os_handle_no_instance_with_id(logger, azure_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_failure.details = {
        'command_output': MagicMock(
            stderr=b'No server with a name or ID dummy-instance-id\nsome other text'
        )
    }

    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.azure, 'run_cli_tool', mock_run_cli_tool)

    r = azure_driver._run_os([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is False


#
# AzureDriver.release_pool_resources tests
#
def test_release_pool_resources_instance(logger, azure_driver, monkeypatch):
    do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        azure_driver,
        {'instance_id': 'dummy-instance-id'},
        '_run_cmd_with_auth',
        [['resource', 'delete', '--ids', 'dummy-instance-id']],
        {'json_format': False}
    )


def test_release_pool_resources_instance_propagate_error(logger, azure_driver, monkeypatch):
    do_test_release_pool_resources_item_propagate_error(
        logger,
        monkeypatch,
        azure_driver,
        {'instance_id': 'dummy-instance-id'},
        '_run_cmd_with_auth'
    )


def test_release_pool_resources_assorted(logger, azure_driver, monkeypatch):
    mock_raw_command = do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        azure_driver,
        {'assorted_resource_ids': ['dummy-resource-id1', 'dummy-resource-id2']},
        '_run_cmd_with_auth'
    )

    mock_raw_command.assert_any_call(['resource', 'delete', '--ids', 'dummy-resource-id1'], json_format=False)
    mock_raw_command.assert_any_call(['resource', 'delete', '--ids', 'dummy-resource-id2'], json_format=False)
