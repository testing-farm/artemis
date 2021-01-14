import pytest

from mock import MagicMock
from gluetool.result import Error

import tft.artemis.drivers.beaker

from . import do_test_release_pool_resources_item, do_test_release_pool_resources_item_propagate_error


#
# BeakerDriver._run_bkr tests
#
def test_run_bkr(logger, beaker_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = 'dummy output'

    monkeypatch.setattr(tft.artemis.drivers.beaker, 'run_cli_tool', mock_run_cli_tool)

    r = beaker_driver._run_bkr(['dummy-bkr-options'])

    assert r.is_ok
    assert r.unwrap() == 'dummy output'

    mock_run_cli_tool.assert_called_once_with(
        logger,
        ['bkr', 'dummy-bkr-options', '--username', 'dummy-username', '--password', 'dummy-password'],
        json_output=False
    )


def test_run_bkr_handle_error(logger, beaker_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.beaker, 'run_cli_tool', mock_run_cli_tool)

    r = beaker_driver._run_bkr([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is True


@pytest.mark.skip('Unsupported, must be implemented')
def test_run_os_handle_no_instance_with_id(logger, beaker_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_failure.details = {
        'command_output': MagicMock(
            stderr=b'No server with a name or ID dummy-instance-id\nsome other text'
        )
    }

    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.beaker, 'run_cli_tool', mock_run_cli_tool)

    r = beaker_driver._run_os([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is False


#
# BeakerDriver.release_pool_resources tests
#
def test_release_pool_resources_job(logger, beaker_driver, monkeypatch):
    do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        beaker_driver,
        {'job_id': 'dummy-job-id'},
        '_run_bkr',
        [['job-cancel', 'dummy-job-id']],
        {}
    )


def test_release_pool_resources_instance_propagate_error(logger, beaker_driver, monkeypatch):
    do_test_release_pool_resources_item_propagate_error(
        logger,
        monkeypatch,
        beaker_driver,
        {'job_id': 'dummy-job-id'},
        '_run_bkr'
    )
