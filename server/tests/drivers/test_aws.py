import pytest

from mock import MagicMock
from gluetool.result import Error

import tft.artemis.drivers.aws

from . import do_test_release_pool_resources_item, do_test_release_pool_resources_item_propagate_error


#
# AWSDriver._aws_command tests
#
def test_aws_command(logger, aws_driver, mock_run_cli_tool, monkeypatch):
    mock_run_cli_tool.return_value.value[0] = {}

    monkeypatch.setattr(tft.artemis.drivers.aws, 'run_cli_tool', mock_run_cli_tool)

    r = aws_driver._aws_command(['dummy-aws-options'])

    assert r.is_ok
    assert r.unwrap() == {}

    mock_run_cli_tool.assert_called_once_with(
        logger,
        ['dummy-aws-cli', 'dummy-aws-options'],
        json_output=True
    )


def test_aws_command_handle_error(logger, aws_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.aws, 'run_cli_tool', mock_run_cli_tool)

    print(aws_driver.pool_config)

    r = aws_driver._aws_command([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is True


@pytest.mark.skip('Unsupported, must be implemented')
def test_run_os_handle_no_instance_with_id(logger, aws_driver, mock_run_cli_tool, mock_failure, monkeypatch):
    mock_failure.details = {
        'command_output': MagicMock(
            stderr=b'No server with a name or ID dummy-instance-id\nsome other text'
        )
    }

    mock_run_cli_tool.return_value = Error(mock_failure)

    monkeypatch.setattr(tft.artemis.drivers.aws, 'run_cli_tool', mock_run_cli_tool)

    r = aws_driver._run_os([])

    assert r.is_error
    assert r.unwrap_error() is mock_failure
    assert r.unwrap_error().recoverable is False


#
# AWSDriver.release_pool_resources tests
#
def test_release_pool_resources_spot_instance(logger, aws_driver, monkeypatch):
    do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        aws_driver,
        {'spot_instance_id': 'dummy-instance-id'},
        '_aws_command',
        [['ec2', 'cancel-spot-instance-requests', '--spot-instance-request-ids=dummy-instance-id']],
        {}
    )


def test_release_pool_resources_spot_instance_propagate_error(logger, aws_driver, monkeypatch,):
    do_test_release_pool_resources_item_propagate_error(
        logger,
        monkeypatch,
        aws_driver,
        {'spot_instance_id': 'dummy-instance-id'},
        '_aws_command'
    )


def test_release_pool_resources_instance(logger, aws_driver, monkeypatch):
    do_test_release_pool_resources_item(
        logger,
        monkeypatch,
        aws_driver,
        {'instance_id': 'dummy-instance-id'},
        '_aws_command',
        [['ec2', 'terminate-instances', '--instance-ids=dummy-instance-id']],
        {}
    )


def test_release_pool_resources_instance_propagate_error(logger, aws_driver, monkeypatch):
    do_test_release_pool_resources_item_propagate_error(
        logger,
        monkeypatch,
        aws_driver,
        {'instance_id': 'dummy-instance-id'},
        '_aws_command'
    )
