# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import os

import mock
import pytest

import gluetool
import gluetool_modules.helpers.execute_command

from mock import MagicMock

from . import create_module, testing_asset as _testing_asset, check_loadable


def local_testing_asset(*bits):
    return _testing_asset('execute-command', *bits)


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.helpers.execute_command.ExecuteCommand)[1]

    return module


def test_sanity(module):
    """
    Test whether it is possible to instantiate the module (via including the fixture).
    """


def test_loadable(module):
    """
    Test whether it is possible to load the module via ``gluetool`` native mechanisms.
    """

    check_loadable(module.glue, 'gluetool_modules/helpers/execute_command.py', 'ExecuteCommand')


def test_shared(module):
    """
    Test whether the loaded module provides the shared function.
    """

    assert module.has_shared('execute_commands')


def test_execute_command(module, mock_command, log):
    """
    Test execution of a command that passes.
    """

    _, _, _, mock_output = mock_command

    output = module._execute_command(['dummy', 'command'])

    assert output is mock_output

    assert log.match(message='Running command: dummy command', levelno=logging.INFO)
    assert log.match(message='Exited with code 0', levelno=logging.INFO)


def test_execute_command_printable(module, mock_command, log):
    """
    Test whether printable form of a command is used in the log.
    """

    _, _, _, mock_output = mock_command

    output = module._execute_command(['dummy', 'command'], printable='something completely different')

    assert output is mock_output

    assert log.match(message='Running command: something completely different', levelno=logging.INFO)
    assert log.match(message='Exited with code 0', levelno=logging.INFO)


def test_execute_command_fail(module, mock_command, log):
    """
    Test execution of command that exited with non-zero status by mocking returned status.
    """

    _, _, _, mock_output = mock_command

    mock_output.exit_code = 1

    with pytest.raises(gluetool.glue.GlueError, match=r"Command 'dummy command' exited with non-zero exit code"):
        module._execute_command(['dummy', 'command'])

    assert log.match(message='Running command: dummy command', levelno=logging.INFO)
    assert log.match(message='Exited with code 1', levelno=logging.ERROR)


def test_execute_command_exception(module, mock_command, log):
    """
    Test execution of command that exited with non-zero status by mocking exception raised by ``Command.run``.
    """

    _, _, mock_run, mock_output = mock_command

    mock_output.exit_code = 1
    mock_exception = gluetool.utils.GlueCommandError("I don't want to work...", output=mock_output)
    mock_run.side_effect = mock_exception

    with pytest.raises(gluetool.glue.GlueError, match=r"Command 'dummy command' exited with non-zero exit code") as exc:
        module._execute_command(['dummy', 'command'])

    assert exc.value.__class__ is gluetool.GlueError
    assert exc.value.caused_by is not None
    assert exc.value.caused_by[1] is mock_exception

    assert log.match(message='Running command: dummy command', levelno=logging.INFO)
    assert log.match(message='Exited with code 1', levelno=logging.ERROR)


def test_execute_command_templates(module, mock_command, log):
    """
    Test execution of a command template.
    """

    mock_command_init, _, mock_run, mock_output = mock_command

    module._execute_command_templates([
        'dummy command {{ FOO }}',
        'dummy command {{ BAR }}'
    ], context_extra={
        'FOO': 'foo',
        'BAR': 'bar'
    })

    assert log.match(message='Running command: dummy command {{ FOO }}', levelno=logging.INFO)
    assert log.match(message='Running command: dummy command {{ BAR }}', levelno=logging.INFO)

    assert mock_command_init.call_args_list == [
        mock.call(['dummy', 'command', 'foo']),
        mock.call(['dummy', 'command', 'bar'])
    ]

    assert log.match(message='Exited with code 0', levelno=logging.INFO)


def test_execute_commands(module, monkeypatch):
    """
    Test whether the shared function uses internal API correctly.
    """

    mock_execute_command_templates = MagicMock()
    monkeypatch.setattr(module, '_execute_command_templates', mock_execute_command_templates)

    templates = [
        'dummy command {{ FOO }}',
        'dummy command {{ BAR }}'
    ]

    context_extra = {}

    module.execute_commands(templates, context_extra=context_extra)

    mock_execute_command_templates.assert_called_once_with(templates, context_extra=context_extra)


def test_external_commands_command(module):
    """
    Test whether ``external_commands`` property provides commands specified via ``--command`` option.
    """

    module._config['command'] = [
        'dummy command #1',
        'dummy command #2'
    ]

    assert module._external_commands == module._config['command']


def test_external_commands_scripts(module):
    """
    Test whether ``external_commands`` property provides commands specified via ``--script`` option.
    """

    module._config['script'] = [
        local_testing_asset('dummy-script-1.yaml'),
        local_testing_asset('dummy-script-2.yaml')
    ]

    assert module._external_commands == [
        'dummy command #1',
        'dummy command #2',
        'dummy command #3',
        'dummy command #4'
    ]


def test_external_commands_scripts_broken(module):
    """
    Test whether ``external_commands`` raises an exception for badly formatted script.
    """

    script_filepath = local_testing_asset('dummy-script-3.yaml')
    absolute_script_filepath = os.path.abspath(script_filepath)

    module._config['script'] = [
        script_filepath
    ]

    with pytest.raises(gluetool.GlueError,
                       match=r"Script '{}' does not contain a list of commands".format(absolute_script_filepath)):

        module._external_commands


def test_execute(module, monkeypatch):
    """
    Test whether ``execute`` method calls internal API correctly.
    """

    mock_external_commands = MagicMock()
    mock_execute_command_templates = MagicMock()

    monkeypatch.setattr(module, '_external_commands', mock_external_commands)
    monkeypatch.setattr(module, '_execute_command_templates', mock_execute_command_templates)

    module.execute()

    mock_execute_command_templates.assert_called_once_with(mock_external_commands)


def test_execute_with_on_destroy(module, monkeypatch):
    """
    Test whether ``execute`` method does nothing when ``--on-destroy`` option is set.
    """

    mock_execute_command_templates = MagicMock()

    monkeypatch.setattr(module, '_execute_command_templates', mock_execute_command_templates)

    module._config['on-destroy'] = 'yes'

    module.execute()

    mock_execute_command_templates.assert_not_called()


def test_destroy(module, monkeypatch):
    """
    Test whether ``destroy`` method calls internal API correctly.
    """

    mock_failure = MagicMock()
    mock_external_commands = MagicMock()
    mock_execute_command_templates = MagicMock()

    monkeypatch.setattr(module, '_external_commands', mock_external_commands)
    monkeypatch.setattr(module, '_execute_command_templates', mock_execute_command_templates)

    module._config['on-destroy'] = 'yes'

    module.destroy(failure=mock_failure)

    mock_execute_command_templates.assert_called_once_with(mock_external_commands, context_extra={
        'FAILURE': mock_failure
    })


def test_destroy_without_on_destroy(module, monkeypatch):
    """
    Test whether ``destroy`` method does nothing when ``--no-destroy`` option wasn't set.
    """

    mock_execute_command_templates = MagicMock()

    monkeypatch.setattr(module, '_execute_command_templates', mock_execute_command_templates)

    module.destroy()

    mock_execute_command_templates.assert_not_called()
