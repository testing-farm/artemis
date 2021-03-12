import os
import json

import pytest

import gluetool
import gluetool_modules.helpers.ansible
import gluetool_modules.libs.testing_environment
import gluetool_modules.libs.guest as guest_module

import mock
from mock import MagicMock

from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.helpers.ansible.Ansible)[1]
    module._config['ansible-playbook-options'] = []
    module._config['ansible-playbook-filepath'] = '/usr/bin/ansible-playbook'
    return module


@pytest.fixture(name='local_guest')
def fixture_local_guest(module):
    guest = guest_module.NetworkedGuest(module, '127.0.0.1', key='dummy_key')
    guest.environment = gluetool_modules.libs.testing_environment.TestingEnvironment(
        arch='x86_64',
        compose='dummy-compose'
    )

    return guest


@pytest.fixture(name='assert_output')
def fixture_assert_output():
    # https://stackoverflow.com/questions/22627659/run-code-before-and-after-each-test-in-py-test
    yield

    assert os.path.exists(gluetool_modules.helpers.ansible.ANSIBLE_OUTPUT)
    os.unlink(gluetool_modules.helpers.ansible.ANSIBLE_OUTPUT)


def test_sanity(module):
    pass


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/ansible.py', 'Ansible')


def test_shared(module):
    assert module.glue.has_shared('run_playbook')


def test_run_playbook_json(module, local_guest, monkeypatch, assert_output):
    json_output = {'task': 'ok'}
    mock_output = MagicMock(exit_code=0, stdout=json.dumps(json_output), stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    output = module.run_playbook('dummy playbook file', local_guest, json_output=True)

    assert output.execution_output is mock_output
    assert output.json_output == json_output

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        os.path.abspath('dummy playbook file')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'json'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_run_playbook_plaintext(module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=0, stdout='', stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    output = module.run_playbook('dummy playbook file', local_guest)

    assert output.execution_output is mock_output
    assert output.json_output is None

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '-v',
        os.path.abspath('dummy playbook file'),
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_run_playbooks(module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=0, stdout='', stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    output = module.run_playbook(['playbook1', 'playbook2'], local_guest, json_output=False)

    assert output.execution_output is mock_output
    assert output.json_output is None

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '-v',
        os.path.abspath('playbook1'),
        os.path.abspath('playbook2')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_change_ansible_playbook_filepath_option(module, local_guest, monkeypatch, assert_output):
    module._config['ansible-playbook-filepath'] = '/foo/bar/ansible-playbook'

    mock_output = MagicMock(exit_code=0, stdout='', stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    output = module.run_playbook(['playbook1', 'playbook2'], local_guest, json_output=False)

    assert output.execution_output is mock_output
    assert output.json_output is None

    mock_command_init.assert_called_once_with([
        '/foo/bar/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '-v',
        os.path.abspath('playbook1'),
        os.path.abspath('playbook2')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_change_ansible_playbook_filepath_argument(module, local_guest, monkeypatch, assert_output):

    mock_output = MagicMock(exit_code=0, stdout='', stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    output = module.run_playbook(
        ['playbook1', 'playbook2'],
        local_guest, json_output=False,
        ansible_playbook_filepath='/foo/bar/ansible-playbook'
    )

    assert output.execution_output is mock_output
    assert output.json_output is None

    mock_command_init.assert_called_once_with([
        '/foo/bar/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '-v',
        os.path.abspath('playbook1'),
        os.path.abspath('playbook2')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_error(log, module, local_guest, monkeypatch, assert_output):
    # simulate output of failed ansible-playbook run, giving user JSON blob with an error message
    mock_error = gluetool.GlueCommandError([], output=MagicMock(stdout='{"msg": "dummy error message"}', stderr=''))
    mock_command_run = MagicMock(side_effect=mock_error)

    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    with pytest.raises(gluetool.GlueError, match='Failure during Ansible playbook execution'):
        module.run_playbook('dummy playbook file', local_guest)


def test_error_exit_code(log, module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=1, stdout='{"msg": "dummy error message"}', stderr='')
    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    with pytest.raises(gluetool.GlueError, match='Failure during Ansible playbook execution'):
        module.run_playbook('dummy playbook file', local_guest)


def test_extra_vars(module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=0, stdout=json.dumps({'task': 'ok'}), stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)
    module.run_playbook('dummy playbook file', local_guest, variables={
        'FOO': 'bar'
    }, cwd='foo')

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '--extra-vars', 'FOO="bar"',
        '-v',
        os.path.abspath('dummy playbook file')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd='foo', env=env_variables)


def test_dryrun(module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=0, stdout=json.dumps({'task': 'ok'}), stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    monkeypatch.setattr(module.glue, '_dryrun_level', gluetool.glue.DryRunLevels.DRY)

    module.run_playbook('dummy playbook path', local_guest)

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook',
        '-i', '127.0.0.1,',
        '--private-key', local_guest.key,
        '-C',
        '-v',
        os.path.abspath('dummy playbook path')
    ], logger=local_guest.logger)

    env_variables = os.environ.copy()
    env_variables.update({'ANSIBLE_STDOUT_CALLBACK': 'debug'})

    mock_command_run.assert_called_once_with(cwd=None, env=env_variables)


def test_additonal_options(module, local_guest, monkeypatch, assert_output):
    mock_output = MagicMock(exit_code=0, stdout=json.dumps({'task': 'ok'}), stderr='')

    mock_command_init = MagicMock(return_value=None)
    mock_command_run = MagicMock(return_value=mock_output)

    monkeypatch.setattr(gluetool.utils.Command, '__init__', mock_command_init)
    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)
    module._config['ansible-playbook-options'] = ['-vvv', '-d']

    module.run_playbook('dummy playbook file', local_guest, variables={
        'FOO': 'bar'
    })

    mock_command_init.assert_called_once_with([
        '/usr/bin/ansible-playbook', '-i', '127.0.0.1,', '--private-key', local_guest.key,
        '--extra-vars', 'FOO="bar"',
        '-vvv',
        '-d',
        '-v',
        os.path.abspath('dummy playbook file')
    ], logger=local_guest.logger)
