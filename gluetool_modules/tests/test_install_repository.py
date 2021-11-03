# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

from mock import MagicMock, call

import gluetool_modules.libs.guest as guest_module
import gluetool_modules.libs.guest_setup
import gluetool_modules.libs.testing_environment
import gluetool_modules.helpers.install_repository
import gluetool_modules.helpers.rules_engine

from . import create_module, patch_shared


def mock_guest(execute_mock):
    guest_mock = MagicMock()
    guest_mock.name = 'guest0'
    guest_mock.execute = execute_mock

    return guest_mock


@pytest.fixture(name='module')
def fixture_module(monkeypatch):
    module = create_module(gluetool_modules.helpers.install_repository.InstallRepository)[1]

    module._config['log-dir-name'] = 'log-dir-example'
    module._config['download-path'] = 'dummy-path'

    def dummy_testing_farm_request():
        environments_requested = [
            {
                'artifacts': [
                    {
                        'id': 'https://example.com/repo1',
                        'packages': None,
                        'type': 'repository'
                    },
                    {
                        'id': 'https://example.com/repo2',
                        'packages': None,
                        'type': 'repository'
                    },
                    {
                        'id': 'wrongid',
                        'packages': None,
                        'type': 'wongtype'
                    }
                ]
            },
            {
                'artifacts': [
                    {
                        'id': 'wrongid',
                        'packages': None,
                        'type': 'wongtype'
                    }
                ]
            }
        ]
        return MagicMock(environments_requested=environments_requested)

    patch_shared(monkeypatch, module, {}, callables={
        'testing_farm_request': dummy_testing_farm_request,
        'evaluate_instructions': gluetool_modules.helpers.rules_engine.RulesEngine.evaluate_instructions,
        'setup_guest': None
    })

    return module


@pytest.fixture(name='local_guest')
def fixture_local_guest(module):
    guest = guest_module.NetworkedGuest(module, '127.0.0.1', key=MagicMock())
    guest.execute = MagicMock(return_value=MagicMock(stdout='', stderr=''))
    guest.environment = gluetool_modules.libs.testing_environment.TestingEnvironment(
        arch='x86_64',
        compose='dummy-compose'
    )

    return guest


def test_sanity_shared(module):
    assert module.glue.has_shared('setup_guest') is True


def test_setup_guest(module, local_guest):
    pass


def test_execute(module, local_guest, monkeypatch):
    module.execute()

    assert module.request_artifacts == [
        {
            'id': 'https://example.com/repo1',
            'packages': None,
            'type': 'repository'
        },
        {
            'id': 'https://example.com/repo2',
            'packages': None,
            'type': 'repository'
        }
    ]


def test_guest_setup(module, local_guest):
    module.execute()

    stage = gluetool_modules.libs.guest_setup.GuestSetupStage.ARTIFACT_INSTALLATION

    execute_mock = MagicMock(return_value=MagicMock(stdout='', stderr=''))
    guest = mock_guest(execute_mock)

    module.setup_guest(guest, stage=stage)

    calls = [
        call('command -v yum'),
        call('mkdir -p dummy-path'),
        call('cd dummy-path && dnf repoquery -q --queryformat "%{name}" --repofrompath artifacts-repo,https://example.com/repo1               --disablerepo="*" --enablerepo="artifacts-repo" --location | xargs -n1 curl -sO'),  # noqa
        call('cd dummy-path && dnf repoquery -q --queryformat "%{name}" --repofrompath artifacts-repo,https://example.com/repo2               --disablerepo="*" --enablerepo="artifacts-repo" --location | xargs -n1 curl -sO'),  # noqa
        call('yum -y reinstall dummy-path/*[^.src].rpm'),
        call('yum -y downgrade dummy-path/*[^.src].rpm'),
        call('yum -y update dummy-path/*[^.src].rpm'),
        call('yum -y install dummy-path/*[^.src].rpm'),
        call("ls dummy-path/*[^.src].rpm | sed 's/.*\\/\\(.*\\).rpm$/\\\\1/' | xargs rpm -q")
    ]

    execute_mock.assert_has_calls(calls)
