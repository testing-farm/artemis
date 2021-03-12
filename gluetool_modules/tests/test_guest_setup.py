import os
import pytest

import mock
from mock import MagicMock

import gluetool
import gluetool_modules.libs.guest as guest_module
import gluetool_modules.libs.guest_setup
import gluetool_modules.libs.testing_environment
import gluetool_modules.helpers.guest_setup
import gluetool_modules.helpers.rules_engine

from . import assert_shared, create_module, patch_shared


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.helpers.guest_setup.GuestSetup)[1]


@pytest.fixture(name='local_guest')
def fixture_local_guest(module):
    guest = guest_module.NetworkedGuest(module, '127.0.0.1', key=MagicMock())
    guest.environment = gluetool_modules.libs.testing_environment.TestingEnvironment(
        arch='x86_64',
        compose='dummy-compose'
    )

    return guest


def test_sanity_shared(module):
    assert module.glue.has_shared('setup_guest') is True


def test_playbook_map_empty(module):
    assert module._playbooks_map == {}


@pytest.mark.parametrize('option_name, raw, expected', [
    (
        'playbooks',
        ['foo'],
        {'pre-artifact-installation': ['foo']}
    ),
    (
        'playbooks',
        ['foo', 'bar'],
        {'pre-artifact-installation': ['foo', 'bar']}
    ),
    (
        'playbooks',
        ['foo,bar'],
        {'pre-artifact-installation': ['foo', 'bar']}
    ),
    (
        'playbooks',
        ['post-artifact-installation:foo'],
        {'post-artifact-installation': ['foo']}
    ),
    (
        'playbooks',
        [
            'foo',
            'post-artifact-installation:bar,baz'
        ],
        {
            'pre-artifact-installation': ['foo'],
            'post-artifact-installation': ['bar', 'baz']
        }
    ),
    (
        'extra-vars',
        [
            'foo=1',
            'post-artifact-installation:bar=2,baz=3,artifact-installation:extra=not,another=stillnot'
        ],
        {
            'pre-artifact-installation': {
                'foo': '1',
                'baz': '3',
                'another': 'stillnot'
            },
            'artifact-installation': {
                'extra': 'not'
            },
            'post-artifact-installation': {
                'bar': '2'
            }
        }
    ),
])
def test_options(module, option_name, raw, expected):
    property_name = '_{}'.format(option_name.replace('-', '_'))

    module._config[option_name] = raw

    getattr(module, property_name) == expected


def test_missing_required_shared(module, monkeypatch):
    assert_shared('run_playbook', module.execute)

    module._config['playbooks-map'] = 'map.yml'

    patch_shared(monkeypatch, module, {
        'run_playbook': None
    })

    assert_shared('evaluate_rules', module.execute)


def test_setup(log, module, local_guest, monkeypatch):
    playbooks = ['dummy-playbook-1.yml', 'dummy-playbook-2.yml']

    def dummy_run_playbook(_playbook, _guest, variables=None, **kwargs):
        assert log.match(message="""setting up with playbooks:
{}""".format(gluetool.log.format_dict([os.path.join(os.getcwd(), playbook) for playbook in playbooks])))

        assert _guest == local_guest
        # key1:val1 is gone because extra-vars option overrides it
        assert variables == {
            'key2': 'val2',
            'key3': 'val3',
            'key4': 'val4',
            'GUEST_SETUP_STAGE': 'pre-artifact-installation'
        }
        assert kwargs == {
            'dummy_option': 17,
            'json_output': False,
            'logger': mock.ANY,
            'log_filepath': 'guest-setup-{}/guest-setup-output-pre-artifact-installation.txt'.format(local_guest.name),
            'extra_vars_filename_prefix': 'extra-vars-pre-artifact-installation-'
        }

        return None

    module._config['playbooks'] = ','.join(playbooks)
    module._config['extra-vars'] = ['key2=val2,key3=val3', 'key4=val4']

    patch_shared(monkeypatch, module, {
        'detect_ansible_interpreter': []
    }, callables={
        'run_playbook': dummy_run_playbook
    })

    module.shared('setup_guest', local_guest, variables={'key1': 'val1'}, dummy_option=17)


def test_playbook_map_guest_setup(module, monkeypatch):
    module._config['playbooks-map'] = 'map.yml'

    patch_shared(monkeypatch, module, {
        'detect_ansible_interpreter': []
    })

    monkeypatch.setattr(module, "_get_details_from_map", lambda guest, stage: ([], {}))

    module.shared('setup_guest', MagicMock())


def test_playbook_map(module, monkeypatch):
    module._config['playbooks-map'] = 'map.yml'

    rules_engine = gluetool_modules.helpers.rules_engine.RulesEngine(module.glue, 'rules-engine')

    # test default context
    patch_shared(monkeypatch, module, {
        'eval_context': {
            'BUILD_TARGET': 'rhel-7.0-candidate',
        }
    }, callables={
        'evaluate_rules': rules_engine.evaluate_rules
    })

    def load_yaml(path, logger):
        return [
            {
                "playbooks": [
                    "other.yaml"
                ],
                "rule": "BUILD_TARGET.match('rhel-6')"
            },
            {
                "playbooks": [
                    "default.yaml"
                ],
                "extra_vars": {
                    "key": "value"
                },
                "rule": "BUILD_TARGET.match('rhel-7.0-candidate')"
            },
        ]

    monkeypatch.setattr(gluetool.utils, "load_yaml", load_yaml)

    assert module._get_details_from_map(
        None,
        gluetool_modules.libs.guest_setup.GuestSetupStage.PRE_ARTIFACT_INSTALLATION
    ) == ([os.path.join(os.getcwd(), 'default.yaml')], {'key': 'value'})
