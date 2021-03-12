import os
import sys

import pytest
from mock import MagicMock

import gluetool
import gluetool_modules.helpers.rules_engine
import gluetool_modules.dispatchers.test_batch_planner

from . import create_module, check_loadable, patch_shared

ASSETS_DIR = os.path.join('gluetool_modules', 'tests', 'assets', 'test_batch_planner')


def _load_from_assets(starts_with):
    assets = []

    for filename in sorted(os.listdir(ASSETS_DIR)):
        if not filename.startswith(starts_with):
            continue

        with open(os.path.join(ASSETS_DIR, filename), 'r') as f:
            assets.append(gluetool.utils.YAML().load(f))

    return assets


@pytest.fixture(name='module')
def fixture_module(monkeypatch):
    module = create_module(gluetool_modules.dispatchers.test_batch_planner.TestBatchPlanner)[1]

    patch_shared(monkeypatch, module, {
        'eval_context': {
            'BUILD_TARGET': 'dummy-target',
            'PRIMARY_TASK': 'dummy-primary-task',
            'TASKS': 'dummy-tasks',
            'NVR': 'foo-13.17-23.el7',
            'SCRATCH': False
            }
    })

    rules_engine = gluetool_modules.helpers.rules_engine.RulesEngine(module.glue, 'rules-engine')
    patch_shared(monkeypatch, module, {}, callables={
        'evaluate_rules': rules_engine.evaluate_rules
    })

    return module


def test_sanity(module):
    # first time `module` fixture is used

    assert isinstance(module, gluetool_modules.dispatchers.test_batch_planner.TestBatchPlanner)


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/dispatchers/test_batch_planner.py', 'TestBatchPlanner')


def test_shared(module):
    module.add_shared()

    assert module.glue.has_shared('plan_test_batch')


@pytest.mark.parametrize('script', _load_from_assets('reduce-section-'))
def test_reduce_section(module, script):
    section_config = script.get('section', None)
    kwargs = script.get('kwargs', {})
    expected = script.get('expected', {})

    raises = script.get('raises', None)

    if raises is not None:
        klass_path = raises['klass'].split('.')
        module_path, klass_name = '.'.join(klass_path[0:-1]), klass_path[-1]

        klass = getattr(sys.modules[module_path], klass_name)

        with pytest.raises(klass, match=raises['match']):
            module._reduce_section(section_config, **kwargs)

    else:
        actual = module._reduce_section(section_config, **kwargs)

        gluetool.log.log_dict(module.debug, 'expected command sets', expected)
        gluetool.log.log_dict(module.debug, 'actual command sets', actual)

        assert actual == expected


@pytest.mark.parametrize('config, expected', [
    (
        {}, {'default': []}
    ),
    (
        {'packages': {}}, {'default': []}
    )
])
def test_config(module, config, expected):
    actual = module._construct_command_sets(config, 'component-foo')

    gluetool.log.log_dict(module.debug, 'expected command sets', expected)
    gluetool.log.log_dict(module.debug, 'actual command sets', actual)

    assert actual == expected


@pytest.mark.parametrize('component, ignored_methods', [
    ('389-ds', ['sti']),
    ('llvm-toolset', ['static-config', 'sti'])
])
def test_ignore_methods(module, monkeypatch, component, ignored_methods):
    module._config['ignore-methods-map'] = os.path.join(ASSETS_DIR, 'ignore-methods-map.yaml')
    rules_engine = gluetool_modules.helpers.rules_engine.RulesEngine(module.glue, 'rules-engine')

    patch_shared(monkeypatch, module, {
        'eval_context': {
            'PRIMARY_TASK': MagicMock(ARTIFACT_NAMESPACE='redhat-module', component=component)
        }
    }, callables={
        'evaluate_rules': rules_engine.evaluate_rules,
        'evaluate_instructions': rules_engine.evaluate_instructions,
    })

    assert module._get_ignored_methods() == ignored_methods


def test_no_ignore_methods(module, monkeypatch):
    assert module._get_ignored_methods() == []
