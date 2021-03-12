import pytest

from mock import MagicMock

import gluetool_modules.helpers.brew_build_task_params
from . import create_module, patch_shared, check_loadable


def _patched_module(module, monkeypatch, scratch=False):
    mock_task = MagicMock()
    mock_task.scratch = scratch
    mock_task.build_id = 'foo-build-id'
    mock_task.id = 'foo-id'

    mock_primary_task = MagicMock()
    mock_primary_task.scratch = scratch
    mock_primary_task.build_id = 'primary-build-id'
    mock_primary_task.id = 'primary-id'
    mock_primary_task.ARTIFACT_NAMESPACE = 'foo-namespace'

    patch_shared(monkeypatch, module, {
        'tasks': [mock_primary_task, mock_task],
        'primary_task': mock_primary_task
    })

    return module


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.helpers.brew_build_task_params.BrewBuildOptions)[1]


@pytest.fixture(name='patched_module')
def fixture_patched_module(module, monkeypatch):
    return _patched_module(module, monkeypatch, False)


@pytest.fixture(name='patched_module_scratch')
def fixture_patched_module_scratch(module, monkeypatch):
    return _patched_module(module, monkeypatch, True)


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/brew_build_task_params.py', 'BrewBuildOptions')


def test_regular_task(patched_module):
    patched_module._config['install-method'] = 'foo-method'
    patched_module._config['install-rpms-blacklist'] = 'foo-blacklist'

    options = patched_module.brew_build_task_params()

    assert options['METHOD'] == 'foo-method'
    assert options['RPM_BLACKLIST'] == 'foo-blacklist'
    assert options['BUILDS'] == 'primary-build-id foo-build-id'
    assert options['SERVER'] == 'foo-namespace'
    assert not 'TASKS' in options


def test_task_is_scratch_build(patched_module_scratch):
    options = patched_module_scratch.brew_build_task_params()

    assert options['TASKS'] == 'primary-id foo-id'
    assert options['SERVER'] == 'foo-namespace'


def test_install_task_not_build(patched_module):
    patched_module._config['install-task-not-build'] = 'yes'

    options = patched_module.brew_build_task_params()

    assert options['TASKS'] == 'primary-id foo-id'
    assert options['SERVER'] == 'foo-namespace'
