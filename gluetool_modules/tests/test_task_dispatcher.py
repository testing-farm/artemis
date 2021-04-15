# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest
import gluetool
from mock import MagicMock
import gluetool_modules.dispatchers.task_dispatcher
from gluetool_modules.dispatchers.task_dispatcher import TaskDispatcher
from . import create_module, patch_shared, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(TaskDispatcher)[1]
    return module


@pytest.fixture(name='module_run_module')
def fixture_module_run_module(module, monkeypatch):
    run_module_mock = MagicMock()

    monkeypatch.setattr(
        'gluetool.Module.run_module',
        run_module_mock
    )

    return module, run_module_mock


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/dispatchers/task_dispatcher.py', 'TaskDispatcher')


def test_empty_test_batch(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    patch_shared(monkeypatch, module, {
        'plan_test_batch': []
    })

    module.execute()

    assert not run_module_mock.called


def test_execute(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = ['--option1', '--option2']
    test_batch = [(module_name, options)]

    patch_shared(monkeypatch, module, {
        'plan_test_batch': test_batch
    })

    module.execute()

    run_module_mock.assert_called_with(module_name, options)


def test_task_id(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = ['--option1', '--option2']
    test_batch = [(module_name, options)]

    patch_shared(monkeypatch, module, {
        'plan_test_batch': test_batch,
        'thread_id': 1234
    })

    module.execute()

    run_module_mock.assert_called_with(module_name, ['--testing-thread-id', '1234-1'] + options)


def test_state_reporter_unknown_options(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = ['--option1', '--option2']
    test_batch = [(module_name, options)]

    topic = 'dummy_topic'
    module._config['pipeline-test-bus-topic'] = topic

    report_pipeline_state_mock = MagicMock()
    patch_shared(monkeypatch, module, {}, callables={
        'report_pipeline_state': report_pipeline_state_mock,
        'plan_test_batch': MagicMock(return_value=test_batch)
    })

    module.execute()

    report_pipeline_state_mock.assert_called_with(
        'queued',
        thread_id=None,
        topic=topic,
        test_category='unknown',
        test_type='unknown'
    )
    run_module_mock.assert_called_with(module_name, options)


@pytest.mark.parametrize('args', [
    '--pipeline-state-reporter-options="--test-category dummy_test_category --test-type dummy_test_type"',
    '--pipeline-state-reporter-options="--test-type dummy_test_type --test-category dummy_test_category"',
    '--pipeline-state-reporter-options="--test-category=dummy_test_category --test-type=dummy_test_type"',
    '--pipeline-state-reporter-options="--test-type=dummy_test_type --test-category=dummy_test_category"',
    '--pipeline-state-reporter-options=--test-category dummy_test_category --test-type dummy_test_type',
    '--pipeline-state-reporter-options=--test-type dummy_test_type --test-category dummy_test_category',
    '--pipeline-state-reporter-options=--test-category=dummy_test_category --test-type=dummy_test_type',
    '--pipeline-state-reporter-options=--test-type=dummy_test_type --test-category=dummy_test_category',
    '--pipeline-state-reporter-options=--test-category=dummy_test_category --test-type dummy_test_type',
    '--pipeline-state-reporter-options=--test-category dummy_test_category --test-type=dummy_test_type'
])
def test_state_reporter_options_from_args(module_run_module, monkeypatch, args):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = [args]
    test_batch = [(module_name, options)]

    topic = 'dummy_topic'
    module._config['pipeline-test-bus-topic'] = topic

    report_pipeline_state_mock = MagicMock()
    patch_shared(monkeypatch, module, {}, callables={
        'report_pipeline_state': report_pipeline_state_mock,
        'plan_test_batch': MagicMock(return_value=test_batch)
    })

    module.execute()

    report_pipeline_state_mock.assert_called_with(
        'queued',
        thread_id=None,
        topic=topic,
        test_category='dummy_test_category',
        test_type='dummy_test_type'
    )
    run_module_mock.assert_called_with(module_name, options)


def test_state_reporter_options_from_mapping(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = ['--option1', '--option2']
    test_batch = [(module_name, options)]

    topic = 'dummy_topic'
    module._config['pipeline-test-bus-topic'] = topic
    module._config['pipeline-test-categories'] = 'dummy_topic_categories'
    module._config['pipeline-test-types'] = 'dummy_topic_types'

    report_pipeline_state_mock = MagicMock()
    patch_shared(monkeypatch, module, {}, callables={
        'report_pipeline_state': report_pipeline_state_mock,
        'plan_test_batch': MagicMock(return_value=test_batch)
    })

    mapping_mock = MagicMock()
    mapping_mock.match = MagicMock(return_value='dummy_value')
    monkeypatch.setattr(
        'gluetool.utils.SimplePatternMap',
        MagicMock(return_value=mapping_mock)
    )

    module.execute()

    report_pipeline_state_mock.assert_called_with(
        'queued',
        thread_id=None,
        topic=topic,
        test_category='dummy_value',
        test_type='dummy_value'
    )
    run_module_mock.assert_called_with(module_name, options)


def test_state_reporter_options_mapping_error(module_run_module, monkeypatch):
    module, run_module_mock = module_run_module

    module_name = 'module1'
    options = ['--option1', '--option2']
    test_batch = [(module_name, options)]

    topic = 'dummy_topic'
    module._config['pipeline-test-bus-topic'] = topic
    module._config['pipeline-test-categories'] = 'dummy_topic_categories'
    module._config['pipeline-test-types'] = 'dummy_topic_types'

    report_pipeline_state_mock = MagicMock()
    patch_shared(monkeypatch, module, {}, callables={
        'report_pipeline_state': report_pipeline_state_mock,
        'plan_test_batch': MagicMock(return_value=test_batch)
    })

    mapping_mock = MagicMock()
    mapping_mock.match = MagicMock()
    mapping_mock.match.side_effect = gluetool.GlueError('dummy_error')
    monkeypatch.setattr(
        'gluetool.utils.SimplePatternMap',
        MagicMock(return_value=mapping_mock)
    )

    module.execute()

    report_pipeline_state_mock.assert_called_with(
        'queued',
        thread_id=None,
        topic=topic,
        test_category='unknown',
        test_type='unknown'
    )
    run_module_mock.assert_called_with(module_name, options)
