# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import pytest

from mock import MagicMock

import gluetool
import gluetool_modules.helpers.pipeline_state_reporter
import gluetool_modules.helpers.rules_engine
from gluetool_modules.libs import strptime

from . import create_module, patch_shared

CI = {
    'name': 'Fake CI',
    'team': 'Fake Team',
    'url': 'Fake URL',
    'email': 'Fake Email',
    'irc': 'Fake IRC'
}

ARTIFACT_MAP = [
    {
        'rule': "ARTIFACT_TYPE == 'brew-build' or ARTIFACT_TYPE == 'koji-build'",
        'details': {
            'id': '{{ PRIMARY_TASK.id }}',
            'component': '{{ PRIMARY_TASK.component }}',
            'issuer': '{{ PRIMARY_TASK.issuer }}',
            'nvr': '{{ PRIMARY_TASK.nvr }}',
            'source': '{{ PRIMARY_TASK.source }}'
        },
    },
    {
        'rule': "ARTIFACT_TYPE == 'brew-build' or ARTIFACT_TYPE == 'koji-build'",
        'eval-as-rule': True,
        'details': {
            'branch': 'PRIMARY_TASK.branch or None',
            'scratch': 'PRIMARY_TASK.scratch'
        }
    }
]

ARTIFACT = {
    'branch': 'fixing-bz17',
    'component': 'dummy-package',
    'id': '123456',
    'issuer': 'bar',
    'nvr': 'dummy-package-1.2.3-79.el7',
    'scratch': 'False',
    'source': 'http://example.com/component.git'
}

FINAL_STATE_MAP = [
    {
        'rules': '1 != 1'
    },
    {
        'rules': 'PRIMARY_TASK'
    },
    {
       'rules': 'PRIMARY_TASK',
       'state': 'complete'
    }
]

RUN_MAP = [{
    'details': {
        'url': 'http://example.com/url',
        'debug': 'http://example.com/debug'
    }
}]

TEST_DOCS_MAP = [
    {
        'rules': '1 != 1'
    },
    {
        'rules': 'PRIMARY_TASK'
    },
    {
       'rules': 'PRIMARY_TASK',
       'docs': 'some-docs'
    }
]

ERROR_REASON_MAP = [
    {
        'rules': '1 != 1'
    },
    {
        'rules': 'PRIMARY_TASK'
    },
    {
       'rules': 'PRIMARY_TASK',
       'reason': 'some-reason'
    }
]

RUN = {
    'debug': 'http://example.com/debug',
    'url': 'http://example.com/url'
}


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.helpers.pipeline_state_reporter.PipelineStateReporter)[1]


def test_sanity_shared(module):
    assert module.glue.has_shared('report_pipeline_state') is True


def test_dont_report_running(module, log):
    module._config['dont-report-running'] = True

    # make sure dont-report-running does nothing
    assert module.execute() == None

    assert log.match(message='not reporting the beginning of the pipeline', levelno=logging.INFO)


def test_no_maps(module):
    assert [
        module.artifact_map,
        module.run_map,
        module.final_state_map,
        module.error_reason_map,
        module.test_docs_map
    ] == [[], [], [], [], []]


@pytest.fixture(name='rules_engine')
def fixture_rules_engine():
    return create_module(gluetool_modules.helpers.rules_engine.RulesEngine)[1]


@pytest.fixture(name='ci_info')
def fixture_ci_info(module):
    module._config.update({
        'ci-name': 'Fake CI',
        'ci-team': 'Fake Team',
        'ci-url': 'Fake URL',
        'ci-contact-email': 'Fake Email',
        'ci-contact-irc': 'Fake IRC'
    })


@pytest.fixture(name='maps')
def fixture_maps(module, monkeypatch):
    module._config.update({
        'artifact-map': ARTIFACT_MAP,
        'run-map': RUN_MAP,
        'final-state-map': FINAL_STATE_MAP,
        'test-docs-map': TEST_DOCS_MAP,
        'error-reason-map': ERROR_REASON_MAP
    })

    # fake load yaml to directly return our maps
    monkeypatch.setattr(gluetool.utils, 'load_yaml', lambda option, logger: option)


@pytest.fixture(name='task')
def fixture_task():
    return MagicMock(ARTIFACT_NAMESPACE='brew-build', id=123456,
                     nvr='dummy-package-1.2.3-79.el7', owner='foo',
                     issuer='bar', branch='fixing-bz17',
                     source='http://example.com/component.git',
                     scratch='False', component='dummy-package')


@pytest.fixture(name='global_eval_context')
def fixture_global_eval_context(module, monkeypatch, rules_engine, maps, task):

    def fake_eval_context(self):
        return {
            'ARTIFACT_TYPE': 'brew-build',
            'PRIMARY_TASK': task,
        }

    # monkeypatching property does not work, fake class instead
    monkeypatch.setattr(gluetool.glue.Glue, 'eval_context', property(fake_eval_context))


@pytest.fixture(name='evaluate')
def fixture_evaluate(module, global_eval_context, rules_engine):
    module.glue.add_shared('evaluate_instructions', rules_engine)
    module.glue.add_shared('evaluate_rules', rules_engine)


@pytest.fixture(name='namespace')
def fixture_namespace(module, monkeypatch, task):
    module._config['test-namespace'] = '{{ PRIMARY_TASK.id }}'

    patch_shared(monkeypatch, module, {
        'primary_task': task
    })


@pytest.fixture(name='mock_namespace')
def fixture_mock_namespace(module, monkeypatch):
    monkeypatch.setattr(module, '_get_test_namespace', lambda: 'namespace')
    monkeypatch.setattr(
        gluetool.utils,
        'render_template',
        lambda *args, **kwargs: 'some-reason' if 'ERROR_MESSAGE' in kwargs else 'topic'
    )


@pytest.fixture(name='publish_messages')
def fixture_publish_messages(module):
    published = {}

    module._config.update({
        'label':  'some-label',
        'note': 'some-note',
        'test-category': 'some-category',
        'test-type': 'some-type',
        'thread-id': 'some-thread-id',
        'version': '0.1.0',
    })

    def mock_publish_bus_messages(message, topic):
        published.update({
            'message': message,
            'topic': topic
        })

    # add a fake publish_bus_messages shared function
    module.publish_bus_messages = mock_publish_bus_messages
    module.glue.add_shared('publish_bus_messages', module)

    return published


def test_get_final_state_error(module, evaluate, monkeypatch):
    # fake load yaml to directly return our maps
    monkeypatch.setattr(gluetool.utils, 'load_yaml', lambda option, logger: [])

    assert module._get_final_state(AttributeError) == gluetool_modules.helpers.pipeline_state_reporter.STATE_ERROR


def test_eval_context(module, namespace, global_eval_context):
    module._config.update({
        'test-type': 'fake-test-type',
        'test-category': 'fake-test-category',
        'test-namespace': '{{ PRIMARY_TASK.id }}',
        'test-docs': 'fake-test-docs',
        'label': 'fake-label'
    })

    assert module.eval_context == {
        'PIPELINE_TEST_TYPE': 'fake-test-type',
        'PIPELINE_TEST_CATEGORY': 'fake-test-category',
        'PIPELINE_TEST_DOCS': 'fake-test-docs',
        'PIPELINE_TEST_NAMESPACE': '123456',
        'PIPELINE_LABEL': 'fake-label'
    }


def test_init_message_thread_id(module, evaluate):
    _, body = module._init_message('category', 'docs', 'namespace', 'type', 'thread_id')

    assert body['thread_id'] == 'thread_id'


def test_init_message_shared_thread_id(ci_info, evaluate, monkeypatch, module):
    patch_shared(monkeypatch, module, {
        'thread_id': 'shared-thread-id',
        'evaluate_instructions': 'something',
        'evaluate_rules': 'something'
    })

    _, body = module._init_message('category', 'docs', 'namespace', 'type', None)

    assert body['thread_id'] == 'shared-thread-id'


def test_execute(ci_info, evaluate, monkeypatch, module, mock_namespace, publish_messages):
    module._config.update({
        'label':  'some-label',
        'note': 'some-note',
        'test-category': 'some-category',
        'test-type': 'some-type',
        'thread-id': 'some-thread-id',
        'version': '0.1.0',
    })

    module.execute()

    assert publish_messages['message'].headers == ARTIFACT

    generated_at = publish_messages['message'].body.pop('generated_at')

    assert publish_messages['message'].body == {
        'artifact': ARTIFACT,
        'ci': CI,
        'run': RUN,
        'category': 'some-category',
        'label': 'some-label',
        'issue_url': None,
        'namespace': 'namespace',
        'docs': 'some-docs',
        'note': 'some-note',
        'reason': 'some-reason',
        'type': 'some-type',
        'version': '0.1.0'
    }

    # check if generated_at has expected format, will traceback if not
    strptime(generated_at, "%Y-%m-%d %H:%M:%S.%f")


def test_execute_reason_in_note(ci_info, evaluate, monkeypatch, module, mock_namespace, publish_messages):
    module._config.update({
        'label':  'some-label',
        'note': None,
        'test-category': 'some-category',
        'test-type': 'some-type',
        'thread-id': 'some-thread-id',
        'version': '0.1.0',
    })

    module.execute()

    assert publish_messages['message'].headers == ARTIFACT

    generated_at = publish_messages['message'].body.pop('generated_at')

    assert publish_messages['message'].body == {
        'artifact': ARTIFACT,
        'ci': CI,
        'run': RUN,
        'category': 'some-category',
        'label': 'some-label',
        'issue_url': None,
        'namespace': 'namespace',
        'docs': 'some-docs',
        'note': 'some-reason',
        'reason': 'some-reason',
        'type': 'some-type',
        'version': '0.1.0'
    }

    # check if generated_at has expected format, will traceback if not
    strptime(generated_at, "%Y-%m-%d %H:%M:%S.%f")


def test_destroy_sysexit(module):
    assert module.destroy(failure=MagicMock(exc_info=[None, SystemExit()])) == None


def test_destroy(module, evaluate, publish_messages, mock_namespace):
    # test with failure
    module.destroy(failure=MagicMock(sentry_event_url='sentry-url'))

    # test with failure and publish_bus_messages
    module.destroy(failure=MagicMock(sentry_event_url='sentry-url'))
    assert publish_messages['message'].body['status'] == 'unknown'
    assert publish_messages['message'].body['issue_url'] == 'sentry-url'


def test_destroy_with_results_and_recipients(module, evaluate, mock_namespace, publish_messages):
    module.results = lambda: [MagicMock(overall_result='passed')]
    module.glue.add_shared('results', module)

    module.notification_recipients = lambda: 'batman'
    module.glue.add_shared('notification_recipients', module)

    # test without failure
    module.destroy()

    assert publish_messages['message'].body['status'] == 'passed'
    assert publish_messages['message'].body['recipients'] == 'batman'


@pytest.mark.parametrize('expected,results', [
    ('info', ['info', 'info', 'info']),
    ('passed', ['passed', 'info', 'passed']),
    ('passed', ['passed', 'passed', 'passed']),
    ('failed', ['passed', 'failed', 'info']),
    ('failed', ['info', 'failed', 'failed']),
])
def test_get_test_results(module, expected, results):
    results = [MagicMock(overall_result=result) for result in results]

    assert module._get_overall_result_legacy(results) == expected
