import pytest

from mock import MagicMock
from gluetool_modules.helpers.jenkins.jenkins_build_name import JenkinsBuildName
from . import create_module, patch_shared, assert_shared, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(JenkinsBuildName)


def test_loadable(module):
    glue, _ = module

    check_loadable(glue, 'gluetool_modules/helpers/jenkins/jenkins_build_name.py', 'JenkinsBuildName')


def test_no_jenkins(module, monkeypatch):
    _, module = module

    patch_shared(monkeypatch, module, {
        'eval_context': 'dummy_context'
    })

    assert_shared('jenkins', module.execute)


def test_no_build_url(log, module, monkeypatch):
    _, module = module

    patch_shared(monkeypatch, module, {
        'jenkins': MagicMock(),
        'primary_task': 'dummy_task'
    })

    try:
        monkeypatch.delenv('BUILD_URL')
    except KeyError:
        pass

    module.execute()
    assert log.records[-1].message == '$BUILD_URL env var not found, was this job started by Jenkins?'


def test_run(log, module, monkeypatch):
    thread_id = 'dummy_thread_qid'
    eval_context = {
        'FIRST': 'dummy_item',
        'SECOND': 'another_dummy_item',
        'THREAD_ID': thread_id
    }

    _, module = module
    module._config['name'] = '{{ THREAD_ID }}:{{ SECOND }}-{{ FIRST }}'

    mocked_set_build_name = MagicMock()

    patch_shared(monkeypatch, module, {
        'eval_context': eval_context,
        'jenkins': MagicMock(set_build_name=mocked_set_build_name)
    })

    monkeypatch.setenv('BUILD_URL', 'dummy_jenkins_url')

    module.execute()
    name = '{}:{}-{}'.format(thread_id, eval_context['SECOND'], eval_context['FIRST'])
    assert log.records[-1].message == "build name set: '{}'".format(name)
    mocked_set_build_name.assert_called_with(name)
