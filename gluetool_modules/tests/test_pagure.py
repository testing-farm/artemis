import pytest

from mock import MagicMock

import gluetool
import gluetool_modules.infrastructure.pagure
from gluetool_modules.infrastructure import pagure
from . import create_module, check_loadable


def patched_module(module, monkeypatch, json=None, side_effect=None):
    default_json = {
        'name': 'json-name',
        'fullname': 'json-fullname',
        'uid': 'json-uid',
        'branch': 'json-branch',
        'user': {'name': 'json-user-name'},
        'commit_start': 'json-commit-start',
        'commit_stop': 'json-commit-stop',
        'branch_from': 'json-branch-from',
        'comments': [{'id': 40}, {'id': 42}, {'id': 43}]
    }
    mocked_response = MagicMock()
    mocked_response.json = MagicMock(return_value=json if json else default_json)
    monkeypatch.setattr(pagure.requests, 'get', MagicMock(return_value=mocked_response, side_effect=side_effect))

    return module


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(pagure.Pagure)[1]

    module._config['pull-request'] = ['rep-name:rep-pr-id']
    module._config['pagure-url'] = 'url'
    module._config['pagure-url-port'] = 'url-port'

    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/infrastructure/pagure.py', 'Pagure')


def test_pagure_api(module, monkeypatch, log):

    json = {'key': 'value'}
    module = patched_module(module, monkeypatch, json=json)

    pagure_api = pagure.PagureApi('url', 'url-port', module)

    output = pagure_api.get_pull_request_info('project-name', 'pr-id')
    assert output == {'key': 'value'}
    assert log.records[-2].message == '[Pagure API]: url/api/0/project-name/pull-request/pr-id'
    assert log.records[-1].message == """[Pagure API] output:
{
    "key": "value"
}"""

    output = pagure_api.get_project_info('project-name')
    assert output == {'key': 'value'}
    assert log.records[-2].message == '[Pagure API]: url/api/0/project-name'
    assert log.records[-1].message == """[Pagure API] output:
{
    "key": "value"
}"""

    assert pagure_api.get_clone_url('full-name') == 'url-port/full-name.git'
    assert pagure_api.get_pr_ui_url('full-name', 'pr-id') == 'url/full-name/pull-request/pr-id'

    # requests.get(url) raise an exception
    module = patched_module(module, monkeypatch, json=json, side_effect=Exception())

    with pytest.raises(gluetool.GlueError, match='Unable to get: url/location'):
        pagure_api._get_json('location')
    assert log.records[-1].message == '[Pagure API]: url/location'


def test_pull_request_id():
    pull_request_id = pagure.PullRequestID('repository-name', 'repository-pr-id')

    assert pull_request_id.__str__() == 'repository-name:repository-pr-id'
    assert pull_request_id.__repr__() == 'repository-name:repository-pr-id'

    pull_request_id = pagure.PullRequestID('repository-name', 'repository-pr-id', '42')

    assert isinstance(pull_request_id.comment_id, int)
    assert pull_request_id.__str__() == 'repository-name:repository-pr-id:42'
    assert pull_request_id.__repr__() == 'repository-name:repository-pr-id:42'


def test_pagure_project(module, monkeypatch):
    module = patched_module(module, monkeypatch)

    pagure_project = pagure.PagureProject(module, 'full-name')

    assert pagure_project.name == 'json-name'
    assert pagure_project.full_name == 'json-fullname'
    assert pagure_project.clone_url == 'url-port/full-name.git'


def test_pagure_pull_request(module, monkeypatch):
    module = patched_module(module, monkeypatch)

    # pull request without comments
    pull_request_id = pagure.PullRequestID('repository-name', 'repository-pr-id')
    pagure_pull_request = pagure.PagurePullRequest(module, pull_request_id)

    assert pagure_pull_request.id == 'repository-name:repository-pr-id'
    assert pagure_pull_request.dispatch_id == 'repository-name:repository-pr-id'
    assert pagure_pull_request.source_branch == 'json-branch-from'
    assert pagure_pull_request.destination_branch == 'json-branch'
    assert pagure_pull_request.issuer == 'json-user-name'
    assert pagure_pull_request.commit_start == 'json-commit-start'
    assert pagure_pull_request.commit_stop == 'json-commit-stop'
    assert pagure_pull_request.comments == []
    assert pagure_pull_request.url == 'url/repository-name/pull-request/repository-pr-id'

    # pull request with comments
    pull_request_id = pagure.PullRequestID('repository-name', 'repository-pr-id', '42')
    pagure_pull_request = pagure.PagurePullRequest(module, pull_request_id)

    assert pagure_pull_request.comments == [{'id': 40}, {'id': 42}]

    # pull request with wrong comment id
    pull_request_id = pagure.PullRequestID('repository-name', 'repository-pr-id', '999')
    with pytest.raises(gluetool.GlueError, match='Comment with id 999 not found'):
        pagure.PagurePullRequest(module, pull_request_id)


def test_eval_context_no_primary_task(module, log):
    assert module.eval_context == {}
    assert log.records[-1].message == 'No primary task available, cannot pass it to eval_context'


def test_eval_context(module, log):
    mocked_primary_task = MagicMock()
    mocked_primary_task.ARTIFACT_NAMESPACE = 'artifact-namespace'
    module._pull_requests = [mocked_primary_task]

    assert module.eval_context == {
        'ARTIFACT_TYPE': 'artifact-namespace',
        'PRIMARY_TASK': mocked_primary_task,
        'TASKS': [mocked_primary_task]
    }


def test_execute(module, monkeypatch, log):
    module = patched_module(module, monkeypatch)
    module.execute()

    assert 'Initialized with rep-name:rep-pr-id (url/rep-name/pull-request/rep-pr-id)' in log.records[-1].message
