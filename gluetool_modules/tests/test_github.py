# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import pytest
import re

import gluetool
import gluetool_modules.infrastructure.github
from . import create_module


ASSETS_DIR = os.path.join('gluetool_modules', 'tests', 'assets', 'github')
# NOTE(ivasilev) commits and commit_statuses are heavily mocked just to make depends-on tests pass
GET_COMMIT = {
  "commit": {
    "url": "https://api.github.com/repos/octocat/Hello-World/git/commits/6dcb09b5b57875f334f61aebed695e2e4193db5e",
    "author": {
      "name": "Monalisa Octocat",
      "email": "support@github.com",
      "date": "2011-04-14T16:00:49Z"},
    "message": "Some commit message"
    },
  "state": "mocked-to-make-tests-pass",
  "statuses": []
}


def _load_assets(name):
    return gluetool.utils.load_json(os.path.join(ASSETS_DIR, '{}.json'.format(name)))


@pytest.fixture
def module():
    github_module = create_module(gluetool_modules.infrastructure.github.GitHub)[1]
    github_module._config['pull-request'] = 'oamg:leapp-repository:620:7fb300d703abbd07e8834d121bd2ac3088535c8b'
    return github_module


def test_depends_on(module, monkeypatch):

    # Borrowed from copr test
    class dummy_request(object):
        def __init__(self, source):
            self.source = source
            self.content = str(self.source)
            self.status_code = 200

        def json(self):
            return self.source

    def mocked_get(url):
        if re.match(r'.*/pulls/\d+$', url):
            return dummy_request(_load_assets("fetch_pull_request"))
        elif re.match(r'.*/repos/oamg/leapp-repository/commits/.*', url):
            return dummy_request(GET_COMMIT)
        elif re.match(r'.*/repos/oamg/leapp-repository/pulls/\d+/commits', url):
            return dummy_request(_load_assets("list_pr_commits"))

    monkeypatch.setattr(gluetool_modules.infrastructure.github.requests, 'get', mocked_get)
    monkeypatch.setattr(gluetool_modules.infrastructure.github, 'is_json_response', lambda _: True)
    monkeypatch.setattr(gluetool_modules.infrastructure.github.GitHubAPI, 'is_collaborator', lambda a, b, c, d: False)
    assert module.eval_context == {}
    module.execute()

    eval_context = module.eval_context
    primary_task = module.primary_task()
    assert eval_context['PRIMARY_TASK'] == primary_task
    assert primary_task.depends_on == ['leapp-repository/PR42', 'anotherproject/PR4242', 'leapp/PR669']

# TODO technical debt - cover other test cases.
