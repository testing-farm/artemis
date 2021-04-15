# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import logging

import git
import pytest

from mock import MagicMock

import gluetool
from gluetool.log import Logging

import gluetool_modules.infrastructure.distgit
from gluetool_modules.infrastructure.distgit import DistGitRepository
from . import assert_shared, create_module, patch_shared, testing_asset

Response = collections.namedtuple('Response', ['status_code', 'content', 'text'])


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.infrastructure.distgit.DistGit)[1]


@pytest.fixture(name='dummy_repository')
def fixture_dummy_repository(module):
    return DistGitRepository(module, 'some-package', clone_url='some-clone-url', web_url='some-web-url', branch='some-branch')


@pytest.fixture(name='dummy_repository_path')
def fixture_dummy_repository_path(module):
    return DistGitRepository(
        module, 'some-package',
        clone_url='some-clone-url', web_url='some-web-url', branch='some-branch', path='some-path'
    )


@pytest.fixture(name='git_log', params=[
    ('systemd', {
        '1777110', '1702565'
    }),
    ('selinux-policy',  {
        '1782925', '1782925', '1779098', '1791557', '1790795', '1787298', '1778126', '1777761', '1777042'
    })
])
def fixture_git_log(request, module, monkeypatch, dummy_repository):
    with open(testing_asset('distgit', request.param[0]), 'r') as logfile:
        log = logfile.read()

    # could not use MagicMock because `log_blob` checks if log returns a string and we are using MagicMock
    class gitMock:
        def __init__(self, *args, **kwargs):
            pass

        def log(self, *args, **kwargs):
            return log

    monkeypatch.setattr(git, 'Git', gitMock)

    # we set the expected bugs to an instance variable, so we can consume it in the test
    module._expected_bugs = request.param[1]

    # set the required regex options for searching for dist-git bugs
    module._config['regex-resolves'] = '^\s*-?\s*Resolves?:'
    module._config['regex-bugzilla'] = '(?:(?:bug|bz|rhbz)\s*#?|#)\s*(\d+)'

    # required for sanity only, not used in tests really ...
    module._config['branch'] = 'some-branch'
    module._config['clone-url'] = 'some-clone-url'
    module._config['web-url'] = 'some-web-url'

    # initialize repository from path
    dummy_repository.initialize_from_path('fake/path')

    # sanity is required to run (it compiles regexes)
    module.sanity()

    return request.param


def test_sanity_shared(module):
    assert module.glue.has_shared('dist_git_repository') is True


@pytest.mark.parametrize('method', ['artifact'])
def test_sanity_missing_required_options(module, method):
    module._config['method'] = method

    with pytest.raises(gluetool.utils.IncompatibleOptionsError,
                       match="missing required options for method '{}'".format(method)):
        module.sanity()


def test_missing_primary_task(module):
    assert_shared('primary_task', module.execute)


def test_artifact(monkeypatch, module):
    module._config['method'] = 'artifact'

    mock_task = MagicMock(component='some-component')
    patch_shared(monkeypatch, module, {
        'primary_task': mock_task,
        'eval_context': {}
    })

    pattern_map_mock = MagicMock(match=MagicMock)

    monkeypatch.setattr(gluetool_modules.infrastructure.distgit, 'PatternMap', pattern_map_mock)
    monkeypatch.setattr(gluetool_modules.infrastructure.distgit, 'render_template', lambda a: 'a-value')

    module.execute()
    repository = module.dist_git_repository()

    assert repository.package == 'some-component'
    assert repository.clone_url == 'a-value'
    assert repository.web_url == 'a-value'
    assert repository.branch == 'a-value'


def test_artifact_override(monkeypatch, module):
    module._config['method'] = 'artifact'

    mock_task = MagicMock(component='some-component')
    patch_shared(monkeypatch, module, {
        'primary_task': mock_task,
        'eval_context': {}
    })

    pattern_map_mock = MagicMock(match=MagicMock)

    monkeypatch.setattr(gluetool_modules.infrastructure.distgit, 'PatternMap', pattern_map_mock)

    # note: make sure render_template does nothing, so the overridden parameter stays intact
    monkeypatch.setattr(gluetool_modules.infrastructure.distgit, 'render_template', lambda a: a)

    module._config['clone-url'] = 'override-clone-url'
    module._config['web-url'] = 'override-web-url'
    module._config['branch'] = 'override-branch'

    module.execute()
    repository = module.dist_git_repository()

    assert repository.package == 'some-component'
    assert repository.clone_url == 'override-clone-url'
    assert repository.web_url == 'override-web-url'
    assert repository.branch == 'override-branch'
    assert repository.ref == None


def test_eval_context(module, dummy_repository, monkeypatch):
    monkeypatch.setattr(module, '_repository', dummy_repository)

    assert module.eval_context['DIST_GIT_REPOSITORY'] is dummy_repository


def test_eval_context_recursion(module, monkeypatch):
    monkeypatch.setattr(gluetool_modules.libs, 'is_recursion', MagicMock(return_value=True))

    assert module.eval_context == {}


def test_repr(module, dummy_repository):
    assert dummy_repository.__repr__() == '<DistGitRepository(package="some-package", branch="some-branch")>'


class MockRequests(object):
    status_code = 200
    content = '# recipients: batman, robin\ndata'
    text = 'this is a test'

    def __enter__(self, *args):
        return self

    def __exit__(self, *args):
        pass

    @staticmethod
    def get(_):
        return Response(MockRequests.status_code, MockRequests.content, MockRequests.text)


def test_gating(module, dummy_repository, monkeypatch, log):
    # gating configuration found
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)

    assert dummy_repository.has_gating
    assert log.match(message=(
        "gating configuration 'some-web-url/plain/gating.yaml?id=some-branch':\n"
        "---v---v---v---v---v---\n"
        "# recipients: batman, robin\n"
        "data\n"
        "---^---^---^---^---^---"
    ))


def test_sti_tests(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)

    assert dummy_repository.sti_tests_url == 'some-web-url/tree/tests?id=some-branch'
    assert dummy_repository.has_sti_tests
    assert log.match(message='has STI tests')


def test_no_sti_tests(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)
    monkeypatch.setattr(MockRequests, 'status_code', 404)

    assert dummy_repository.has_sti_tests is False
    assert log.match(message='does not have STI tests')


def test_ci_config(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)

    assert dummy_repository.ci_config_url == 'some-web-url/plain/.fmf/version?id=some-branch'
    assert dummy_repository.has_ci_config
    assert log.match(message='contains CI configuration')


def test_no_ci_config(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)
    monkeypatch.setattr(MockRequests, 'status_code', 404)

    assert dummy_repository.has_ci_config is False
    assert log.match(message='does not contain CI configuration')


def test_rpminspect_yaml(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)

    assert dummy_repository.rpminspect_yaml == 'this is a test'
    assert dummy_repository.rpminspect_yaml
    assert log.match(message='contains rpminspect configuration')


def test_no_rpminspect_yaml(module, dummy_repository, monkeypatch, log):
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)
    monkeypatch.setattr(MockRequests, 'status_code', 404)

    assert dummy_repository.rpminspect_yaml is None
    assert log.match(message='does not contain rpminspect configuration')


def test_no_gating(module, dummy_repository, monkeypatch, log):
    # gating configuration not found
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)
    monkeypatch.setattr(MockRequests, 'status_code', 400)

    assert dummy_repository.has_gating is False
    assert log.match(message="dist-git repository has no gating.yaml 'some-web-url/plain/gating.yaml?id=some-branch'")


def test_repository_persistance(module, dummy_repository):
    module._repository = dummy_repository

    assert module.dist_git_repository() is dummy_repository


def test_gating_recipients(module, dummy_repository, monkeypatch):
    # gating configuration found
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)

    assert dummy_repository.gating_recipients == ['batman', 'robin']


def test_no_gating_recipients(module, dummy_repository, monkeypatch):
    # gating configuration found
    monkeypatch.setattr(gluetool.utils, 'requests', MockRequests)
    monkeypatch.setattr(MockRequests, 'content', 'data')

    assert dummy_repository.gating_recipients == []


@pytest.mark.parametrize('method', [
    'previous-tag-build',
    'previous-build',
    'specific-build'
])
def test_bugs(module, dummy_repository, git_log, monkeypatch, method):
    module._config['baseline-method'] = method
    module._config['git-repo-path'] = 'fake/path'
    module._repository = dummy_repository

    mock_previous_task = MagicMock(
        nvr='previous-nvr',
        url='previous-url',
        distgit_ref='123456'
    )

    mock_primary_task = MagicMock(
        nvr='primary-nvr',
        url='primary-url',
        latest_released=MagicMock(return_value=mock_previous_task),
        distgit_ref='789123'
    )

    patch_shared(monkeypatch, module, {
        'primary_task': mock_primary_task,
        'tasks': mock_previous_task
    })

    monkeypatch.setattr(dummy_repository, 'clone', MagicMock())

    assert module.dist_git_bugs() == module._expected_bugs


def test_repository_path(module, dummy_repository_path):
    assert dummy_repository_path.path == 'some-path'

    with pytest.raises(
        gluetool.GlueError,
        match=r"^Clone path does not match initialized repository, misunderstood arguments?"
    ):
        dummy_repository_path.clone(Logging.get_logger(), path='other-path')
