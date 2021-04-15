# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

from mock import MagicMock
from mock import call

import os
import __builtin__
import gluetool
from gluetool_modules.helpers import pagure_srpm
from . import create_module, patch_shared, check_loadable


PROJECT_NAME = 'dummy_project_name'


@pytest.fixture(name='module')
def fixture_module():
    return create_module(pagure_srpm.PagureSRPM)[1]


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/pagure_srpm.py', 'PagureSRPM')


def run_src_rpm(module, monkeypatch, command_calls):
    project_mock = MagicMock()
    project_mock.name = PROJECT_NAME
    project_mock.clone_url = 'dummy_clone_url'

    pull_request_id_mock = MagicMock(repository_pr_id=8)

    pull_request_mock = MagicMock()
    pull_request_mock.ARTIFACT_NAMESPACE = 'dist-git-pr'
    pull_request_mock.project = project_mock
    pull_request_mock.pull_request_id = pull_request_id_mock
    pull_request_mock.destination_branch = 'dummy_destination_branch'

    patch_shared(monkeypatch, module, {
        'primary_task': pull_request_mock
    })

    run_return_value_mock = MagicMock()
    run_return_value_mock.stdout = 'dummy_directory/dummy_src_rpm.srpm'

    run_mock = MagicMock(return_value=run_return_value_mock)
    monkeypatch.setattr(module, '_run_command', run_mock)

    rename_mock = MagicMock()
    monkeypatch.setattr(os, 'rename', rename_mock)

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    assert module.src_rpm() == ('dummy_src_rpm.srpm', PROJECT_NAME)
    rename_mock.assert_called_once_with('{}/dummy_project_name.spec'.format(PROJECT_NAME),
                                        '{}/dummy_project_name.spec.backup'.format(PROJECT_NAME))

    run_mock.assert_has_calls(command_calls, any_order=True)


def test_src_rpm(tmp_path, module, monkeypatch):
    path = tmp_path / "pagure.log"
    path_mock = MagicMock(return_value=path)
    monkeypatch.setattr(pagure_srpm, 'normalize_path', path_mock)
    monkeypatch.setattr(os.path, 'relpath', path_mock)

    calls = []

    calls.append(call(
        ['git', 'clone', '-b', 'dummy_destination_branch', 'dummy_clone_url'],
        path,
        'Clone git repository'
    ))
    calls.append(call(
        ['git', 'fetch', 'origin', 'refs/pull/8/head'],
        path,
        'Fetch pull request changes',
        PROJECT_NAME
    ))
    calls.append(call(
        ['git', 'merge', 'FETCH_HEAD', '-m', 'ci pr merge'],
        path,
        'Merge pull request changes',
        PROJECT_NAME
    ))
    calls.append(call(
        ['rhpkg', 'srpm'],
        path,
        'Make srpm',
        PROJECT_NAME
    ))

    run_src_rpm(module, monkeypatch, calls)


def test_src_rpm_additional_options(tmp_path, module, monkeypatch):
    path = tmp_path / "pagure.log"
    path_mock = MagicMock(return_value=path)
    monkeypatch.setattr(pagure_srpm, 'normalize_path', path_mock)
    monkeypatch.setattr(os.path, 'relpath', path_mock)

    calls = []

    module._config['git-clone-options'] = '--depth 1'
    module._config['git-fetch-options'] = '--multiple'
    module._config['git-merge-options'] = '--allow-unrelated-histories'

    calls.append(call(
        ['git', 'clone', '-b', 'dummy_destination_branch', 'dummy_clone_url', '--depth', '1'],
        path,
        'Clone git repository'
    ))
    calls.append(call(
        ['git', 'fetch', 'origin', 'refs/pull/8/head', '--multiple'],
        path,
        'Fetch pull request changes',
        PROJECT_NAME
    ))
    calls.append(call(
        ['git', 'merge', 'FETCH_HEAD', '-m', 'ci pr merge', '--allow-unrelated-histories'],
        path,
        'Merge pull request changes',
        PROJECT_NAME
    ))
    calls.append(call(
        ['rhpkg', 'srpm'],
        path,
        'Make srpm',
        PROJECT_NAME
    ))

    run_src_rpm(module, monkeypatch, calls)


def test_incompatible_type(module, monkeypatch):
    pull_request_mock = MagicMock()
    pull_request_mock.ARTIFACT_NAMESPACE = 'unsupported-artifact'

    patch_shared(monkeypatch, module, {
        'primary_task': pull_request_mock
    })

    with pytest.raises(gluetool.GlueError, match=r"^Incompatible artifact namespace: unsupported-artifact$"):
        module.src_rpm()
