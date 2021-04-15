# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import pytest
import gluetool_modules.libs
from gluetool_modules.libs.brew_build_fail import BrewBuildFailedError
from mock import MagicMock
from gluetool_modules.testing.pull_request_builder import brew_builder
from gluetool import GlueCommandError
from . import create_module, patch_shared, check_loadable


RHPKG_OUTPUT = """
Created task: 123
Task info: dummy_brew_url
"""


@pytest.fixture(name='module')
def fixture_module():
    return create_module(brew_builder.BrewBuilder)[1]


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/testing/pull_request_builder/brew_builder.py', 'BrewBuilder')


def test_pass(tmp_path, module, monkeypatch):
    run_mock = MagicMock(return_value=(False, None, MagicMock(stdout=RHPKG_OUTPUT)))
    run_command = MagicMock()
    path_mock = MagicMock(return_value=tmp_path)

    monkeypatch.setattr(brew_builder, 'normalize_path', path_mock)
    monkeypatch.setattr(os.path, 'relpath', path_mock)
    monkeypatch.setattr(brew_builder, 'run_and_log', run_mock)
    monkeypatch.setattr(brew_builder, 'run_command', run_command)

    patch_shared(monkeypatch, module, {
        'src_rpm': (MagicMock(), MagicMock())
    })

    publish_result_mock = MagicMock()
    monkeypatch.setattr(brew_builder, 'publish_result', publish_result_mock)

    module.execute()

    publish_result_mock.assert_called_once_with(module, brew_builder.BrewBuildTestResult,
                                                'PASS', 'dummy_brew_url', None, None)


def test_fail(tmp_path, module, monkeypatch):
    process_output_mock = MagicMock(exit_code=1)

    run_log = MagicMock(return_value=(False, None, MagicMock(stdout=RHPKG_OUTPUT)))
    run_command = MagicMock(side_effect=BrewBuildFailedError('Wait for brew build finish failed', process_output_mock))
    path_mock = MagicMock(return_value=tmp_path)

    monkeypatch.setattr(brew_builder, 'normalize_path', path_mock)
    monkeypatch.setattr(os.path, 'relpath', path_mock)
    monkeypatch.setattr(brew_builder, 'run_and_log', run_log)
    monkeypatch.setattr(brew_builder, 'run_command', run_command)

    patch_shared(monkeypatch, module, {
        'src_rpm': (MagicMock(), MagicMock())
    })

    publish_result_mock = MagicMock()
    monkeypatch.setattr(brew_builder, 'publish_result', publish_result_mock)

    module.execute()

    publish_result_mock.assert_called_once_with(module, brew_builder.BrewBuildTestResult,
                                                'FAIL', None, 'Wait for brew build finish failed', process_output_mock)


def test_fail_src_rpm(tmp_path, module, monkeypatch):
    process_output_mock = MagicMock(exit_code=1)
    run_mock = MagicMock(return_value=(False, None, MagicMock(stdout=RHPKG_OUTPUT)))
    path_mock = MagicMock(return_value=tmp_path)

    monkeypatch.setattr(brew_builder, 'normalize_path', path_mock)
    monkeypatch.setattr(os.path, 'relpath', path_mock)
    monkeypatch.setattr(brew_builder, 'run_and_log', run_mock)

    src_rpm_mock = MagicMock(
        side_effect=gluetool_modules.libs.brew_build_fail.BrewBuildFailedError(
            'src_rpm build failed',
            process_output_mock
        )
    )

    patch_shared(monkeypatch, module, {}, callables={
        'src_rpm': src_rpm_mock
    })

    publish_result_mock = MagicMock()
    monkeypatch.setattr(brew_builder, 'publish_result', publish_result_mock)

    module.execute()

    publish_result_mock.assert_called_once_with(module, brew_builder.BrewBuildTestResult,
                                                'FAIL', None, 'src_rpm build failed', process_output_mock)
