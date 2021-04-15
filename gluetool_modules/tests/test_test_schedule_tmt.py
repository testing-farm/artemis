# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os

import pytest

import gluetool
import gluetool_modules.testing.test_schedule_tmt
from gluetool_modules.libs.test_schedule import TestScheduleResult
from gluetool_modules.testing.test_schedule_tmt import gather_plan_results, TestScheduleEntry

from . import create_module, check_loadable

ASSETS_DIR = os.path.join('gluetool_modules', 'tests', 'assets', 'test_schedule_tmt')


def _load_assets(name):
    return (
        name,
        gluetool.utils.load_yaml(os.path.join(ASSETS_DIR, '{}.yaml'.format(name))),
    )


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.testing.test_schedule_tmt.TestScheduleTMT)[1]

    return module


def test_sanity(module):
    assert isinstance(module, gluetool_modules.testing.test_schedule_tmt.TestScheduleTMT)


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/testing/test_schedule_tmt.py', 'TestScheduleTMT')


def test_shared(module):
    module.add_shared()

    for functions in ['create_test_schedule', 'run_test_schedule_entry', 'serialize_test_schedule_entry_results']:
        assert module.glue.has_shared(functions)


def _assert_results(results, expected_results):
    for result, expected in zip(results, expected_results):
        assert result.name == expected['name']
        assert result.result == expected['result']
        assert result.log == os.path.join(ASSETS_DIR, expected['log'])
        assert result.artifacts_dir == os.path.join(ASSETS_DIR, expected['artifacts_dir'])


@pytest.mark.parametrize('asset', [
        _load_assets('passed'),
        _load_assets('failed'),
        _load_assets('error'),
    ]
)
def test_gather_results(module, asset, monkeypatch):
    name, expected_results = asset

    schedule_entry = TestScheduleEntry(
        gluetool.log.Logging().get_logger(),
        # a plan always starts with slash
        '/{}'.format(name),
        'some-repo-dir'
    )

    outcome, results = gather_plan_results(schedule_entry, ASSETS_DIR)

    assert outcome == getattr(TestScheduleResult, expected_results['outcome'])
    _assert_results(results, expected_results['results'])
