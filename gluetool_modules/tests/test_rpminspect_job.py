# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

import gluetool_modules.static_analysis.rpminspect.rpminspect_job

from gluetool_modules.tests.test_dispatch_job import test_dispatch as basic_test_dispatch
from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.static_analysis.rpminspect.rpminspect_job.RpminspectJob)


def test_loadable(module):
    glue, _ = module

    check_loadable(glue, 'gluetool_modules/static_analysis/rpminspect/rpminspect_job.py', 'RpminspectJob')


def test_dispatch_analysis(module, monkeypatch):
    _, mod = module

    mod._config['type'] = 'analysis'

    basic_test_dispatch(mod, monkeypatch, job_name='ci-test-brew-rpminspect_analysis')


def test_dispatch_comparison(module, monkeypatch):
    _, mod = module

    mod._config['type'] = 'comparison'

    basic_test_dispatch(mod, monkeypatch, job_name='ci-test-brew-rpminspect_comparison')
