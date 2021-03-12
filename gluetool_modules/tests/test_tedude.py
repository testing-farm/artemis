# test_tedude.py

import pytest  # main testing framework

import gluetool
import gluetool_modules.testing.tedude  # importing of a module that will be tested
import gluetool_modules.testing.testing_results
import gluetool_modules.helpers.rules_engine
from . import create_module, check_loadable, patch_shared, testing_asset  # helper function to easy creating of a module
from gluetool.utils import new_xml_element


BZ_QUERY_RESULTS = {
    111111: {
        'bug_id': 111111,
        'cf_devel_whiteboard': 'foo requires_ci_gating+ ci_tests_implemented bar'
    },
    222222: {
        'bug_id': 222222,
        'cf_devel_whiteboard': 'requires_ci_gating+'
    },
    333333: {
        'bug_id': 333333,
        'cf_devel_whiteboard': 'ci_tests_implemented bar'
    },
    444444: {
        'bug_id': 444444,
        'cf_devel_whiteboard': 'foo requires_ci_gating-'
    },
    555555: {
        'bug_id': 555555,
        'cf_devel_whiteboard': 'foo'
    },
    666666: {
        "message": "Could not get bugzilla data."
    }
}

GATING_TEST_STATUSES_NO_BUGS = [
    "passed",
    {
        'NO_BUGS_FOUND': {
            "message": "No bugs have been found in the changelog. This is acceptable.",
            "result": "passed"
        }
    }
]

GATING_TEST_STATUSES = [
    "failed",
    {
        'BZ#111111': {
            "message": "ci_tests_implemented: CI Gating tests are implemented.",
            "result": "passed"
        },
        'BZ#222222': {
            "message": "requires_ci_gating+: CI Gating tests are required but not implemented.",
            "result": "failed"
        },
        'BZ#333333': {
            "message": "ci_tests_implemented: CI Gating tests are implemented.",
            "result": "passed"
        },
        'BZ#444444': {
            "message": "requires_ci_gating-: CI Gating tests are not required.",
            "result": "passed"
        },
        'BZ#555555': {
            "message": "CI Gating tests decission is missing.",
            "result": "failed"
        },
        'BZ#666666': {
            "message": "Could not access required attribute, wrong attribute or insufficent bugzilla permissions?",
            "result": "failed"
        }
    }
]


# The fixture provides a created module, the main access to a module for testing.
@pytest.fixture(name='module')
def fixture_module():
    # the function returns glue and module instances. We are interested in the module only.
    return create_module(gluetool_modules.testing.tedude.TeDuDe)[1]


@pytest.fixture(name='module_with_results')
def fixture_module_with_results():
    # the function returns glue and module instances. We are interested in the module only.
    ci, module = create_module(gluetool_modules.testing.tedude.TeDuDe)
    module_results = gluetool_modules.testing.testing_results.TestingResults(ci, "dummy_results_module")
    module_results.add_shared()
    return module


@pytest.fixture(name='rules_engine')
def fixture_rules_engine():
    return create_module(gluetool_modules.helpers.rules_engine.RulesEngine)[1]


# The fixture provides a created module, the main access to a module for testing.
@pytest.fixture(name='result')
def fixture_result(module):
    # the function returns glue and module instances. We are interested in the module only.
    return create_module(gluetool_modules.testing.tedude.TeDuDeTestResult, add_shared=False)[1]


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/testing/tedude.py', 'TeDuDe')


def test_sanity_shared(module):
    assert module.glue.has_shared('tedude_xunit_serialize') is True


def test_tedude_test_statuses_no_bugs(module, monkeypatch, rules_engine):
    module._config['instructions'] = testing_asset('tedude', 'sst_platform_security.yaml')
    module._config['bugzilla-attributes'] = 'cf_devel_whiteboard'

    patch_shared(monkeypatch, module, {
        'bugzilla_attributes': {},
        'dist_git_bugs': []
    }, callables={
        'evaluate_instructions': rules_engine.evaluate_instructions
    })
    result, statuses = module._tedude_test_statuses
    assert result == GATING_TEST_STATUSES_NO_BUGS[0]
    assert statuses == GATING_TEST_STATUSES_NO_BUGS[1]


def test_tedude_test_statuses(module, monkeypatch, rules_engine):
    module._config['instructions'] = testing_asset('tedude', 'sst_platform_security.yaml')
    module._config['bugzilla-attributes'] = 'cf_devel_whiteboard'

    patch_shared(monkeypatch, module, {
        'bugzilla_attributes': BZ_QUERY_RESULTS,
        'dist_git_bugs': map(str, BZ_QUERY_RESULTS.keys())
    }, callables={
        'evaluate_instructions': rules_engine.evaluate_instructions
    })
    result, statuses = module._tedude_test_statuses
    assert result == GATING_TEST_STATUSES[0]
    assert statuses == GATING_TEST_STATUSES[1]


def test_execute(module_with_results, monkeypatch, rules_engine, log):
    module_with_results._config['instructions'] = testing_asset('tedude', 'sst_platform_security.yaml')
    module_with_results._config['bugzilla-attributes'] = 'cf_devel_whiteboard'
    patch_shared(monkeypatch, module_with_results, {
        'bugzilla_attributes': BZ_QUERY_RESULTS,
        'dist_git_bugs': map(str, BZ_QUERY_RESULTS.keys())
    }, callables={
        'evaluate_instructions': rules_engine.evaluate_instructions,
    })
    module_with_results.execute()
    assert log.records[-1].message == """result:
{
    "ids": {},
    "overall_result": "failed",
    "payload": {
        "BZ#111111": {
            "message": "ci_tests_implemented: CI Gating tests are implemented.",
            "result": "passed"
        },
        "BZ#222222": {
            "message": "requires_ci_gating+: CI Gating tests are required but not implemented.",
            "result": "failed"
        },
        "BZ#333333": {
            "message": "ci_tests_implemented: CI Gating tests are implemented.",
            "result": "passed"
        },
        "BZ#444444": {
            "message": "requires_ci_gating-: CI Gating tests are not required.",
            "result": "passed"
        },
        "BZ#555555": {
            "message": "CI Gating tests decission is missing.",
            "result": "failed"
        },
        "BZ#666666": {
            "message": "Could not access required attribute, wrong attribute or insufficent bugzilla permissions?",
            "result": "failed"
        }
    },
    "result_class": "gluetool_modules.testing.tedude.TeDuDeTestResult",
    "test_type": "tedude",
    "urls": {}
}"""


def test_tedude_xunit_serialize(module_with_results, result):
    result.payload = GATING_TEST_STATUSES[1]
    testsuite = new_xml_element('testsuite')
    testsuite = module_with_results.tedude_xunit_serialize(testsuite, result)
    assert testsuite.find('testcase', attrs={'name': 'BZ#111111'})
    assert testsuite.find('testcase', attrs={'name': 'BZ#222222'})
    assert testsuite.find('testcase', attrs={'name': 'BZ#333333'})
    assert testsuite.find('testcase', attrs={'name': 'BZ#444444'})
    assert testsuite.find('testcase', attrs={'name': 'BZ#555555'})
    assert testsuite.find('testcase', attrs={'name': 'BZ#666666'})
