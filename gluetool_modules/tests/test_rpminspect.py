# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import pytest

from mock import MagicMock
import __builtin__

import gluetool
from gluetool.utils import from_json
import gluetool_modules.static_analysis.rpminspect.rpminspect
from . import create_module, patch_shared, check_loadable

ALL_PASSED_STDOUT = "{}"

ALL_PASSED_PARSED_STDOUT = ""

STDOUT = """{
   "License": [
     {
       "message": "license-message1",
       "result": "OK",
       "remedy": "Remedy",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "license-message2",
       "result": "INFO",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "license-message3",
       "result": "VERIFY",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "license-message4",
       "result": "BAD",
       "waiver authorization": "Not Waivable"
     }
   ],
   "Payload": [
     {
       "result": "OK",
       "waiver authorization": "Not Waivable"
     }
   ],
   "Man pages": [
     {
       "message": "man-message1",
       "screendump": "man-screendump1",
       "result": "OK",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "man-message2",
       "result": "INFO",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "man-message3",
       "result": "VERIFY",
       "waiver authorization": "Not Waivable"
     },
     {
       "message": "man-message4",
       "result": "BAD",
       "waiver authorization": "Not Waivable"
     }
   ]
 }"""


ANALYSIS_PARSED_STDOUT = [
    {
        "data": {
            "item": "dummy-nvr",
            "newnvr": "dummy-nvr",
            "oldnvr": "",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.analysis",
            "ref_url": ""
        }
    },
    {
        "data": {
            "item": "dummy-nvr",
            "newnvr": "dummy-nvr",
            "oldnvr": "",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.analysis.license",
            "ref_url": "",
            "test_outputs": [
                {
                    "message": "license-message1",
                    "waiver_authorization": "Not Waivable",
                    'result': 'PASSED',
                    "remedy": "Remedy"
                },
                {
                    "message": "license-message2",
                    'result': 'INFO',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "license-message3",
                    'result': 'NEEDS_INSPECTION',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "license-message4",
                    'result': 'FAILED',
                    "waiver_authorization": "Not Waivable"
                }
            ]
        }
    },
    {
        "data": {
            "item": "dummy-nvr",
            "newnvr": "dummy-nvr",
            "oldnvr": "",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.analysis.man_pages",
            "ref_url": "",
            "test_outputs": [
                {
                    "message": "man-message1",
                    "screendump": "man-screendump1",
                    'result': 'PASSED',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message2",
                    'result': 'INFO',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message3",
                    'result': 'NEEDS_INSPECTION',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message4",
                    'result': 'FAILED',
                    "waiver_authorization": "Not Waivable"
                }
            ]
        }
    },
    {
        "data": {
            "item": "dummy-nvr",
            "newnvr": "dummy-nvr",
            "oldnvr": "",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build"
        },
        "outcome": "PASSED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.analysis.payload",
            "ref_url": "",
            "test_outputs": [
                {
                    'result': 'PASSED',
                    'waiver_authorization': 'Not Waivable'
                }]
        }
    }
]


COMPARISON_PARSED_STDOUT = [
    {
        "data": {
            "item": "dummy-nvr dummy-latest",
            "newnvr": "dummy-nvr",
            "oldnvr": "dummy-latest",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build_pair"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.comparison",
            "ref_url": ""
        }
    },
    {
        "data": {
            "item": "dummy-nvr dummy-latest",
            "newnvr": "dummy-nvr",
            "oldnvr": "dummy-latest",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build_pair"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.comparison.license",
            "ref_url": "",
            "test_outputs": [
                {
                    "message": "license-message1",
                    "waiver_authorization": "Not Waivable",
                    "remedy": "Remedy",
                    'result': 'PASSED'
                },
                {
                    "message": "license-message2",
                    'result': 'INFO',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "license-message3",
                    'result': 'NEEDS_INSPECTION',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "license-message4",
                    'result': 'FAILED',
                    "waiver_authorization": "Not Waivable"
                }
            ]
        }
    },
    {
        "data": {
            "item": "dummy-nvr dummy-latest",
            "newnvr": "dummy-nvr",
            "oldnvr": "dummy-latest",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build_pair"
        },
        "outcome": "FAILED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.comparison.man_pages",
            "ref_url": "",
            "test_outputs": [
                {
                    "message": "man-message1",
                    'result': 'PASSED',
                    "screendump": "man-screendump1",
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message2",
                    'result': 'INFO',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message3",
                    'result': 'NEEDS_INSPECTION',
                    "waiver_authorization": "Not Waivable"
                },
                {
                    "message": "man-message4",
                    'result': 'FAILED',
                    "waiver_authorization": "Not Waivable"
                }
            ]
        }
    },
    {
        "data": {
            "item": "dummy-nvr dummy-latest",
            "newnvr": "dummy-nvr",
            "oldnvr": "dummy-latest",
            "scratch": False,
            "taskid": 111111,
            "type": "brew_build_pair"
        },
        "outcome": "PASSED",
        "ref_url": "",
        "testcase": {
            "name": "dist.rpminspect.comparison.payload",
            "ref_url": "",
            "test_outputs": [
                {
                    'result': 'PASSED',
                    'waiver_authorization': 'Not Waivable'
                }]
        }
    },
]


@pytest.fixture(name='module')
def fixture_module(monkeypatch, tmpdir):
    workdir = tmpdir.mkdir('rpminspect-workdir')

    monkeypatch.setattr(
        gluetool_modules.static_analysis.rpminspect.rpminspect.tempfile,
        "mkdtemp",
        MagicMock(return_value=str(workdir))
    )

    module = create_module(gluetool_modules.static_analysis.rpminspect.rpminspect.CIRpminspect)[1]

    module._config['tests'] = ['ALL']
    module._config['type'] = 'comparison'
    module._config['results-file'] = 'results-file'
    module._config['artifacts-dir'] = 'artifacts'
    module._config['verbose-log-file'] = 'verbose'
    module._config['command-name'] = 'rpminspect'

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.baseline_task = MagicMock()
    mock_primary_task.baseline_task.nvr = 'dummy-latest'
    mock_primary_task.baseline_task.scratch = False
    mock_primary_task.scratch = False
    mock_primary_task.id = 111111
    module.task = mock_primary_task

    patch_shared(monkeypatch, module, {
        'primary_task': mock_primary_task,
        'results': MagicMock()
    })

    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/static_analysis/rpminspect/rpminspect.py', 'CIRpminspect')


def test_run_rpminspect(module, monkeypatch):

    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.baseline_task = MagicMock()
    mock_primary_task.baseline_task.nvr = 'dummy-latest'
    mock_primary_task.scratch = False
    mock_primary_task.baseline_task.scratch = False
    mock_primary_task.id = 111111

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')

    mock_command.assert_called_with(['rpminspect',
                                     '-v',
                                     '-w', 'workdir/artifacts',
                                     '-o', 'workdir/results-file',
                                     '-F', 'json',
                                     '-T', 'ALL',
                                     'dummy-latest', 'dummy-nvr'])


def test_run_rpminspect_scratch(module, monkeypatch):

    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.baseline_task = MagicMock()
    mock_primary_task.baseline_task.nvr = 'dummy-latest'
    mock_primary_task.scratch = True
    mock_primary_task.baseline_task.scratch = True
    mock_primary_task.id = 111111
    mock_primary_task.baseline_task.id = 222222

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')

    mock_command.assert_called_with(['rpminspect',
                                     '-v',
                                     '-w', 'workdir/artifacts',
                                     '-o', 'workdir/results-file',
                                     '-F', 'json',
                                     '-T', 'ALL',
                                     '222222', '111111'])


def test_run_rpminspect_profile(module, monkeypatch):

    module._config['profile'] = 'profile'

    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.baseline_task = MagicMock()
    mock_primary_task.baseline_task.nvr = 'dummy-latest'
    mock_primary_task.scratch = False
    mock_primary_task.baseline_task.scratch = False
    mock_primary_task.id = 111111

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')

    mock_command.assert_called_with(['rpminspect',
                                     '-v',
                                     '-w', 'workdir/artifacts',
                                     '-o', 'workdir/results-file',
                                     '-F', 'json',
                                     '-T', 'ALL',
                                     '-p', 'profile',
                                     'dummy-latest', 'dummy-nvr'])


def test_run_rpminspect_no_baseline(module, monkeypatch):

    mock_command = MagicMock()
    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.baseline_task = None

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    with pytest.raises(gluetool.GlueError, match=r"^Not provided baseline for comparison"):
        module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')


def test_run_rpminspect_fail(module, monkeypatch):

    mock_error = gluetool.GlueCommandError([], output=MagicMock(
        stdout='{"msg": "dummy error message"}', stderr='Some error', exit_code=2))

    mock_command_run = MagicMock(side_effect=mock_error)

    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    mock_primary_task = MagicMock()

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    with pytest.raises(gluetool.GlueError, match=r"^Rpminspect failed during execution with exit code 2"):
        module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')


def test_run_rpminspect_tests_failed(module, monkeypatch, log):

    mock_error = gluetool.GlueCommandError([], output=MagicMock(stdout='Tests failed', stderr='', exit_code=1))
    mock_command_run = MagicMock(side_effect=mock_error)

    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)

    mock_primary_task = MagicMock()

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module._run_rpminspect(mock_primary_task, ['ALL'], 'workdir')

    assert log.records[-1].message == "Result of testing: FAILED"


def test_parse_comparison_runinfo(module):
    stdout = from_json(STDOUT)

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.baseline_task = MagicMock()
    mock_primary_task.baseline_task.nvr = 'dummy-latest'
    mock_primary_task.scratch = False
    mock_primary_task.id = 111111

    assert COMPARISON_PARSED_STDOUT == module._parse_runinfo(mock_primary_task, stdout)


def test_parse_analysis_runinfo(module):
    module._config['type'] = 'analysis'
    stdout = from_json(STDOUT)

    mock_primary_task = MagicMock()
    mock_primary_task.nvr = 'dummy-nvr'
    mock_primary_task.scratch = False
    mock_primary_task.id = 111111

    assert ANALYSIS_PARSED_STDOUT == module._parse_runinfo(mock_primary_task, stdout)


def test_execute(module, monkeypatch, log):
    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    monkeypatch.setattr(gluetool.utils.Command, 'run', mock_command_run)
    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect, 'load_json', MagicMock(return_value={}))

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module.execute()
    mock_command_run.assert_called_once()

    assert 'Rpminspect results are in ' in log.records[-2].message
    assert log.records[-4].message == "running comparison for task '111111' compared to dummy-latest"
    assert log.records[-3].message == "Result of testing: PASSED"


def test_execute_no_latest(module, monkeypatch, log):
    module.task.baseline_task = None

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module.execute()

    assert log.records[-2].message == 'no baseline found, refusing to continue testing'
    assert log.records[-1].message == """result:
{
    "ids": {},
    "overall_result": "INFO",
    "payload": [
        {
            "data": {
                "item": "dummy-nvr",
                "scratch": false,
                "taskid": 111111,
                "type": "brew_build_pair"
            },
            "note": "No baseline found for the build. Testing skipped",
            "outcome": "INFO",
            "ref_url": "",
            "testcase": {
                "name": "dist.rpminspect.comparison",
                "ref_url": ""
            }
        }
    ],
    "result_class": "gluetool_modules.static_analysis.rpminspect.rpminspect.RpminspectSkippedTestResult",
    "test_type": "rpminspect-comparison",
    "urls": {}
}"""


def test_execute_nvr_is_latest(module, monkeypatch, log):
    module.task.baseline_task.nvr = module.task.nvr

    monkeypatch.setattr(__builtin__, 'open', MagicMock())

    module.execute()

    assert log.records[-1].message == 'cowardly refusing to compare same packages'


def test_sanity(module, monkeypatch):
    mock_check_for_command = MagicMock()
    monkeypatch.setattr(gluetool_modules.static_analysis.rpminspect.rpminspect,
                        'check_for_commands', mock_check_for_command)

    module.sanity()
    mock_check_for_command.assert_called_once_with(['rpminspect'])


def test_test_result_type():
    test_result = gluetool_modules.static_analysis.rpminspect.rpminspect.RpminspectTestResult(
        gluetool.glue, 'comparison', 'INFO')
    assert test_result.rpminspect_test_type == 'comparison'

    skipped_test_result = gluetool_modules.static_analysis.rpminspect.rpminspect.RpminspectSkippedTestResult(
        gluetool.glue)
    assert skipped_test_result.rpminspect_test_type == 'comparison'
