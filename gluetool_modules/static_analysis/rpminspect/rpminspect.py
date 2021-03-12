import enum
import os
import re
import shutil
import stat
import tempfile

import gluetool
from gluetool import GlueError, GlueCommandError
from gluetool.utils import Command, check_for_commands, load_json, normalize_multistring_option, new_xml_element
from gluetool.log import format_blob, log_blob
from gluetool_modules.libs.artifacts import artifacts_location
from gluetool_modules.libs.results import TestResult, publish_result

# Type annotations
from typing import cast, TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Type, Union  # noqa

if TYPE_CHECKING:
    from gluetool.utils import ProcessOutput  # noqa

# Map RPMINSPECT_SCORE to resultsdb 2.0 API outcome states - http://docs.resultsdb20.apiary.io/
# Note: WAIVED score is mapped to INFO
RPMINSPECT_MAP = ['INFO', 'PASSED', 'INFO', 'NEEDS_INSPECTION', 'FAILED']

# Helping dict for calculating overall_result
# Note: numbers represent the priority of the result and also position in RPMINSPECT_MAP list
RPMINSPECT_SCORE = {
    'INFO': 0,
    'OK': 1,
    'WAIVED': 2,
    'VERIFY': 3,
    'BAD': 4
}


class RpminspectExitCodes(enum.IntEnum):
    RPMINSPECT_TESTS_SUCCESS = 0
    RPMINSPECT_TESTS_FAILURE = 1
    RPMINSPECT_PROGRAM_ERROR = 2


class RpminspectTestResult(TestResult):
    """
    RPMinspect test result data container

    :param str test_type: one of 'analysis', 'comparison'
    :param str overall_result: general result of a test
    """

    def __init__(self, glue, test_type, overall_result, **kwargs):
        # type: (gluetool.glue.Glue, str, str, **Any) -> None

        super(RpminspectTestResult, self).__init__(glue, 'rpminspect-{}'.format(test_type), overall_result, **kwargs)
        self.rpminspect_test_type = test_type

    @property
    def test_results(self):
        # type: () -> Dict[str, str]
        """
        Return dict with name of test as a key
        and it result as a value

        :rtype: dict
        :returns Dictionary with results of every test
        """
        test_results = {}

        # first value is an overall result, skip it
        for result in self.payload[1:]:
            test_name = result['testcase']['name'].split('.')[-1]
            test_results[test_name] = result['outcome']

        return test_results

    def _serialize_to_xunit_property_dict(self, parent, properties, names):
        # type: (Any, Any, Any) -> None

        if 'data' in self.payload[0]:

            rpminspect_data = self.payload[0]['data']
            for item in rpminspect_data:
                new_xml_element('property', parent,
                                name='rpminspect.{}'.format(item),
                                value=rpminspect_data[item])

        super(RpminspectTestResult, self)._serialize_to_xunit_property_dict(parent, properties, names)

    def _serialize_to_xunit(self):
        # type: () -> Any
        test_suite = super(RpminspectTestResult, self)._serialize_to_xunit()

        test_suite = self.glue.shared('rpminspect_xunit_serialize', test_suite, self)

        return test_suite


class RpminspectSkippedTestResult(TestResult):
    """
    RPMinspect test result data container for a skipped test result
    """

    def __init__(self, glue, **kwargs):
        # type: (gluetool.glue.Glue, **Any) -> None
        super(RpminspectSkippedTestResult, self).__init__(glue, 'rpminspect-comparison', 'INFO', **kwargs)
        self.rpminspect_test_type = 'comparison'
        self.test_results = {'ALL': 'SKIPPED'}  # notification for users, will be visible in email


class CIRpminspect(gluetool.Module):

    name = 'rpminspect'
    description = 'Run RPMinspect analysis or comparison'

    # pylint: disable=gluetool-option-hard-default
    options = {
        'command-name': {
            'help': 'Name of the rpminspect command to execute (default: %(default)s)',
            'metavar': 'COMMAND',
            'type': str,
            'default': 'rpminspect'
        },
        'type': {
            'help': 'Test type: analysis or comparison (default: %(default)s)',
            'metavar': 'TYPE',
            'type': str,
            'choices': ['analysis', 'comparison'],
            'default': 'comparison'
        },
        'tests': {
            'help': """
                    List of tests to perform. If nothing is set, all tests would run. Run `rpminspect -l`
                    to find out a list of all available types of tests  (default: ALL)
                    """,
            'metavar': 'TESTS',
            'action': 'append',
            'default': []
        },
        'profile': {
            'help': "RPMinspect profile to use.",
            'type': str,
            'metavar': 'NAME',
        },
        'results-file': {
            'help': 'A file for storing not formated rpminspect results (default: %(default)s)',
            'metavar': 'FILE',
            'type': str,
            'default': ''
        },
        'verbose-log-file': {
            'help': 'A file for storing verbose log of rpminspect run (default: %(default)s)',
            'metavar': 'FILE',
            'type': str,
            'default': ''
        },
        'artifacts-dir': {
            'help': 'A directory for storing artifacts (default: %(default)s)',
            'metavar': 'DIR',
            'type': str,
            'default': 'artifacts'
        }
    }

    shared_functions = ['rpminspect_xunit_serialize', ]

    def sanity(self):
        # type: () -> None

        check_for_commands([self.option('command-name')])

    def _rpminspect_cmd(self, tests, workdir):
        # type: (List[str], str) -> List[str]

        cmd = [
            self.option('command-name'),
            '-v',
            # give a subfolder as a workdir to rpminspect for easy deleting it later
            '-w', os.path.join(workdir, self.option('artifacts-dir')),
            '-o', os.path.join(workdir, self.option('results-file')),
            '-F', 'json',
            '-T', ','.join(tests) if tests and tests != [''] else 'ALL'
        ]

        if self.option('profile'):
            cmd += ['-p', self.option('profile')]

        return cmd

    def _run_rpminspect(self, task, tests, workdir):
        # type: (Any, List[str], str) -> None
        """
        Execute RPMinspect analysis or comparison based on test type.
        Store results and verbose log to a separate files.

        :param task: a task for analysis
        :param workdir: a workdir for storing logs and temporary artifacts
        """

        command = self._rpminspect_cmd(tests, workdir)

        if self.option('type') == 'comparison':
            if task.baseline_task is None:
                raise GlueError('Not provided baseline for comparison')
            command.append(str(task.baseline_task.id) if task.baseline_task.scratch else task.baseline_task.nvr)

        command.append(str(task.id) if task.scratch else task.nvr)

        def _write_log(output):
            # type: (ProcessOutput) -> None
            """
            Store a verbose log to a file
            :param log: a log string
            """
            if output is None:
                return

            with open(os.path.join(workdir, self.option('verbose-log-file')), 'w') as output_file:
                def _write(label, s):
                    # type: (str, str) -> None
                    output_file.write('{}\n{}\n\n'.format(label, s))

                _write('# STDOUT:', format_blob(cast(str, output.stdout)))
                _write('# STDERR:', format_blob(cast(str, output.stderr)))

                output_file.flush()

        try:
            output = Command(command).run()
            self.info('Result of testing: PASSED')
            _write_log(output)

        except GlueCommandError as exc:
            _write_log(exc.output)

            if exc.output.exit_code == RpminspectExitCodes.RPMINSPECT_TESTS_FAILURE:
                self.error('Result of testing: FAILED')
            else:
                if exc.output.stderr is not None:
                    log_blob(self.error, 'Rpminspect stderr', exc.output.stderr)
                raise GlueError('Rpminspect failed during execution with exit code {}'.format(exc.output.exit_code))

        # output is verbose log, store it to a file

    def _publish_skipped_result(self, task):
        # type: (Any) -> None
        """
        Publish a skipped test result.
        """
        result = [{
            'data': {
                'item': task.nvr,
                'type': 'brew_build_pair',
                'scratch': task.scratch,
                'taskid': task.id
            },
            'ref_url': '',
            'testcase': {
                'name': 'dist.rpminspect.comparison',
                'ref_url': '',
            },
            'outcome': 'INFO',
            'note': 'No baseline found for the build. Testing skipped'
        }]

        publish_result(self, RpminspectSkippedTestResult, payload=result)

    def _parse_runinfo(self, task, json_output):
        # type: (Any, Dict[str, List[Dict[str, str]]]) -> Any
        """
        Return parsed runinfo into known structure.

        :param task: info about task
        :param dict runinfo: informations about RPMinspect run
        """
        test_type = self.option('type')

        if test_type == 'comparison':
            result_type = 'brew_build_pair'
            item = '{} {}'.format(task.nvr, task.baseline_task.nvr)
        else:
            result_type = 'brew_build'
            item = task.nvr

        # Get the worst result of all tests is overall
        overall_result = 'OK'
        for test_info in json_output.values():
            for test_entry in test_info:
                if RPMINSPECT_SCORE[test_entry['result']] > RPMINSPECT_SCORE[overall_result]:
                    overall_result = test_entry['result']

        # Map to result consistent with resultsdb
        overall_result = RPMINSPECT_MAP[RPMINSPECT_SCORE[overall_result]]

        # Basic result data and overall result
        payload = [{
            'data': {
                'item': item,
                'type': result_type,
                'newnvr': task.nvr,
                'oldnvr': task.baseline_task.nvr if self.option('type') == 'comparison' else '',
                'scratch': task.scratch,
                'taskid': task.id
            },
            'ref_url': '',
            'testcase': {
                'name': 'dist.rpminspect.{}'.format(test_type),
                'ref_url': ''
            },
            'outcome': overall_result
        }]

        def _parse_results(data):
            # type: (Dict[str, List[Dict[str, str]]]) -> List[Dict[str, Any]]
            parsed_results = []

            # Parse results for every test.
            for test_name, test_info in data.iteritems():

                # Return the worst result from test
                def _outcome():
                    # type: () -> str
                    if not test_info:
                        return 'PASSED'

                    return RPMINSPECT_MAP[
                        max([RPMINSPECT_SCORE[test_entry['result']] for test_entry in test_info])
                    ]

                def _test_outputs():
                    # type: () -> List[Dict[str, str]]
                    test_outputs = []
                    for test_entry in test_info:
                        output = {}
                        if 'message' in test_entry:
                            output['message'] = test_entry['message']
                        if 'result' in test_entry:
                            output['result'] = RPMINSPECT_MAP[RPMINSPECT_SCORE[test_entry['result']]]
                        if 'screendump' in test_entry:
                            output['screendump'] = test_entry['screendump']
                        if 'remedy' in test_entry:
                            output['remedy'] = test_entry['remedy']
                        if 'waiver authorization' in test_entry:
                            output['waiver_authorization'] = test_entry['waiver authorization']

                        if output:
                            test_outputs.append(output)
                    return test_outputs

                # Make lowercase test_name, change spaces to underlines
                description = re.sub('[ ]', '_', test_name.lower())
                parsed_results.append({
                    'data': {
                        'item': item,
                        'type': result_type,
                        'newnvr': task.nvr,
                        'oldnvr': task.baseline_task.nvr if self.option('type') == 'comparison' else '',
                        'scratch': task.scratch,
                        'taskid': task.id
                    },
                    'ref_url': '',
                    'testcase': {
                        'name': 'dist.rpminspect.{}.{}'.format(test_type, description),
                        'ref_url': '',
                        'test_outputs': _test_outputs() if test_info else []
                    },
                    'outcome': _outcome()
                })
            return parsed_results

        payload.extend(_parse_results(json_output))

        # Return sorted list - the key is a testcase name. This presents deterministic output one can test.
        return sorted(payload, key=lambda x: x['testcase']['name'])

    def _publish_results(self, task, json_output):
        # type: (Any, Dict[str, List[Dict[str, str]]]) -> None

        payload = self._parse_runinfo(task, json_output)
        overall_result = payload[0]['outcome']
        publish_result(self, RpminspectTestResult, self.option('type'), overall_result, payload=payload)

    def rpminspect_xunit_serialize(self, test_suite, result):
        # type: (Any, Any, Any) -> Any

        if not result.payload:
            return test_suite

        for _test in result.payload:

            outcome = _test['outcome']
            testcase = _test['testcase']

            test_case = new_xml_element(
                'testcase',
                _parent=test_suite,
                name=testcase['name']
            )

            properties = new_xml_element('properties', _parent=test_case)
            new_xml_element('property', _parent=properties, name='outcome', value=outcome)

            if outcome in RPMINSPECT_MAP:

                outcome_index = RPMINSPECT_MAP.index(outcome)
                fail_indexes = [
                    RPMINSPECT_MAP.index('NEEDS_INSPECTION'),
                    RPMINSPECT_MAP.index('FAILED')
                ]

                if outcome_index in fail_indexes:
                    new_xml_element('failure', _parent=test_case, message="Test failed")

            else:
                self.warn('Unknown outcome {} in test {}', outcome, testcase['name'])

            logs = new_xml_element('logs', _parent=test_case)
            new_xml_element('log',
                            _parent=logs,
                            href=artifacts_location(self, 'results.json', logger=self.logger),
                            name='results.json')

            if 'test_outputs' in testcase:

                test_outputs = new_xml_element(
                    'test-outputs',
                    _parent=test_case
                )

                for test_output in testcase['test_outputs']:
                    new_xml_element(
                        'test-output',
                        _parent=test_outputs,
                        **test_output
                    )

        return test_suite

    def execute(self):
        # type: () -> None

        # Module create workdir with logs and artifacts which is very large.
        # Finally block deletes artifact after execution even the error occurs.
        # It can't be done in destroy method for multithread supporting.
        try:
            tests = normalize_multistring_option(self.option('tests'))
            test_type = self.option('type')

            workdir = os.path.relpath(tempfile.mkdtemp(dir=os.getcwd()), os.getcwd())

            # Fixing permissions of workdir which, created via `mkdtemp`, is set to u=rwx,go= only.
            os.chmod(
                workdir,
                stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
            )

            self.require_shared('primary_task')
            task = self.shared('primary_task')

            if test_type == 'comparison':
                if not task.baseline_task:
                    self.warn('no baseline found, refusing to continue testing')
                    self._publish_skipped_result(task)
                    return
                if task.baseline_task.nvr == task.nvr:
                    self.warn('cowardly refusing to compare same packages')
                    return

            msg = ["running {} for task '{}'".format(test_type, task.id)]

            if test_type == 'comparison' and task.baseline_task:
                msg += ['compared to {}'.format(task.baseline_task.nvr)]

            self.info(' '.join(msg))

            self._run_rpminspect(task, tests, workdir)

            results_filepath = os.path.join(workdir, self.option('results-file'))
            results_location = artifacts_location(self, results_filepath, logger=self.logger)

            self.info('Rpminspect results are in {}'.format(results_location))

            json_results = load_json(results_filepath)

            self._publish_results(task, json_results)

        finally:
            if os.path.exists(os.path.join(workdir, self.option('artifacts-dir'))):
                shutil.rmtree(os.path.join(workdir, self.option('artifacts-dir')))
