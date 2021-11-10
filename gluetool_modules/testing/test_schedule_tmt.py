# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import stat
import sys
import tempfile

import enum
import six

import gluetool
from gluetool import GlueError, GlueCommandError, Module
from gluetool.action import Action
from gluetool.log import Logging, format_blob, log_blob, log_dict
from gluetool.log import ContextAdapter, LoggingFunctionType  # Ignore PyUnusedCodeBear
from gluetool.utils import Command, load_yaml, new_xml_element, dict_update

from gluetool_modules.libs import create_inspect_callback, sort_children
from gluetool_modules.libs.artifacts import artifacts_location
from gluetool_modules.libs.testing_environment import TestingEnvironment
from gluetool_modules.libs.test_schedule import TestSchedule, TestScheduleResult, TestScheduleEntryOutput, \
    TestScheduleEntryStage
from gluetool_modules.libs.test_schedule import TestScheduleEntry as BaseTestScheduleEntry

# Type annotations
from typing import cast, Any, Callable, Dict, List, Optional, Tuple  # noqa

# Type annotations
from typing import Any, Dict, List, NamedTuple, Optional  # noqa

# TMT run log file
TMT_LOG = 'tmt-run.log'

# Weight of a test result, used to count the overall result. Higher weight has precendence
# when counting the overall result. See https://tmt.readthedocs.io/en/latest/spec/steps.html#execute
RESULT_WEIGHT = {
    'pass': 0,
    'info': 0,
    'fail': 1,
    'warn': 1,
    'error': 2,
}

# Map tmt results to our expected results
#
# Note that we comply to
#
#     https://pagure.io/fedora-ci/messages/blob/master/f/schemas/test-complete.yaml
#
# TMT recognized `error` for a test, but we do not translate it to a TestScheduleResult
# error, as this error is user facing, nothing we can do about it to fix it, it is his problem.
#
# For more context see: https://pagure.io/fedora-ci/messages/pull-request/86
RESULT_OUTCOME = {
    'pass': 'passed',
    'info': 'info',
    'fail': 'failed',
    'warn': 'needs_inspection',
    'error': 'error'
}

# Result weight to TestScheduleResult outcome
#
#     https://tmt.readthedocs.io/en/latest/overview.html#exit-codes
#
# All tmt errors are connected to tests or config, so only higher return code than 3
# is treated as error
PLAN_OUTCOME = {
    0: TestScheduleResult.PASSED,
    1: TestScheduleResult.FAILED,
    2: TestScheduleResult.FAILED,
}

# Results YAML file, contains list of test run results, relative to plan workdir
RESULTS_YAML = "execute/results.yaml"

#: Represents a test run result
#:
#: :ivar name: name of the test.
#: :ivar result: test result.
#: :ivar log: output log of the test.
#: :ivar artifacts_dir: directory
TestResult = NamedTuple('TestResult', (
    ('name', str),
    ('result', str),
    ('log', str),
    ('artifacts_dir', str)
))


# https://tmt.readthedocs.io/en/latest/overview.html#exit-codes
class TMTExitCodes(enum.IntEnum):
    TESTS_PASSED = 0
    TESTS_FAILED = 1
    TESTS_ERROR = 2
    RESULTS_MISSING = 3


class TestScheduleEntry(BaseTestScheduleEntry):
    def __init__(self, logger, plan, repodir):
        # type: (ContextAdapter, str, Dict[str, Any]) -> None
        """
        Test schedule entry, suited for use with TMT runners.

        :param ContextAdapter logger: logger used as a parent of this entry's own logger.
        :param str plan: Name of the plan.
        """

        # As the ID use the test plan name
        super(TestScheduleEntry, self).__init__(
            logger,
            plan,
            'tmt'
        )

        self.plan = plan
        self.work_dirpath = None  # type: Optional[str]
        self.results = None  # type: Any
        self.repodir = repodir

    def log_entry(self, log_fn=None):
        # type: (Optional[LoggingFunctionType]) -> None

        log_fn = log_fn or self.debug

        super(TestScheduleEntry, self).log_entry(log_fn=log_fn)

        log_fn('plan: {}'.format(self.plan))


#: Represents run of one plan and results of this run.
#:
#: :ivar str name: name of the plan.
#: :ivar libs.test_schedule.TestScheduleEntry schedule_entry: test schedule entry the task belongs to.
#: :ivar result: overall result of the plan - i.e. agregation of all test results
#: :ivar dict results: result of the plan run, as reported by tmt.
PlanRun = NamedTuple('PlanRun', (
    ('name', str),
    ('schedule_entry', TestScheduleEntry),
    ('result', str),
    ('results', List[TestResult])
))


def gather_plan_results(schedule_entry, work_dir):
    # type: (TestScheduleEntry, str) -> Tuple[TestScheduleResult, List[TestResult]]
    """
    Extracts plan results from tmt logs.

    :param TestScheduleEntry schedule_entry: Plan schedule entry.
    :param str work_dir: Plan working directory.
    :rtype: tuple
    :returns: A tuple with overall_result and results detected for the plan.
    """
    test_results = []  # type: List[TestResult]

    # TMT uses plan name as a relative directory to the working directory, but
    # plan start's with '/' character, strip it so we can use it with os.path.join
    plan_path = schedule_entry.plan[1:]

    results_yaml = os.path.join(work_dir, plan_path, RESULTS_YAML)

    if not os.path.exists(results_yaml):
        schedule_entry.warn("Could not find results file '{}' containing tmt results".format(results_yaml), sentry=True)
        return TestScheduleResult.ERROR, test_results

    # load test results from `results.yaml` which is created in tmt's execute step
    # https://tmt.readthedocs.io/en/latest/spec/steps.html#execute
    try:
        results = load_yaml(results_yaml)
        log_dict(schedule_entry.debug, "loaded results from '{}'".format(results_yaml), results)

    except GlueError as error:
        schedule_entry.warn('Could not load results.yaml file: {}'.format(error))
        return TestScheduleResult.ERROR, results

    # iterate through all the test results and create TestResult for each
    for name, data in results.iteritems():

        # translate result outcome
        try:
            outcome = RESULT_OUTCOME[data['result']]
        except KeyError:
            schedule_entry.warn("Encountered invalid result '{}' in runner results".format(data['result']))
            return TestScheduleResult.ERROR, results

        # log can be a string or a list, in case it is a list, the main log is the first one
        log = data['log'][0] if isinstance(data['log'], list) else data['log']

        # get the relative path to the log file
        test_log_path = os.path.join(work_dir, plan_path, 'execute', log)

        # NOTE: directory of log file is used as artifacts log, in case the tests produced more log files
        test_results.append(TestResult(
            name,
            outcome,
            test_log_path,
            os.path.split(test_log_path)[0]
        ))

    # count the maximum result weight encountered, i.e. the overall result
    max_weight = max(RESULT_WEIGHT[data['result']] for _, data in results.iteritems())

    return PLAN_OUTCOME[max_weight], test_results


class TestScheduleTMT(Module):
    """
    Creates test schedule entries for ``test-scheduler`` module by inspecting FMF configuration using TMT tool.

        `<https://tmt.readthedocs.io>`

    It executes each plan in a separate schedule entry using ``tmt run``. For execution it uses ``how=connect``
    for the provision step.
    """

    name = 'test-schedule-tmt'
    description = 'Create test schedule entries for ``test-scheduler`` module by inspecting FMF configuration via TMT.'
    options = [
        ('TMT options', {
            'command': {
                'help': 'TMT command to use (default: %(default)s).',
                'default': 'tmt'
            },
            'plan-filter': {
                'help': "Use the given filter passed to 'tmt plan ls --filter'. See pydoc fmf.filter for details.",
                'metavar': 'FILTER'
            }
        })
    ]

    shared_functions = ['create_test_schedule', 'run_test_schedule_entry', 'serialize_test_schedule_entry_results']

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(TestScheduleTMT, self).__init__(*args, **kwargs)

    def _plans_from_dist_git(self, repodir, filter=None):
        # type: (str, Optional[str]) -> List[str]
        """
        Return list of plans from given repository.

        :param str repodir: clone of a dist-git repository.
        :param str filter: use the given filter when listing plans.
        """

        command = [self.option('command'), 'plan', 'ls']

        if filter:
            command.append(['--filter', filter])

        try:
            tmt_output = Command(command).run(cwd=repodir)

        except GlueCommandError as exc:
            assert exc.output.stderr
            log_dict(self.error, "Failed to get list of plans", {
                'command': ' '.join(command),
                'exception': exc.output.stderr
            })
            six.reraise(*sys.exc_info())

        assert tmt_output.stdout

        output_lines = [line.strip() for line in tmt_output.stdout.splitlines()]

        # TMT emits warnings to stdout, spoiling the actual output, and we have to remove them before we consume
        # what's left. And it could be helpful to display them. When TMT gets wiser, we can remove this workaround.
        tmt_warnings = [line for line in output_lines if line.startswith('warning:')]

        plans = [line for line in output_lines if line not in tmt_warnings]

        if tmt_warnings:
            log_dict(self.warn, 'tmt emitted following warnings', tmt_warnings)

        log_dict(self.debug, 'tmt plans', plans)

        if not plans:
            raise GlueError('No plans found, cowardly refusing to continue.')

        return plans

    def create_test_schedule(self, testing_environment_constraints=None):
        # type: (Optional[List[TestingEnvironment]]) -> TestSchedule
        """
        Create a test schedule based on list of tmt plans.

        :param list(gluetool_modules.libs.testing_environment.TestingEnvironment) testing_environment_constraints:
            limitations put on us by the caller. In the form of testing environments - with some fields possibly
            left unspecified - the list specifies what environments are expected to be used for testing.
            At this moment, only ``arch`` property is obeyed.
        :returns: a test schedule consisting of :py:class:`TestScheduleEntry` instances.
        """

        if not testing_environment_constraints:
            self.warn('TMT scheduler does not support open constraints', sentry=True)
            return TestSchedule()

        self.require_shared('dist_git_repository')
        repository = self.shared('dist_git_repository')

        repodir = repository.clone(
            logger=self.logger,
            prefix='workdir-{}-{}-'.format(repository.package, repository.branch)
        )

        plans = self._plans_from_dist_git(repodir)

        log_dict(self.info, 'creating schedule for {} plans'.format(len(plans)), plans)

        schedule = TestSchedule()

        # For each plan, architecture and compose, create a schedule entry
        for plan in plans:
            for tec in testing_environment_constraints:
                if tec.arch == tec.ANY:
                    self.warn('TMT scheduler does not support open constraints', sentry=True)
                    continue

                schedule_entry = TestScheduleEntry(Logging.get_logger(), plan, repodir)

                schedule_entry.testing_environment = TestingEnvironment(
                    compose=tec.compose,
                    arch=tec.arch,
                    snapshots=tec.snapshots
                )

                schedule.append(schedule_entry)

        schedule.log(self.debug, label='complete schedule')

        return schedule

    def _prepare_environment(self, schedule_entry):
        # type: (TestScheduleEntry) -> str
        """
        Prepare local environment for running the schedule entry, by setting up some directories and files.

        :returns: a path to a work directory, dedicated for this entry.
        """

        assert schedule_entry.guest is not None

        # Create a working directory, we try hard to keep all the related work inside this directory.
        # This directory is passed to `tmt run --id` and tmt will keep all test artifacts.

        work_dir_prefix = 'work-{}'.format(os.path.basename(schedule_entry.plan))

        # tempfile.mkdtemp returns an absolute path to the directory, but the unspoken convention says
        # we must use paths that are relative to the current working directory. Therefore we must make
        # both schedule entry's work dir relative to the CWD.
        work_dir = os.path.relpath(
            tempfile.mkdtemp(dir=os.getcwd(), prefix=work_dir_prefix),
            os.getcwd()
        )

        # Make sure it's possible to enter our directories for other parties. We're not that concerned with privacy,
        # we'd rather let common users inside the directories when inspecting the pipeline artifacts. Therefore
        # setting their permissions to ug=rwx,o=rx.

        os.chmod(
            work_dir,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH  # noqa: E501  # line too long
        )

        schedule_entry.info("working directory '{}'".format(work_dir))

        return work_dir

    def _run_plan(self, schedule_entry, work_dirpath, tmt_log_filepath):
        # type: (TestScheduleEntry, str, str) -> Tuple[TestScheduleResult, List[TestResult]]
        """
        Run a test plan, observe and report results.
        """

        # We're going to spawn new thread for `_run_plan`, therefore we will have to setup its thread
        # root action to the current one of this thread.
        current_action = Action.current_action()

        assert schedule_entry.guest is not None

        Action.set_thread_root(current_action)

        context = dict_update(
            self.shared('eval_context'),
            {
                'GUEST': schedule_entry.guest
            }
        )

        variables = self.shared('user_variables', logger=schedule_entry.logger, context=context) or {}

        self.info('running in {}'.format(schedule_entry.repodir))

        # work_dirpath is relative to the current directory, but tmt expects it to be a absolute path
        # so it recognizes it as a path instead of run directory name
        command = [
            self.option('command')
        ]

        command += [
            'run',
            '--all',
            '--id', os.path.abspath(work_dirpath)
        ]

        for name, value in variables.iteritems():
            command += [
                '-e', '{}={}'.format(name, value)
            ]

        command += [
            # `provision` step
            'provision',
            '--how', 'connect',
            '--guest', schedule_entry.guest.hostname,
            '--key', schedule_entry.guest.key,

            # `plan` step
            'plan',
            '--name', schedule_entry.plan
        ]

        def _save_output(output):
            # type: (gluetool.utils.ProcessOutput) -> None

            with open(tmt_log_filepath, 'w') as f:
                def _write(label, s):
                    # type: (str, str) -> None
                    f.write('{}\n{}\n\n'.format(label, s))

                _write('# STDOUT:', format_blob(cast(str, output.stdout)))
                _write('# STDERR:', format_blob(cast(str, output.stderr)))

                f.flush()

        tmt_output = None

        # run plan via tmt, note that the plan MUST be run in the artifact_dirpath
        try:
            tmt_output = Command(command).run(
                cwd=schedule_entry.repodir,
                inspect=True,
                inspect_callback=create_inspect_callback(schedule_entry.logger)
            )

        except GlueCommandError as exc:
            tmt_output = exc.output

            # check if tmt failed to produce results
            if tmt_output.exit_code == TMTExitCodes.RESULTS_MISSING:
                schedule_entry.warn('tmt did not produce results, skipping results evaluation')

                log_blob(
                    schedule_entry.error,
                    'tmt execution failed with exit code {}'.format(tmt_output.exit_code),
                    tmt_output.stderr if tmt_output.stderr else ''
                )

                return TestScheduleResult.ERROR, []

            self.info('tmt produced results with exit code {}'.format(tmt_output.exit_code))

        finally:
            if tmt_output:
                _save_output(tmt_output)

        # gather and return overall plan run result and test results
        return gather_plan_results(schedule_entry, work_dirpath)

    def run_test_schedule_entry(self, schedule_entry):
        # type: (TestScheduleEntry) -> None

        # this schedule entry is not ours, move it along
        if schedule_entry.runner_capability != 'tmt':
            self.overloaded_shared('run_test_schedule_entry', schedule_entry)
            return

        self.shared('trigger_event', 'test-schedule-runner-sti.schedule-entry.started',
                    schedule_entry=schedule_entry)

        work_dirpath = self._prepare_environment(schedule_entry)
        schedule_entry.work_dirpath = work_dirpath

        tmt_log_filepath = os.path.join(work_dirpath, TMT_LOG)

        artifacts = artifacts_location(self, tmt_log_filepath, logger=schedule_entry.logger)

        schedule_entry.info('TMT logs are in {}'.format(artifacts))

        plan_result, test_results = self._run_plan(schedule_entry, work_dirpath, tmt_log_filepath)

        schedule_entry.result = plan_result
        schedule_entry.results = test_results

        log_dict(schedule_entry.debug, 'results', test_results)

        self.shared('trigger_event', 'test-schedule-runner-sti.schedule-entry.finished',
                    schedule_entry=schedule_entry)

    def serialize_test_schedule_entry_results(self, schedule_entry, test_suite):
        # type: (TestScheduleEntry, Any) -> None

        def _add_property(properties, name, value):
            # type: (Any, str, str) -> Any
            return new_xml_element('property', _parent=properties, name='baseosci.{}'.format(name), value=value or '')

        def _add_log(logs, name, path, href, schedule_entry=None):
            # type: (Any, str, str, str, Optional[TestScheduleEntry]) -> Any

            attrs = {
                'name': name,
                'href': href,
                'schedule-stage': 'running'
            }

            if schedule_entry is not None:
                attrs['schedule-entry'] = schedule_entry.id

                schedule_entry.outputs.append(TestScheduleEntryOutput(
                    stage=TestScheduleEntryStage.RUNNING,
                    label=name,
                    log_path=path,
                    additional_data=None
                ))

            return new_xml_element(
                'log',
                _parent=logs,
                **attrs
            )

        def _add_testing_environment(test_case, name, arch, compose, snapshots):
            # type: (Any, str, Any, Any, bool) -> Any
            parent_elem = new_xml_element('testing-environment', _parent=test_case, name=name)
            new_xml_element('property', _parent=parent_elem, name='arch', value=arch)
            new_xml_element('property', _parent=parent_elem, name='compose', value=compose)
            new_xml_element('property', _parent=parent_elem, name='snapshots', value=str(snapshots))

        if schedule_entry.runner_capability != 'tmt':
            self.overloaded_shared('serialize_test_schedule_entry_results', schedule_entry, test_suite)
            return

        for task in schedule_entry.results:

            test_case = new_xml_element('testcase', _parent=test_suite, name=task.name, result=task.result)
            properties = new_xml_element('properties', _parent=test_case)
            logs = new_xml_element('logs', _parent=test_case)

            if task.result == 'failed':
                new_xml_element('failure', _parent=test_case)

            if task.result == 'error':
                new_xml_element('error', _parent=test_case)

            # test properties
            assert schedule_entry.guest is not None
            assert schedule_entry.guest.environment is not None
            _add_property(properties, 'arch', schedule_entry.guest.environment.arch)
            _add_property(properties, 'connectable_host', schedule_entry.guest.hostname)
            _add_property(properties, 'distro', schedule_entry.guest.environment.compose)
            _add_property(properties, 'status', schedule_entry.stage.value.capitalize())
            _add_property(properties, 'testcase.source.url', self.shared('dist_git_repository').web_url)
            _add_property(properties, 'variant', '')

            # add main log
            _add_log(
                logs,
                name='testout.log',
                path=task.log,
                href=artifacts_location(self, task.log, logger=schedule_entry.logger),
                schedule_entry=schedule_entry
            )

            # add log_dir
            _add_log(
                logs,
                name="log_dir",
                path=task.artifacts_dir,
                href=artifacts_location(self, task.artifacts_dir, logger=schedule_entry.logger),
                schedule_entry=schedule_entry
            )

            assert schedule_entry.testing_environment is not None
            _add_testing_environment(
                test_case, 'requested',
                schedule_entry.testing_environment.arch,
                schedule_entry.testing_environment.compose,
                schedule_entry.testing_environment.snapshots
            )
            _add_testing_environment(
                test_case, 'provisioned',
                schedule_entry.guest.environment.arch,
                schedule_entry.guest.environment.compose,
                schedule_entry.guest.environment.snapshots
            )

            # sorting
            sort_children(properties, lambda child: child.attrs['name'])
            sort_children(logs, lambda child: child.attrs['name'])

        test_suite['tests'] = len(schedule_entry.results)
