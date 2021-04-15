# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import tempfile
import os
import re
import stat

from concurrent.futures import ThreadPoolExecutor
import inotify.adapters

import gluetool
from gluetool import GlueError
from gluetool.action import Action
from gluetool.log import log_blob, log_dict
from gluetool.utils import dict_update, new_xml_element, normalize_path

from gluetool_modules.libs import sort_children
from gluetool_modules.libs.artifacts import artifacts_location
from gluetool_modules.libs.test_schedule import TestScheduleResult

# Type annotations
from typing import cast, Any, Callable, Dict, List, Optional, Tuple  # noqa
from gluetool_modules.testing.test_scheduler_sti import TestScheduleEntry  # noqa

# Check whether Ansible finished running tests every 5 seconds.
DEFAULT_WATCH_TIMEOUT = 5

STI_ANSIBLE_LOG_FILENAME = 'ansible-output.txt'


#: Represents a single run of a test - one STI playbook can contain multiple such tests
#  - and results of this run.
#:
#: :ivar str name: name of the test.
#: :ivar libs.test_schedule.TestScheduleEntry schedule_entry: test schedule entry the task belongs to.
#: :ivar dict results: results of the test run, as reported by Ansible playbook log.
#: :ivar dict logs: list of logs associated with the test
TaskRun = collections.namedtuple('TaskRun', ('name', 'schedule_entry', 'result', 'logs'))


def gather_test_results(schedule_entry, artifacts_directory):
    # type: (TestScheduleEntry, str) -> List[TaskRun]
    """
    Extract detailed test results from 'results.yml' or 'test.log'.
    """

    results = []

    # By default, check results in the new results.yml format
    # https://docs.fedoraproject.org/en-US/ci/standard-test-interface/#_results_format
    results_yml_filename = os.path.join(artifacts_directory, 'results.yml')
    if os.path.isfile(results_yml_filename):
        schedule_entry.debug('Checking results in {}'.format(results_yml_filename))
        try:
            parsed_results = gluetool.utils.load_yaml(results_yml_filename, logger=schedule_entry.logger)
            for result in parsed_results['results']:
                results.append(
                    TaskRun(
                        name=result.get('test'),
                        schedule_entry=schedule_entry,
                        result=result.get('result'),
                        logs=result.get('logs', [])))
        except gluetool.glue.GlueError:
            schedule_entry.warn('Unable to check results in {}'.format(results_yml_filename))

    # Otherwise attempt to parse the old test.log file
    else:
        test_log_filename = os.path.join(artifacts_directory, 'test.log')
        schedule_entry.debug('Checking results in {}'.format(test_log_filename))
        try:
            with open(test_log_filename) as test_log:
                for line in test_log:
                    match = re.match('([^ ]+) (.*)', line)
                    if not match:
                        continue
                    result, name = match.groups()
                    results.append(TaskRun(
                        name=name, schedule_entry=schedule_entry, result=result, logs=[]))
        except IOError:
            schedule_entry.warn('Unable to check results in {}'.format(test_log_filename))

    return results


class STIRunner(gluetool.Module):
    """
    Runs STI-compatible test schedule entries.

    For more information about Standard Test Interface see:

        `<https://fedoraproject.org/wiki/CI/Standard_Test_Interface>`

    Plugin for the "test schedule" workflow.
    """

    name = 'test-schedule-runner-sti'
    description = 'Runs STI-compatible test schedule entries.'
    options = {
        'watch-timeout': {
            'help': 'Check whether Ansible finished running tests every SECONDS seconds. (default: %(default)s)',
            'metavar': 'SECONDS',
            'type': int,
            'default': DEFAULT_WATCH_TIMEOUT
        },
        'ansible-playbook-filepath': {
            'help': """
                    Provide different ansible-playbook executable to the call
                    of a `run_playbook` shared function. (default: %(default)s)
                    """,
            'metavar': 'PATH',
            'type': str,
            'default': ''
        }
    }

    shared_functions = ['run_test_schedule_entry', 'serialize_test_schedule_entry_results']

    def _set_schedule_entry_result(self, schedule_entry):
        # type: (TestScheduleEntry) -> None
        """
        Try to find at least one task that didn't complete or didn't pass.
        """

        self.debug('Try to find any non-PASS task')

        for task_run in schedule_entry.results:
            schedule_entry, task, result = task_run.schedule_entry, task_run.name, task_run.result

            schedule_entry.debug('  {}: {}'.format(task, result))

            if result.lower() == 'pass':
                continue

            schedule_entry.debug('    We have our traitor!')
            schedule_entry.result = TestScheduleResult.FAILED
            return

        schedule_entry.result = TestScheduleResult.PASSED

    def _prepare_environment(self, schedule_entry):
        # type: (TestScheduleEntry) -> Tuple[str, str, str]
        """
        Prepare local environment for running the schedule entry, by setting up some directories and files.

        :returns: a path to a work directory, dedicated for this entry, and path to a "artifact" directory
            in which entry's artifacts are supposed to appear.
        """

        assert schedule_entry.guest is not None

        # Create a working directory, we try hard to keep all the related work inside this directory.
        # Under this directory, there will be an inventory file and an "artifact" directory in which
        # the Ansible is supposed to run - all artifacts created by the playbook will therefore land
        # in the artifact directory.

        work_dir_prefix = 'work-{}'.format(os.path.basename(schedule_entry.playbook_filepath))
        artifact_dir_prefix = 'tests-'

        # tempfile.mkdtemp returns an absolute path to the directory, but the unspoken convention says
        # we must use paths that are relative to the current working directory. Therefore we must make
        # both schedule entry's work dir and artifact dir relative to the CWD.
        work_dir = os.path.relpath(
            tempfile.mkdtemp(dir=os.getcwd(), prefix=work_dir_prefix),
            os.getcwd()
        )

        artifact_dir = os.path.relpath(
            tempfile.mkdtemp(dir=work_dir, prefix=artifact_dir_prefix),
            os.getcwd()
        )

        # Make sure it's possible to enter our directories for other parties. We're not that concerned with privacy,
        # we'd rather let common users inside the directories when inspecting the pipeline artifacts. Therefore
        # setting their permissions to ug=rwx,o=rx.

        os.chmod(
            work_dir,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH  # noqa: E501  # line too long
        )

        os.chmod(
            artifact_dir,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH  # noqa: E501  # line too long
        )

        schedule_entry.info("working directory '{}'".format(work_dir))

        # try to detect ansible interpreter
        interpreters = self.shared('detect_ansible_interpreter', schedule_entry.guest)

        # inventory file contents
        ansible_interpreter = 'ansible_python_interpreter={}'.format(interpreters[0]) if interpreters else ''
        inventory_content = """
[localhost]
sut     ansible_host={} ansible_user=root {}
""".format(schedule_entry.guest.hostname, ansible_interpreter)

        with tempfile.NamedTemporaryFile(delete=False, dir=work_dir, prefix='inventory-') as inventory:
            log_blob(schedule_entry.info, 'using inventory', inventory_content)

            inventory.write(inventory_content)
            inventory.flush()

        # Inventory file's permissions are limited to user only, u=rw,go=. That's far from being perfect, hard
        # to examine such file, hence one more chmod to u=rw,go=r

        os.chmod(
            inventory.name,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        )

        return work_dir, artifact_dir, inventory.name

    def _run_playbook(self, schedule_entry, work_dirpath, artifact_dirpath, inventory_filepath):
        # type: (TestScheduleEntry, str, str, str) -> List[TaskRun]
        """
        Run an STI playbook, observe and report results.
        """

        # We're going to spawn new thread for `run_playbook`, therefore we will have to setup its thread
        # root action to the current one of this thread.
        current_action = Action.current_action()

        def _run_playbook_wrapper():
            # type: () -> Any

            assert schedule_entry.guest is not None

            Action.set_thread_root(current_action)

            context = dict_update(
                self.shared('eval_context'),
                {
                    'GUEST': schedule_entry.guest
                }
            )

            variables = dict_update(
                {},
                {
                    # Internally we're working with CWD-relative path but we have to feed ansible
                    # with the absolute one because it operates from its own, different cwd.
                    'artifacts': os.path.abspath(artifact_dirpath),
                    'ansible_ssh_common_args': ' '.join(['-o ' + option for option in schedule_entry.guest.options])
                },
                self.shared('user_variables', logger=schedule_entry.logger, context=context) or {},
                schedule_entry.variables
            )

            if schedule_entry.ansible_playbook_filepath:
                ansible_playbook_filepath = schedule_entry.ansible_playbook_filepath  # type: Optional[str]
            elif self.option('ansible-playbook-filepath'):
                ansible_playbook_filepath = normalize_path(self.option('ansible-playbook-filepath'))
            else:
                ansible_playbook_filepath = None

            # `run_playbook` and log the output to the working directory
            self.shared(
                'run_playbook',
                schedule_entry.playbook_filepath,
                schedule_entry.guest,
                inventory=inventory_filepath,
                cwd=artifact_dirpath,
                json_output=False,
                log_filepath=os.path.join(work_dirpath, STI_ANSIBLE_LOG_FILENAME),
                variables=variables,
                ansible_playbook_filepath=ansible_playbook_filepath
            )

        # monitor artifact directory
        notify = inotify.adapters.Inotify()
        notify.add_watch(artifact_dirpath)

        # initial values
        run_tests = []  # type: List[str]

        # testname matching regex
        testname_regex = re.compile(r'^\.?([^_]*)_(.*).log.*$')

        # run the playbook in a separate thread
        with ThreadPoolExecutor(thread_name_prefix='testing-thread') as executor:
            future = executor.submit(_run_playbook_wrapper)

            # monitor the test execution
            while True:
                for event in notify.event_gen(yield_nones=False, timeout_s=self.option('watch-timeout')):
                    (_, event_types, path, filename) = event

                    self.debug("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(path, filename, event_types))

                    # we lookup testing progress by looking at their logs being created
                    if 'IN_CREATE' not in event_types:
                        continue

                    # try to match the test log name
                    match = re.match(testname_regex, filename)

                    if not match:
                        continue

                    result, testname = match.groups()

                    # do not log the test multiple times
                    if testname not in run_tests:
                        run_tests.append(testname)
                        schedule_entry.info("{} - {}".format(testname, result))

                # handle end of execution
                if future.done():
                    break

        # parse results
        results = gather_test_results(schedule_entry, artifact_dirpath)

        try:
            future.result()

        except GlueError:

            # STI defines that Ansible MUST fail if any of the tests fail. To differentiate from a generic ansible
            # error, we check if required test.log was generated with at least one result.
            # Note that Ansible error is still a user error though, nothing we can do anything about, in case ansible
            # failed, report the ansible output as the test result.
            if not results:
                results.append(TaskRun(name='ansible', schedule_entry=schedule_entry, result='FAIL', logs=[]))

        return results

    def run_test_schedule_entry(self, schedule_entry):
        # type: (TestScheduleEntry) -> None

        if schedule_entry.runner_capability != 'sti':
            self.overloaded_shared('run_test_schedule_entry', schedule_entry)
            return

        self.require_shared('run_playbook', 'detect_ansible_interpreter')

        self.shared('trigger_event', 'test-schedule-runner-sti.schedule-entry.started',
                    schedule_entry=schedule_entry)

        # We don't need the working directory actually - we need artifact directory, which is
        # a subdirectory of working directory. But one day, who knows...
        work_dirpath, artifact_dirpath, inventory_filepath = self._prepare_environment(schedule_entry)
        schedule_entry.work_dirpath = work_dirpath
        schedule_entry.artifact_dirpath = artifact_dirpath
        schedule_entry.inventory_filepath = inventory_filepath

        ansible_log_filepath = os.path.join(work_dirpath, STI_ANSIBLE_LOG_FILENAME)

        artifacts = artifacts_location(self, ansible_log_filepath, logger=schedule_entry.logger)

        schedule_entry.info('Ansible logs are in {}'.format(artifacts))

        results = self._run_playbook(schedule_entry, work_dirpath, artifact_dirpath, inventory_filepath)

        schedule_entry.results = results

        log_dict(schedule_entry.debug, 'results', results)

        self._set_schedule_entry_result(schedule_entry)

        self.shared('trigger_event', 'test-schedule-runner-sti.schedule-entry.finished',
                    schedule_entry=schedule_entry)

    def serialize_test_schedule_entry_results(self, schedule_entry, test_suite):
        # type: (TestScheduleEntry, Any) -> None

        def _add_property(properties, name, value):
            # type: (Any, str, str) -> Any
            return new_xml_element('property', _parent=properties, name='baseosci.{}'.format(name), value=value or '')

        def _add_log(logs, name, href):
            # type: (Any, str, str) -> Any
            return new_xml_element(
                'log',
                _parent=logs,
                **{
                    'name': name,
                    'href': href,
                    'schedule-stage': 'running'
                })

        def _add_testing_environment(test_case, name, arch, compose):
            # type: (Any, str, Any, Any) -> Any
            parent_elem = new_xml_element('testing-environment', _parent=test_case, name=name)
            new_xml_element('property', _parent=parent_elem, name='arch', value=arch)
            new_xml_element('property', _parent=parent_elem, name='compose', value=compose)

        if schedule_entry.runner_capability != 'sti':
            self.overloaded_shared('serialize_test_schedule_entry_results', schedule_entry, test_suite)
            return

        for task in schedule_entry.results:

            test_case = new_xml_element('testcase', _parent=test_suite, name=task.name, result=task.result)
            properties = new_xml_element('properties', _parent=test_case)
            logs = new_xml_element('logs', _parent=test_case)

            if task.result.upper() == 'FAIL':
                new_xml_element('failure', _parent=test_case)

            if task.result.upper() == 'ERROR':
                new_xml_element('error', _parent=test_case)

            # test properties
            assert schedule_entry.guest is not None
            assert schedule_entry.guest.environment is not None
            _add_property(properties, 'arch', schedule_entry.guest.environment.arch)
            _add_property(properties, 'connectable_host', schedule_entry.guest.hostname)
            _add_property(properties, 'distro', schedule_entry.guest.environment.compose)
            _add_property(properties, 'status', schedule_entry.stage.value.capitalize())
            if self.has_shared('dist_git_repository'):
                _add_property(properties, 'testcase.source.url', self.shared('dist_git_repository').web_url)
            _add_property(properties, 'variant', '')

            # logs
            assert schedule_entry.artifact_dirpath is not None

            # standard STI logs
            if task.logs:
                for log in task.logs:
                    log_path = os.path.join(schedule_entry.artifact_dirpath, log)
                    artifacts_location_url = artifacts_location(self, log_path, logger=schedule_entry.logger)
                    _add_log(logs, name=log, href=artifacts_location_url)

                artifacts_location_url = artifacts_location(
                    self, schedule_entry.artifact_dirpath, logger=schedule_entry.logger)
                _add_log(logs, name="log_dir", href=artifacts_location_url)

            # ansible output only available
            else:
                assert schedule_entry.work_dirpath
                log_path = os.path.join(schedule_entry.work_dirpath, STI_ANSIBLE_LOG_FILENAME)
                artifacts_location_url = artifacts_location(self, log_path, logger=schedule_entry.logger)
                _add_log(logs, name=STI_ANSIBLE_LOG_FILENAME, href=artifacts_location_url)

            assert schedule_entry.testing_environment is not None
            _add_testing_environment(test_case, 'requested', schedule_entry.testing_environment.arch,
                                     schedule_entry.testing_environment.compose)
            _add_testing_environment(test_case, 'provisioned', schedule_entry.guest.environment.arch,
                                     schedule_entry.guest.environment.compose)

            # sorting
            sort_children(properties, lambda child: child.attrs['name'])
            sort_children(logs, lambda child: child.attrs['name'])

        test_suite['tests'] = len(schedule_entry.results)
