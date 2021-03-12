import os
import sys
import six
import re
import gluetool
from gluetool.utils import normalize_multistring_option, normalize_path, Command
from gluetool_modules.libs import run_and_log
from gluetool_modules.libs.brew_build_fail import BrewBuildFailedError, run_command
from gluetool_modules.libs.results import TestResult, publish_result
from gluetool_modules.libs.artifacts import artifacts_location


class BrewBuildTestResult(TestResult):
    def __init__(self, glue, overall_result, build_url, comment, process_output, **kwargs):
        super(BrewBuildTestResult, self).__init__(glue, 'brew-build', overall_result, **kwargs)

        self.build_url = build_url
        self.comment = comment
        self.process_output = process_output


class BrewBuilder(gluetool.Module):

    name = 'brew-builder'
    description = 'Triggers scratch brew build'

    options = {
        'arches': {
            'help': 'List of arches to build (default: none).',
            'action': 'append',
            'default': []
        },
        'log-path': {
            'help': 'Path to log file (default: %(default)s).',
            'default': 'brew_builder.log'
        }
    }

    def report_result(self, result, build_url=None, exception=None):
        self.info('Result of testing: {}'.format(result))

        comment = exception.message if exception else None
        process_output = exception.output if exception else None

        publish_result(self, BrewBuildTestResult, result, build_url, comment, process_output)

    def _make_brew_build(self):
        self.require_shared('src_rpm')

        src_rpm_name, path_to_src_rpm = self.shared('src_rpm')

        self.info('Initializing brew scratch build')

        def _executor(command):
            return Command(command).run(cwd=path_to_src_rpm)

        command = [
            'rhpkg', 'scratch-build',
            '--srpm', src_rpm_name,
            '--nowait'
        ]

        log_path = normalize_path(self.option('log-path'))
        display_log_path = os.path.relpath(log_path, os.getcwd())
        self.info('build logs are in {}'.format(artifacts_location(self, display_log_path, logger=self.logger)))

        arches = normalize_multistring_option(self.option('arches'))

        if arches:
            command += ['--arches', ' '.join(arches)]

        command_failed, err_msg, output = run_and_log(command,
                                                      log_path,
                                                      _executor)
        if command_failed:
            six.reraise(*sys.exc_info())

        # detect brew task id
        match = re.search(r'^Created task: (\d+)$', output.stdout, re.M)
        if not match:
            raise gluetool.GlueError('Unable to find `task-id` in `rhpkg` output')
        task_id = match.group(1)

        # detect brew task URL and log it
        match = re.search(r'^Task info: (.+)$', output.stdout, re.M)
        if not match:
            raise gluetool.GlueError('Unable to find `task-url` in `rhpkg` output')
        task_url = match.group(1)
        self.info('Waiting for brew to finish task: {0}'.format(task_url))

        # wait until brew task finish
        brew_watch_cmd = ['brew', 'watch-task', task_id]

        run_command(brew_watch_cmd,
                    log_path,
                    'Wait for brew build finish'
                    )

        return task_url

    def execute(self):
        try:
            brew_task_url = self._make_brew_build()
        except BrewBuildFailedError as exc:
            self.report_result('FAIL', exception=exc)
            return

        self.report_result('PASS', build_url=brew_task_url)
