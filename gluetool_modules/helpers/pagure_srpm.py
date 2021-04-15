# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import shlex
import gluetool
from gluetool.utils import normalize_path, Command
from gluetool_modules.libs.brew_build_fail import run_command
from gluetool_modules.libs.artifacts import artifacts_location


class PagureSRPM(gluetool.Module):

    name = 'pagure-srpm'
    description = 'Makes source rpm from pagure pull request'

    options = {
        'git-clone-options': {
            'help': 'Additional options for `git clone` command (default: %(default)s).',
            'default': ''
        },
        'git-fetch-options': {
            'help': 'Additional options for `git fetch` command (default: %(default)s).',
            'default': ''
        },
        'git-merge-options': {
            'help': 'Additional options for `git merge` command (default: %(default)s).',
            'default': ''
        },
        'log-path': {
            'help': 'Path to log file (default: %(default)s).',
            'default': 'pagure_srpm.log'
        }
    }

    shared_functions = ['src_rpm']

    def _run_command(self, cmd, log_path, comment, cwd=None):
        def _executor(command):
            return Command(command).run(cwd=cwd) if cwd else Command(command).run()

        return run_command(
                    command=cmd,
                    log_path=log_path,
                    comment=comment,
                    executor=_executor
                )

    def src_rpm(self):
        self.require_shared('primary_task')

        pull_request = self.shared('primary_task')

        if pull_request.ARTIFACT_NAMESPACE not in ['dist-git-pr']:
            raise gluetool.GlueError('Incompatible artifact namespace: {}'.format(pull_request.ARTIFACT_NAMESPACE))

        log_path = normalize_path(self.option('log-path'))
        display_log_path = os.path.relpath(log_path, os.getcwd())
        self.info('build logs are in {}'.format(artifacts_location(self, display_log_path, logger=self.logger)))

        clone_cmd = [
            'git', 'clone',
            '-b', pull_request.destination_branch,
            pull_request.project.clone_url
        ]

        if self.option('git-clone-options'):
            clone_cmd.extend(shlex.split(self.option('git-clone-options')))

        self._run_command(
            clone_cmd,
            log_path,
            'Clone git repository'
        )

        pr_id = pull_request.pull_request_id.repository_pr_id

        fetch_cmd = ['git', 'fetch', 'origin', 'refs/pull/{}/head'.format(pr_id)]

        if self.option('git-fetch-options'):
            fetch_cmd.extend(shlex.split(self.option('git-fetch-options')))

        self._run_command(
            fetch_cmd,
            log_path,
            'Fetch pull request changes',
            pull_request.project.name
        )

        merge_cmd = ['git', 'merge', 'FETCH_HEAD', '-m', 'ci pr merge']

        if self.option('git-merge-options'):
            merge_cmd.extend(shlex.split(self.option('git-merge-options')))

        self._run_command(
            merge_cmd,
            log_path,
            'Merge pull request changes',
            pull_request.project.name
        )

        last_comment_id = pull_request.comments[-1]['id'] if pull_request.comments else 0

        spec_origin_name = '{0}/{0}.spec'.format(pull_request.project.name)
        spec_backup_name = '{}.backup'.format(spec_origin_name)

        os.rename(spec_origin_name, spec_backup_name)

        with open(spec_backup_name, 'r') as infile, open(spec_origin_name, 'w') as outfile:
            for line in infile.readlines():
                line = line.replace('%{?dist}', '.0.pr.{}.c.{}%{{?dist}}'.format(pull_request.uid, last_comment_id))
                outfile.writelines(line)

        rhpkg_cmd = ['rhpkg', 'srpm']
        output = self._run_command(
            rhpkg_cmd,
            log_path,
            'Make srpm',
            pull_request.project.name
        )

        src_rpm_name = output.stdout.split('/')[-1].strip()

        return src_rpm_name, pull_request.project.name
