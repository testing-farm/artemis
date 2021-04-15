# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import json
import gluetool
from gluetool.log import log_dict
from gluetool.utils import Command
from gluetool import GlueError
from gluetool_modules.libs.sut_installation import check_ansible_sut_installation


class InstallMBSBuild(gluetool.Module):
    """
    Installs packages from specified rhel module on given guest. Calls given ansible playbook
    which downloads repofile and installs module.
    """

    name = 'install-mbs-build'
    description = 'Install module on given guest'

    options = {
        'playbook': {
            'help': 'Ansible playbook, which installs given module',
            'type': str,
            'metavar': 'FILE'
        }
    }

    shared_functions = ('setup_guest',)

    def _get_repo(self, module_nsvc, guest):
        self.info('Generating repo for module via ODCS')

        command = [
            'odcs',
            '--redhat', 'create',
            'module', module_nsvc,
            '--sigkey', 'none',
            '--arch', guest.environment.arch
        ]

        # TO improve: raise OdcsError if command fails
        output = Command(command).run()
        # strip 1st line before json data
        output = output.stdout[output.stdout.index('{'):]
        output_json = json.loads(output)
        log_dict(self.debug, 'odcs output', output_json)
        state = output_json['state_name']
        if state != 'done':
            raise GlueError('Getting repo from ODCS failed')
        repo_url = output_json['result_repofile']
        self.info('Module repo from ODCS: {}'.format(repo_url))
        return repo_url

    def setup_guest(self, guest, **kwargs):

        self.require_shared('run_playbook', 'primary_task')

        self.overloaded_shared('setup_guest', guest, **kwargs)

        primary_task = self.shared('primary_task')

        nsvc = primary_task.nsvc
        repo_url = self._get_repo(nsvc, guest)
        self.info('Installing module "{}" from {}'.format(nsvc, repo_url))

        _, ansible_output = self.shared(
            'run_playbook',
            gluetool.utils.normalize_path(self.option('playbook')),
            guest,
            variables={
                'REPO_URL': repo_url,
                'MODULE_NSVC': nsvc,
                'ansible_python_interpreter': '/usr/bin/python3'
            },
        )

        check_ansible_sut_installation(ansible_output, guest, self.shared('primary_task'))

        self.info('All modules have been successfully installed')
