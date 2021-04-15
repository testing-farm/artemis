# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import gluetool
from gluetool.action import Action
from gluetool.log import log_dict
from gluetool.result import Ok, Error
from gluetool.utils import Command, normalize_shell_option, render_template
from gluetool import GlueError

from gluetool_modules.libs.guest_setup import guest_setup_log_dirpath, GuestSetupOutput, GuestSetupStage
from gluetool_modules.libs.sut_installation import SUTInstallation


DEFAULT_ODCS_OPTIONS_SEPARATOR = '#-#-#-#-#'


class InstallMBSBuild(gluetool.Module):
    """
    Installs packages from specified rhel module on given guest. Calls given ansible playbook
    which downloads repofile and installs module.

    Options to ODCS can be extended using the `--odcs-options` option. If you need to specify
    more parameters, you can use as separator of the options `#-#-#-#-#`, this is useful for
    example with Jenkins.
    """

    name = 'install-mbs-build-execute'
    description = 'Install module on given guest'

    shared_functions = ('setup_guest',)

    options = {
        'profile': {
            'help': 'Use given profile for module installation',
        },
        'installation-workarounds': {
            'help': 'File with commands and rules, when used them.'
        },
        'use-devel-module': {
            'help': 'Use -devel module when generating ODCS repo.',
            'action': 'store_true'
        },
        'enable-only': {
            'help': 'Module is only enabled, not installed.',
            'action': 'store_true'
        },
        'log-dir-name': {
            'help': 'Name of directory where outputs of installation commands will be stored (default: %(default)s).',
            'type': str,
            'default': 'artifact-installation'
        },
        'odcs-options': {
            'help': 'Addditional options passed to ODCS command, value is treated as a template.',
            'type': str
        },
        'odcs-options-separator': {
            'help': """
                    Due to technical limitations of Jenkins, when jobs want to pass multiple via ``--odcs-options``
                    instances to this module, it is necessary to separate them in a single string. To tell them
                    apart, this SEPARATOR string is used (default: %(default)s).
                    """,
            'metavar': 'SEPARATOR',
            'type': str,
            'action': 'store',
            'default': DEFAULT_ODCS_OPTIONS_SEPARATOR
        }
    }

    def _get_repo(self, task, module_nsvc, guest):
        self.info('Generating repo for module via ODCS')

        command = [
            'odcs',
            '--redhat', 'create-module', module_nsvc,
            '--sigkey', 'none'
        ]

        # If module is scratch, we need to call it differently
        if task.scratch:
            command = [
                'odcs',
                '--redhat', 'create-module', '--scratch-module', module_nsvc,
                '--sigkey', 'none'
            ]

        # Inner list gather all arches, `set` gets rid of duplicities, and final `list` converts set to a list.
        command += [
            '--arch', guest.environment.arch
        ]

        if self.option('odcs-options'):
            separator = self.option('odcs-options-separator')

            odcs_options = render_template(
                self.option('odcs-options'),
                logger=guest.logger,
                **self.shared('eval_context')
            )

            command += normalize_shell_option(odcs_options.replace(separator, ' '))

        with Action(
            'creating ODCS repository',
            parent=Action.current_action(),
            logger=guest.logger,
            tags={
                'guest': {
                    'hostname': guest.hostname,
                    'environment': guest.environment.serialize_to_json()
                },
                'artifact-id': task.id,
                'artifact-type': task.ARTIFACT_NAMESPACE
            }
        ):
            try:
                output = Command(command).run()
            except gluetool.glue.GlueCommandError:
                raise GlueError('ODCS call failed')

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

    @gluetool.utils.cached_property
    def installation_workarounds(self):
        if not self.option('installation-workarounds'):
            return []

        return gluetool.utils.load_yaml(self.option('installation-workarounds'), logger=self.logger)

    def setup_guest(self, guest, stage=GuestSetupStage.PRE_ARTIFACT_INSTALLATION, log_dirpath=None, **kwargs):
        self.require_shared('primary_task', 'evaluate_instructions')

        log_dirpath = guest_setup_log_dirpath(guest, log_dirpath)

        r_overloaded_guest_setup_output = self.overloaded_shared(
            'setup_guest',
            guest,
            stage=stage,
            log_dirpath=log_dirpath,
            **kwargs
        )

        if r_overloaded_guest_setup_output is None:
            r_overloaded_guest_setup_output = Ok([])

        if r_overloaded_guest_setup_output.is_error:
            return r_overloaded_guest_setup_output

        if stage != GuestSetupStage.ARTIFACT_INSTALLATION:
            return r_overloaded_guest_setup_output

        guest_setup_output = r_overloaded_guest_setup_output.unwrap() or []

        installation_log_dirpath = os.path.join(
            log_dirpath,
            '{}-{}'.format(self.option('log-dir-name'), guest.name)
        )

        primary_task = self.shared('primary_task')

        nsvc = nsvc_odcs = primary_task.nsvc

        #
        # Include -devel module if requested, for more information see COMPOSE-2993
        #
        # Note that -devel module can contain some packages people want to use in their tests
        #
        if self.option('use-devel-module'):
            # we will use devel module for installation
            nsvc = '{}-devel:{}:{}:{}'.format(
                primary_task.name,
                primary_task.stream,
                primary_task.version,
                primary_task.context
            )

            # For ODCS request we need to include both modules, for installation we will use only -devel if requested
            nsvc_odcs = '{} {}'.format(primary_task.nsvc, nsvc)

        # create name:stream from current NSVC, required for scratch modules later on
        name_stream = ':'.join(nsvc.split(':')[:2])

        repo_url = self._get_repo(primary_task, nsvc_odcs, guest)

        #
        # Some modules do not provide 'default' module and user needs to explicitly specify it,
        # for more info see OSCI-56
        #

        # using dictionary with one item to be able modify this value from inner functions, since python 2 does not
        # support `nonlocal`
        profile = {}

        if self.option('profile'):
            profile['profile'] = self.option('profile')
            nsvc = '{}/{}'.format(nsvc, profile['profile'])
            name_stream = '{}/{}'.format(name_stream, profile['profile'])

        sut_installation = SUTInstallation(self, installation_log_dirpath, primary_task, logger=guest)

        # callback for 'commands' item in installation_workarounds
        def _add_step_callback(instruction, command, argument, context):
            for step in argument:
                sut_installation.add_step(step['label'], step['command'])

        self.shared('evaluate_instructions', self.installation_workarounds, {
            'steps': _add_step_callback,
        })

        sut_installation.add_step(
            'Download ODCS repo', 'curl -v {} --output /etc/yum.repos.d/mbs_build.repo',
            items=repo_url
        )

        def _verify_profile(command, output):
            module_info = output.stdout

            profiles = None
            match = re.search(r'Profiles\s*:\s*(.+)', module_info)
            if match:
                profiles = match.group(1).split(',')
                profiles = [re.sub(r'\s*(?:\[d\])?(?: \[i])?', '', item) for item in profiles]

            if not profiles:
                return "Module '{}' does not have any profiles".format(nsvc)

            log_dict(self.debug, 'Available profiles', profiles)

            if not profile:
                match = re.search(r'Default profiles\s*:\s*([^\s]*)$', module_info, re.MULTILINE)
                profile['profile'] = match.group(1) if match else None

                if profile['profile']:
                    self.info("Using default profile '{}'".format(profile['profile']))
                else:
                    return "Module '{}' doesn't have default profile set".format(nsvc)

            if profile['profile'] not in profiles:
                return "Profile '{}' is not available".format(profile['profile'])

            return None

        def _check_enabled(command, output):
            # type: (str, gluetool.utils.ProcessOutput) -> None
            """
            Process output of `yum module info` command and returns description of issue, when output is not correct.
            """
            module_info = output.stdout

            if not module_info:
                return "Module '{}' was not found, module info is empty".format(primary_task.nsvc)

            stream_regex = re.compile(r'Stream\s*:\s*{} (?:\[d\])?\[e\] ?\[a\]'.format(primary_task.stream))

            if not stream_regex.search(module_info):
                return "Stream '{}' is not active or enabled".format(primary_task.stream)

            return None

        def _check_installed(command, output):
            # type: (str, gluetool.utils.ProcessOutput) -> None
            """
            Process output of `yum module info` command and returns description of issue, when output is not correct.
            """

            module_info = output.stdout

            profile_regex = re.compile(r'Profiles\s*:.*{}(?: \[d\])? \[i\]'.format(profile['profile']))

            if not (module_info and profile_regex.search(module_info)):
                return "Profile '{}' is not installed".format(profile['profile'])

            return None

        if not self.option('enable-only'):
            if primary_task.scratch:
                sut_installation.add_step('Verify profile', 'yum module info {}',
                                          items=name_stream, callback=_verify_profile)
            else:
                sut_installation.add_step('Verify profile', 'yum module info {}',
                                          items=nsvc, callback=_verify_profile)

        # Extract module name from `nsvc` because we might have modified it in the `setup_guest`
        # function, e.g. for devel modules.
        # Module reset requires only module name.
        sut_installation.add_step('Reset module', 'yum module reset -y {}', items=nsvc.split(':')[0])

        # If this is a scratch module use "name:stream" instead of whole nsvc, as a workaround. Ref: BZ #1926771
        if primary_task.scratch:
            sut_installation.add_step('Enable module', 'yum module enable -y {}', items=name_stream)
            sut_installation.add_step('Verify module enabled', 'yum module info {}',
                                      items=name_stream, callback=_check_enabled)
        else:
            sut_installation.add_step('Enable module', 'yum module enable -y {}', items=nsvc)
            sut_installation.add_step('Verify module enabled', 'yum module info {}',
                                      items=nsvc, callback=_check_enabled)

        if not self.option('enable-only'):

            # If this is a scratch module use "name:stream" instead of the whole nsvc, as a workaround. Ref: BZ #1926771
            if primary_task.scratch:
                sut_installation.add_step('Install module', 'yum module install -y {}',
                                          items=name_stream)
                sut_installation.add_step('Verify module installed', 'yum module info {}',
                                          items=name_stream, callback=_check_installed)
            else:
                sut_installation.add_step('Install module', 'yum module install -y {}', items=nsvc)
                sut_installation.add_step('Verify module installed', 'yum module info {}',
                                          items=nsvc, callback=_check_installed)

        with Action(
            'installing module',
            parent=Action.current_action(),
            logger=guest.logger,
            tags={
                'guest': {
                    'hostname': guest.hostname,
                    'environment': guest.environment.serialize_to_json()
                },
                'artifact-id': primary_task.id,
                'artifact-type': primary_task.ARTIFACT_NAMESPACE
            }
        ):
            sut_result = sut_installation.run(guest)

        guest_setup_output += [
            GuestSetupOutput(
                stage=stage,
                label='module installation',
                log_path=installation_log_dirpath,
                additional_data=sut_installation
            )
        ]

        if sut_result.is_error:
            assert sut_result.error is not None

            return Error((
                guest_setup_output,
                sut_result.error
            ))

        return Ok(guest_setup_output)
