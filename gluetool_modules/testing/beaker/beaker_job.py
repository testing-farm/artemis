# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.utils import cached_property, dict_update
import gluetool_modules.libs.dispatch_job

# Type annotations
from typing import Dict, Optional  # noqa


DEFAULT_WOW_OPTIONS_SEPARATOR = '#-#-#-#-#'


class BeakerJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching Beaker-based testing pipeline, as defined in ``ci-test-brew-beaker-beaker.yaml`` job.

    .. note::

       Value of the ``--id`` option is, by default, first searched in the environment, at it is expected
       to be set by Jenkins' machinery, e.g. by the ``redhat-ci-plugin``.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'beaker-job'
    description = 'Job module dispatching Beaker-based testing pipeline.'

    job_name = 'ci-test-brew-beaker-beaker'

    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'build-dependencies-options': {
            'help': 'Additional options for ``build-dependencies-options`` module.'
        },
        'guess-environment-options': {
            'help': 'Additional options for ``guess-environment`` module.'
        },
        'wow-options': {
            'help': 'Additional options for ``workflow-tomorrow``.',
            'action': 'append',
            'default': []
        },
        'beaker-jobwatch-options': {
            'help': 'Additional options for ``beaker-jobwatch`` module (default: %(default)s).',
            'default': ''
        },
        'beaker-options': {
            'help': 'Additional options for ``beaker`` module (default: %(default)s).',
            'default': ''
        },
        'brew-build-task-params-options': {
            'help': 'Additional options for ``brew-build-task-params`` module (default: %(default)s).',
            'default': ''
        },
        'wow-options-separator': {
            'help': """
                    Due to technical limitations of Jenkins, when jobs want to pass multiple ``--wow-options``
                    instances to this module, it is necessary to encode them into a single string. To tell them
                    apart, this SEPARATOR string is used (default: %(default)s).
                    """,
            'metavar': 'SEPARATOR',
            'type': str,
            'action': 'store',
            'default': DEFAULT_WOW_OPTIONS_SEPARATOR
        },

        # following options passed to brew-build-task-params module
        'install-rpms-blacklist': {
            'help': """
                    Regexp pattern (compatible with ``egrep``) - when installing build, matching packages
                    will **not** be installed (default: %(default)s).
                    """,
            'type': str,
            'default': ''
        },
        'install-method': {
            'help': 'Yum method to use for installation (default: %(default)s).',
            'type': str,
            'default': 'multi'
        }
    })

    required_options = ('wow-options',)

    @cached_property
    def build_params(self):
        # type: () -> Dict[str, Optional[str]]
        brew_build_task_params_options = self.option('brew-build-task-params-options')
        install_rpms_blacklist = self.option('install-rpms-blacklist')
        install_method = self.option('install-method')

        if install_rpms_blacklist:
            brew_build_task_params_options = '{} --install-rpms-blacklist={}'.format(brew_build_task_params_options,
                                                                                     install_rpms_blacklist)

        if install_method:
            brew_build_task_params_options = '{} --install-method={}'.format(brew_build_task_params_options,
                                                                             install_method)

        wow_options = self.option('wow-options-separator').join(self.option('wow-options'))

        return dict_update(super(BeakerJob, self).build_params, {
            'build_dependencies_options': self.option('build-dependencies-options'),
            'guess_environment_options': self.option('guess-environment-options'),
            'wow_options': wow_options,
            'beaker_jobwatch_options': self.option('beaker-jobwatch-options'),
            'beaker_options': self.option('beaker-options'),
            'brew_build_task_params_options': brew_build_task_params_options
        })
