import gluetool
from gluetool.utils import cached_property, dict_update
import gluetool_modules.libs.dispatch_job


DEFAULT_WOW_OPTIONS_SEPARATOR = '#-#-#-#-#'


class OpenStackJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching OpenStack-based testing pipeline, as defined in ``ci-openstack.yaml`` file.

    .. note::

       Value of the ``--id`` option is, by default, first searched in the environment, at it is expected
       to be set by Jenkins' machinery, e.g. by the ``redhat-ci-plugin``.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'openstack-job'
    description = 'Run package tests using restraint and OpenStack guest'

    job_name = 'ci-openstack'

    # DispatchJenkinsJobMixin.options contain hard defaults
    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'artemis-options': {
            'help': 'Additional options for ``artemis-options`` module.'
        },
        'ansible-options': {
            'help': 'Additional options for ``ansible-options`` module.'
        },
        'build-dependencies-options': {
            'help': 'Additional options for ``build-dependencies-options`` module.'
        },
        'dist-git-options': {
            'help': 'Additional options for ``dist-git`` module.'
        },
        'guess-environment-options': {
            'help': 'Additional options for ``guess-environment`` module.'
        },
        'install-mbs-build-options': {
            'help': 'Additional options for install-mbs-build or install-mbs-build-execute module.'
        },
        'wow-options': {
            'help': 'Additional options for workflow-tomorrow.',
            'action': 'append',
            'default': []
        },
        'openstack-options': {
            'help': 'Additional options for openstack module.',
        },
        'brew-build-task-params-options': {
            'help': 'Additional options for ``brew-build-task-params`` module (default: %(default)s).',
            'default': ''
        },
        'test-scheduler-options': {
            'help': 'Additional options for test-scheduler module.'
        },
        'test-scheduler-sti-options': {
            'help': 'Additional options for test-scheduler-sti module.'
        },
        'test-scheduler-upgrades-options': {
            'help': 'Additional options for test-scheduler-upgrades module.'
        },
        'test-schedule-runner-options': {
            'help': 'Additional options for test-schedule-runner module.'
        },
        'test-schedule-runner-restraint-options': {
            'help': 'Additional options for test-schedule-runner-restraint module.'
        },
        'pipeline-install-ancestors-options': {
            'help': 'Additional options for pipeline-install-ancestors module.'
        },
        'github-options': {
            'help': 'Additional options for github module.'
        },
        'compose-url-options': {
            'help': 'Additional options for compose-url module.'
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

        # following options are passed to brew-build-task-params module
        'install-rpms-blacklist': {
            'help': """
                    Regexp pattern (compatible with ``egrep``) - when installing build, matching packages will
                    **not** be installed (default: %(default)s).
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

    @cached_property
    def build_params(self):
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

        return dict_update(super(OpenStackJob, self).build_params, {
            'artemis_options': self.option('artemis-options'),
            'ansible_options': self.option('ansible-options'),
            'build_dependencies_options': self.option('build-dependencies-options'),
            'dist_git_options': self.option('dist-git-options'),
            'install_mbs_build_options': self.option('install-mbs-build-options'),
            'guess_environment_options': self.option('guess-environment-options'),
            'wow_options': wow_options,
            'openstack_options': self.option('openstack-options'),
            'brew_build_task_params_options': brew_build_task_params_options,
            'test_scheduler_options': self.option('test-scheduler-options'),
            'test_scheduler_sti_options': self.option('test-scheduler-sti-options'),
            'test_scheduler_upgrades_options': self.option('test-scheduler-upgrades-options'),
            'test_schedule_runner_options': self.option('test-schedule-runner-options'),
            'test_schedule_runner_restraint_options': self.option('test-schedule-runner-restraint-options'),
            'pipeline_install_ancestors_options': self.option('pipeline-install-ancestors-options'),
            'github_options': self.option('github-options'),
            'compose_url_options': self.option('compose-url-options')
        })
