import gluetool
import gluetool_modules.libs.dispatch_job

from gluetool.utils import render_template


class SystemRolesJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching system roles testing, as defined in
    ``ci-test-github-ts_sti-artemis-system-roles.yaml`` file

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'system-roles-job'
    description = 'Job module dispatching system roles test.'

    # DispatchJenkinsJobMixin.options contains hard defaults
    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = gluetool.utils.dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'ansible-options': {
            'help': 'Additional options for ``ansible-options`` module.',
            'default': ''
        },
        'dist-git-options': {
            'help': 'Additional options for ``dist-git`` module.',
            'default': ''
        },
        'guess-environment-options': {
            'help': 'Additional options for ``guess-environment`` module.',
            'default': ''
        },
        'artemis-options': {
            'help': 'Additional options for artemis module.',
            'default': ''
        },
        'pipeline-state-reporter-options': {
            'help': 'Additional options for pipeline-state-reporter module',
            'default': ''
        },
        'github-options': {
            'help': 'Additional options for github module.',
            'default': ''
        },
        'test-scheduler-options': {
            'help': 'Additional options for test-scheduler module.',
            'default': ''
        },
        'test-scheduler-system-roles-options': {
            'help': 'Additional options for test-scheduler-system-roles module.',
            'default': ''
        },
        'test-scheduler-sti-options': {
            'help': 'Additional options for test-scheduler-sti module.',
            'default': ''
        },
        'test-schedule-runner-options': {
            'help': 'Additional options for test-schedule-runner module.',
            'default': ''
        },
        'test-schedule-runner-sti-options': {
            'help': 'Additional options for test-schedule-runner-sti module.',
            'default': ''
        },

        'composes-to-test-on': {
            'help': 'List of composes which will be tested on',
            'action': 'append',
            'default': []
        },
        'system-roles-ansibles': {
            'help': 'List of ansible playbook filepaths and versions values',
            'action': 'append',
            'default': []
        }
    })

    def system_roles_ansibles(self):
        mapping = {}

        for pair in self.option('system-roles-ansibles').split(',\n'):
            splitted_pair = pair.split(':')
            mapping[splitted_pair[0]] = splitted_pair[1]

        return mapping

    def access_control(self):
        primary_task = self.shared('primary_task')

        # Check if 'citest' comment exists and author is collaborator
        if primary_task.comment:
            comment_author_collaborator = '[citest' in primary_task.comment \
                and primary_task.comment_author_is_collaborator
        else:
            comment_author_collaborator = False

        if primary_task.pull_head_branch_owner_is_collaborator or comment_author_collaborator:
            return True

        return False

    def execute(self):

        common_build_params = {
            'ansible_options': self.option('ansible-options'),
            'dist_git_options': self.option('dist-git-options'),
            'guess_environment_options': self.option('guess-environment-options'),
            'artemis_options': self.option('artemis-options'),
            'github_options': self.option('github-options'),
            'pipeline_state_reporter_options': self.option('pipeline-state-reporter-options'),
            'test_scheduler_options': self.option('test-scheduler-options'),
            'test_scheduler_system_roles_options': self.option('test-scheduler-system-roles-options'),
            'test_scheduler_sti_options': self.option('test-scheduler-sti-options'),
            'test_schedule_runner_options': self.option('test-schedule-runner-options'),
            'test_schedule_runner_sti_options': self.option('test-schedule-runner-sti-options'),
        }

        # Do nothing if branch or comment author is not a collaborator
        if not self.access_control:
            return

        composes_to_test_on = []
        for compose_template in self.option('composes-to-test-on').split(','):
            composes_to_test_on.append((render_template(compose_template, **self.shared('eval_context'))))

        for compose in composes_to_test_on:
            for ansible_version, ansible_path in self.system_roles_ansibles().items():
                self.build_params = common_build_params.copy()

                self.build_params['guess_environment_options'] += ' --compose-method=force --compose={}'.format(compose)

                self.build_params['test_scheduler_system_roles_options'] += ' --ansible-playbook-filepath={}'.format(
                    ansible_path
                )

                self.build_params['pipeline_state_reporter_options'] += ' --pr-label={}/ansible-{}/(citool)'.format(
                    compose, ansible_version
                )

                self.shared('jenkins').invoke_job('ci-test-github-ts_sti-artemis-system-roles', self.build_params)
