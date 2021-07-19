# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool

from typing import Dict, List, Optional, Any # noqa


class BrewBuildOptions(gluetool.Module):
    """
    Create options for ``/distribution/install/brew-build task``.

    This task is being used to install both Koji and Brew builds on both Beaker and OpenStack guests.
    Its actual involvement in the process may differ but its inputs are still the same and it makes
    sense to construct its options just once, and use them by different pipelines as they wish to.
    """

    name = 'brew-build-task-params'
    description = 'Create options for /distribution/install/brew-build task.'

    options = {
        'install-task-not-build': {
            'help': """
                    Try to install SUT using brew task ID as a referrence, instead of the brew build ID
                    (default: %(default)s).
                    """,
            'action': 'store_true',
            'default': 'no'
        },
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
        },
        'brew-build-repo-priority': {
            'help': 'Set priority of brew build repository (default: %(default)s).',
            'type': int,
            'default': 50  # The priority should be higher (lower number) than the default one (99)
        }
    }

    shared_functions = ['brew_build_task_params']

    def brew_build_task_params(self, artifacts=None):
        # type: (Optional[List[Any]]) -> Dict[str, str]
        """
        Return mapping with options for ``/distribution/install/brew-build``, to install currently known artifacts.

        If no artifacts are provided, they are extracted from primary task.
        """

        self.require_shared('primary_task', 'tasks')

        # temporary holders of options
        tasks = []  # type: List[int]
        builds = []  # type: List[int]

        input_tasks = artifacts if artifacts else self.shared('tasks')

        if gluetool.utils.normalize_bool_option(self.option('install-task-not-build')):
            self.debug('asked to install by task ID')
            tasks = [task.id for task in input_tasks]

        else:
            for task in input_tasks:
                if task.scratch:
                    self.debug('task {} is a scratch build, using task ID for installation'.format(task.id))

                    tasks.append(task.id)

                else:
                    self.debug('task {} is a regular task, using build ID for installation'.format(task.id))

                    builds.append(task.build_id)

        options = {
            'METHOD': self.option('install-method'),
            'SERVER': self.shared('primary_task').ARTIFACT_NAMESPACE,
            'RPM_BLACKLIST': self.option('install-rpms-blacklist'),
            'PRIORITY': self.option('brew-build-repo-priority')
        }

        if tasks:
            options['TASKS'] = ' '.join([str(i) for i in tasks])

        if builds:
            options['BUILDS'] = ' '.join([str(i) for i in builds])

        return options
