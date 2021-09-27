# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.utils import normalize_path
from gluetool_modules.libs.testing_environment import TestingEnvironment
from gluetool_modules.libs.test_schedule import TestSchedule
from gluetool_modules.testing.test_schedule_runner_sti import TestScheduleEntry

# Type annotations
from typing import Optional, List, cast  # noqa


class TestSchedulerSystemRoles(gluetool.Module):

    name = 'test-scheduler-system-roles'
    description = 'Prepare schedule for system roles testing. Modify entries provided by previous (STI) provider.'

    options = {
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

    shared_functions = ['create_test_schedule']

    def create_test_schedule(self, testing_environment_constraints=None):
        # type: (Optional[List[TestingEnvironment]]) -> TestSchedule
        """
        This module modifies STI test schedule provided by other module. It adds provided ansible playbook filepath
        to schedule entries.
        """

        schedule = self.overloaded_shared(
            'create_test_schedule', testing_environment_constraints=testing_environment_constraints
        )  # type: TestSchedule

        if self.option('ansible-playbook-filepath'):
            for entry in schedule:

                if entry.runner_capability != 'sti':
                    continue

                assert isinstance(entry, TestScheduleEntry)
                entry.ansible_playbook_filepath = normalize_path(self.option('ansible-playbook-filepath'))

        return schedule
