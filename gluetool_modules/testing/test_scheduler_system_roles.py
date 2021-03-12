import gluetool
from gluetool.utils import normalize_path


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
        """
        This module modifies STI test schedule provided by other module. It adds provided ansible playbook filepath
        to schedule entries.
        """

        schedule = self.overloaded_shared(
            'create_test_schedule', testing_environment_constraints=testing_environment_constraints
        )

        if self.option('ansible-playbook-filepath'):
            for entry in schedule:

                if entry.runner_capability != 'sti':
                    continue

                entry.ansible_playbook_filepath = normalize_path(self.option('ansible-playbook-filepath'))

        return schedule
