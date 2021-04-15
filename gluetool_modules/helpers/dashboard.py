# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
import gluetool_modules.libs


class Dashboard(gluetool.Module):
    """
    Provides - and logs - "dashboard" URL - an URL somewhere in the wild that, when opened,
    shows nice overview of testing performed by different CI system for the primary artifact.
    """

    name = 'dashboard'
    description = 'Provides "dashboard" URL'
    supported_dryrun_level = gluetool.glue.DryRunLevels.ISOLATED

    options = {
        'dashboard-url-template': {
            'help': 'Template used for creating a Dashboard URL'
        }
    }

    required_options = ('dashboard-url-template',)

    @property
    def dashboard_url(self):
        return gluetool.utils.render_template(self.option('dashboard-url-template'), **self.shared('eval_context'))

    @property
    def eval_context(self):
        # To render dashboard URL, we need eval context. When asked to provide eval context, we want to
        # include dashboard URL. Voila, infinite recursion: eval_context => dasboard_url => eval_context => ...

        if gluetool_modules.libs.is_recursion(__file__, 'eval_context'):
            return {}

        __content__ = {  # noqa
            'DASHBOARD_URL': """
                             URL of the dashboard page containing details of CI runs for the artifact.
                             """
        }

        return {
            'DASHBOARD_URL': self.dashboard_url
        }

    def execute(self):
        if not self.dashboard_url:
            self.warn('Dashboard URL seems to be empty')
            return

        self.info('For more info on the artifact, see {}'.format(self.dashboard_url))
