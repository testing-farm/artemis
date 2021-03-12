import gluetool
from gluetool.utils import cached_property, dict_update

import gluetool_modules.libs.dispatch_job


class CoprBuildJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching copr build, as defined in ``ci-test-github-copr_build.yaml`` file.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'github-copr-build-job'
    description = 'Create and run ci-test-github-copr_build job'

    job_name = 'ci-test-github-copr_build'

    # DispatchJenkinsJobMixin.options contain hard defaults
    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'copr-builder-options': {
            'help': 'Additional options for ``copr-builder`` module.'
        },
        'github-options': {
            'help': 'Additional options for ``github`` module.'
        },
    })

    @cached_property
    def build_params(self):
        return dict_update(super(CoprBuildJob, self).build_params, {
            'copr_builder_options': self.option('copr-builder-options'),
            'github_options': self.option('github-options'),
        })
