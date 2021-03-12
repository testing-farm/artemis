import gluetool
import gluetool_modules.libs.dispatch_job
from gluetool.utils import cached_property, dict_update


class BrewBuildJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching brew build, as defined in ``ci-test-pagure-brew_build.yaml`` file.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'pagure-brew-build-job'
    description = 'Create and run ci-test-pagure-brew_build job'

    job_name = 'ci-test-pagure-brew_build'

    # DispatchJenkinsJobMixin.options contain hard defaults
    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'brew-builder-options': {
            'help': 'Additional options for ``brew-builder`` module.'
        }
    })

    @cached_property
    def build_params(self):
        return dict_update(super(BrewBuildJob, self).build_params, {
            'brew_builder_options': self.option('brew-builder-options')
        })
