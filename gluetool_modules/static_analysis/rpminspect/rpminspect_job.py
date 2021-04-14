import gluetool
import gluetool_modules.libs.dispatch_job


class RpminspectJob(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
    """
    Jenkins job module dispatching RPMinspect analysis and comparison testing, as defined in
    ``ci-test-brew-rpminspect_analysis.yaml`` and ``ci-test-brew-rpminspect_comparison.yaml`` files.

    .. note::

       Value of the ``--id`` option is, by default, first searched in the environment, at it is expected
       to be set by Jenkins' machinery, e.g. by the ``redhat-ci-plugin``.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    name = 'rpminspect-job'
    description = 'Job module dispatching RPMinspect analysis and comparison pipeline.'

    # DispatchJenkinsJobMixin.options contain hard defaults
    # pylint: disable=gluetool-option-no-default-in-help,gluetool-option-hard-default
    options = gluetool.utils.dict_update({}, gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin.options, {
        'build-system': {
            'help': 'Source of build to test: brew or mbs',
            'choices': ('brew', 'mbs'),
            'default': 'brew'
        },
        'type': {
            'help': 'Test type: analysis or comparison',
            'choices': ('analysis', 'comparison')
        },
        'profile': {
            'help': 'RPMinspect profile to use',
        },
        'baseline-method': {
            'help': 'Brew baseline method',
        },
        'baseline-nvr': {
            'help': 'Baseline NVR for specific-build baseline method'
        }
    })

    required_options = ('type',)

    def execute(self):
        # type: () -> None

        if self.option('profile'):
            self.build_params.update({
                'rpminspect_profile': self.option('profile')
            })
        if self.option('baseline-method'):
            self.build_params.update({
                'brew_with_baseline_method': self.option('baseline-method')
            })
        if self.option('baseline-nvr'):
            self.build_params.update({
                'brew_with_baseline_nvr': self.option('baseline-nvr')
            })

        if self.option('job-name'):
            job = self.option('job-name')
        else:
            job = 'ci-test-{}-rpminspect_{}'.format(self.option('build-system'), self.option('type'))

        self.shared('jenkins').invoke_job(job, self.build_params)
