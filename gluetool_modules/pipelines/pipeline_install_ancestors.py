# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.result import Ok, Error
from gluetool.utils import normalize_shell_option, normalize_multistring_option
from gluetool.log import log_dict
from gluetool_modules.libs.guest_setup import guest_setup_log_dirpath, GuestSetupStage


class PipelineInstallAncestors(gluetool.Module):
    """
    Installs package ancestors in a separate pipeline.

    The ancestors names are resolved from ``primary_task`` component name using ``ancestors``
    shared function. When ``ancestors`` shared function is not available or if it returns empty list,
    we suppose ancestor name is the same as the component name.

    If option ``ancestors`` is set, its value is used.

    Then these ancestors names are used to resolve specific brew builds on the given tag
    specified by the option ``tag``.

    Guest is setup by `guest-setup` module.
    """
    name = 'pipeline-install-ancestors'

    options = {
        'tag': {
            'help': 'Tag to use when looking up ancestors.'
        },
        'install-rpms-blacklist': {
            'help': """
                Value is passed to inner called `brew-build-task-params` module (default: %(default)s).
                """,
            'type': str,
            'default': ''
        },
        'ancestors': {
            'help': """
                Comma separated list of packages to be install on the guest (default: none).
                """,
            'default': [],
            'action': 'append'
        },
    }

    required_options = ('tag',)
    shared_functions = ('setup_guest',)

    def __init__(self, *args, **kwargs):
        super(PipelineInstallAncestors, self).__init__(*args, **kwargs)

        self.context = {}

    def _build_exists(self, name, tag):
        self.require_shared('koji_session')
        koji_session = self.shared('koji_session')
        builds = koji_session.listTagged(tag, package=name, inherit=True, latest=True)

        return len(builds) > 0

    @gluetool.utils.cached_property
    def _brew_options(self):
        ancestors = []

        self.require_shared('primary_task')
        component = self.shared('primary_task').component

        if self.option('ancestors'):
            self.info('Ancestors set by option')
            ancestors = normalize_multistring_option(self.option('ancestors'))

        elif self.has_shared('ancestors'):
            self.info('Ancestors set by shared function')
            ancestors = self.shared('ancestors', component)

        if ancestors:
            log_dict(self.info, "Ancestors of '{}'".format(component), ancestors)

        else:
            self.info("No ancestors of '{}' found, assume ancestor's name is the same.".format(component))
            ancestors = [component]

        tag = self.option('tag')

        self.info("Filter out ancestors without builds tagged '{}'".format(tag))
        ancestors = [ancestor for ancestor in ancestors if self._build_exists(ancestor, tag)]

        if ancestors:
            log_dict(self.info, "Ancestors of '{}' with builds tagged '{}'".format(component, tag), ancestors)
            return '--tag {} --name {}'.format(tag, ','.join(ancestors))

        self.info('No ancestors left, nothing will be installed on SUT.')
        return None

    def setup_guest(self, guest, stage=GuestSetupStage.PRE_ARTIFACT_INSTALLATION, log_dirpath=None, **kwargs):
        log_dirpath = guest_setup_log_dirpath(guest, log_dirpath)

        # Make sure previous setup_guest methods are called. This is out of decency only - we don't expect there
        # to be any other `setup_guest` in the pipeline. If there were, it would be operate within the context
        # of the initial primary artifact while we're trying to do our job within context of the ancestor.
        r_overloaded_guest_setup_output = self.overloaded_shared(
            'setup_guest',
            guest,
            stage=stage,
            log_dirpath=log_dirpath,
            **kwargs
        )

        if r_overloaded_guest_setup_output is None:
            r_overloaded_guest_setup_output = Ok([])

        if r_overloaded_guest_setup_output.is_error:
            return r_overloaded_guest_setup_output

        # Containers for guest setup outputs and result from the child pipeline.
        guest_setup_output = r_overloaded_guest_setup_output.unwrap() or []
        guest_setup_output_result = [Ok(guest_setup_output)]

        # Callback to initiate setup guest in child pipeline - will add its outputs to our container,
        # and it should propagate any failure - or at least the first one - by updating the result.
        def do_setup_guest(self):
            r_guest_setup = self.shared(
                'setup_guest',
                guest,
                stage=stage,
                log_dirpath=log_dirpath,
                **kwargs
            )

            if r_guest_setup is None:
                r_guest_setup = Ok([])

            if r_guest_setup.is_error:
                # Just like the successful result, the failed one also carries list of outputs
                # we need to propagate to our parent pipeline.
                outputs, exc = r_guest_setup.value

                guest_setup_output.extend(outputs)

                # If the current global outcome of guest-setup is still set to "success", change that to failed.
                # If it's already an error, we don't care, just propagate the outputs.
                if guest_setup_output_result[0].is_ok:
                    guest_setup_output_result[0] = Error((
                        guest_setup_output,
                        exc
                    ))

            else:
                guest_setup_output.extend(r_guest_setup.unwrap() or [])

        #
        # Run the installation of the ancestors in a separate pipeline. We are using a separate pipeline
        # so we do not spoil the parent pipeline with the build initialization.
        #
        # Please note that we are already in 'setup_guest' function here, and will be requiring to kick
        # additional ``setup_guest`` for modules in the separate pipeline. For that kick we use a helper
        # function ``do_guest_setup``.
        #

        modules = []

        # If we have an ancestor build, by adding `brew` module at the beginning of our pipeline we're running
        # all the modules in the context of the ancestor build.
        if self._brew_options:
            modules += [
                gluetool.glue.PipelineStepModule('brew', argv=normalize_shell_option(self._brew_options))
            ]

        else:
            # When there's no artifact we'd inject into our child pipeline, we try at least to "fake" its presence
            # by providing dummy eval context content, to fool modules that need it, like guest-setup and its
            # method of picking playbooks via map based on artifact's build target.
            self.context = {
                'BUILD_TARGET': self.option('tag'),
            }

        # We always want to run guest-setup (or any other module hooked on setup_guest function), for all
        # stages.
        modules += [
            gluetool.glue.PipelineStepModule('guest-setup'),
            gluetool.glue.PipelineStepCallback('do_setup_guest', do_setup_guest)
        ]

        # In the artifact-installation stage, throw in modules to install the ancestor.
        if stage == GuestSetupStage.ARTIFACT_INSTALLATION and self._brew_options:
            self.info('installing the ancestor {}'.format(self.shared('primary_task').nvr))

            blacklist = self.option('install-rpms-blacklist')
            brew_build_task_params_argv = ['--install-rpms-blacklist', blacklist] if blacklist else []

            modules += [
                gluetool.glue.PipelineStepModule('brew-build-task-params', argv=brew_build_task_params_argv),
                gluetool.glue.PipelineStepModule('install-koji-build', argv=['--skip-overloaded-shared']),
                gluetool.glue.PipelineStepCallback('do_setup_guest', do_setup_guest)
            ]

        failure_execute, failure_destroy = self.glue.run_modules(modules)

        # Finalize the response. We must return Result, either Ok or Error, with a list of guest setup
        # outputs and possible the exception.
        #
        # Note that we can return just a single exception, so the first one wins. If there were more
        # exceptions raised somewhere later, then we at least log them.
        result = guest_setup_output_result[0]

        if failure_execute:
            if result.is_ok:
                result = Error((
                    guest_setup_output,
                    failure_execute.exception
                ))

            else:
                guest.error(
                    'Exception raised: {}'.format(failure_execute.exception),
                    exc_info=failure_execute.exc_info
                )

        if failure_destroy:
            if result.is_ok:
                result = Error((
                    guest_setup_output,
                    failure_destroy.exception
                ))

            else:
                guest.error(
                    'Exception raised: {}'.format(failure_destroy.exception),
                    exc_info=failure_destroy.exc_info
                )

        return result

    @property
    def eval_context(self):
        __content__ = {  # noqa
            'BUILD_TARGET': """
                            Build target of build we were looking for in case nothing found.
                            If build was found, this value is provided by artifact provider (etc. koji, brew or copr).
                            """
        }

        return self.context
