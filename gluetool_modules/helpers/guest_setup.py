# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import re

import gluetool
from gluetool.action import Action
from gluetool.log import log_dict
from gluetool.result import Ok
from gluetool.utils import normalize_path_option, render_template
from gluetool_modules.libs.artifacts import artifacts_location
from gluetool_modules.libs.guest_setup import guest_setup_log_dirpath, GuestSetupOutput, GuestSetupStage, \
    GuestSetupStageAdapter, SetupGuestReturnType

# Type annotations
from typing import cast, TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, Union  # noqa

if TYPE_CHECKING:
    import gluetool_modules.libs.guest  # noqa
    import gluetool_modules.helpers.ansible  # noqa


ConfigFileMapType = Dict[str, List[str]]
ConfigInstructionMapType = Dict[str, List[Any]]
ConfigVarsMapType = Dict[str, Dict[str, str]]

ConfigMapType = Union[
    ConfigFileMapType,
    ConfigInstructionMapType,
    ConfigVarsMapType
]

ConfigValueCallbackType = Callable[
    [
        ConfigMapType,
        str,
        str
    ],
    None
]


STAGE_SPEC_PATTERN = re.compile(r'^(?:({}):)?(.+)$'.format(
    '|'.join([
        'pre-artifact-installation',
        'pre-artifact-installation-workarounds',
        'artifact-installation',
        'post-artifact-installation-workarounds',
        'post-artifact-installation'
    ])
))


class GuestSetup(gluetool.Module):
    """
    Prepare guests for testing process. This is implemented by running Ansible playbooks, in a sequence of stages.
    When set via options, module will run the playbooks on a given guest.

    Stages
    ======

    There are 5 stages:

    * ``pre-artifact-installation``
    * ``pre-artifact-installation-workarounds``
    * ``artifact-installation``
    * ``post-artifact-installation-workarounds``
    * ``post-artifact-installation``

    There is an obvious overlap between ``pre-artifact-installation`` and ``pre-artifact-installation-workarounds``
    the difference is that the former stage should cover the generic steps while the later one is supposed to
    focus on the artifact, component and workflow exceptions and workarounds. Tasks like "ignore AVC denials
    when installing component X" or "add repository Y when testing component Z" should be executed during
    ``pre-artifact-installation-workarounds``.

    The same rule of thumb applies to ``post-artifact-installation-workarounds`` and ``post-artifact-installation``.

    Playbooks
    =========

    The playbooks to play can be specified by following ways (for each stage):

    * a configuration file, ``playbooks-map``, which specifies playbooks and conditions under which the playbook
      should be played on the guest.
    * the ``playbooks`` option can be used to force play from the specified playbooks instead of those
      provided by the configuration file.


    playbooks-map
    =============

    .. code-block:: yaml

      ---
      # Default playbook to use on RHEL
      - rule: BUILD_TARGET.match('.*')
        playbooks:
          - ~/.citool.d/guest-setup/rhel/openstack-restraint.yaml

      # For RHEL8 packages use 1mt playbook for guest-setup
      - rule: BUILD_TARGET.match('rhel-8.0-candidate')
        playbooks:
          - ~/.citool.d/guest-setup/openstack-restraint-1mt.yaml
        extra_vars:
          ansible_python_interpreter: /usr/bin/python

    Each set specifies a ``rule`` key which is evaluated by ``rules-engine`` module. If it evaluates to ``True``,
    the value of ``playbooks`` replaces the list of playbooks to play. The dictionary extra_vars adds
    additional extra variables which should be run with playbooks. All variables are processed by Jinja2 templating
    engine, so you can use evaluation context variables if needed.
    """

    name = 'guest-setup'
    description = 'Prepare guests for testing process.'

    options = {
        'extra-vars': {
            'help': """
                    Comma-separated list of ``KEY=VALUE`` variables passed to ``run_playbook``
                    shared function. This option overrides variables gathered from the mapping file
                    specified via the ``--playbooks-map`` option and also the shared function variables
                    argument. If ``STAGE`` is omitted, ``pre-artifact-installation`` is used as a default
                    stage. (default: none).
                    """,
            'action': 'append',
            'default': [],
            'metavar': 'STAGE:VAR=VALUE,STAGE2:VAR2=VALUE2,...'
        },
        'playbooks': {
            'help': """
                    Comma-separated list of Ansible playbooks to execute on guests, overrides mapped values from
                    ``--playbooks-map`` option. If ``STAGE`` is omitted, ``pre-artifact-installation`` is used as
                    a default stage. (default: none).
                    """,
            'action': 'append',
            'default': [],
            'metavar': 'STAGE:FILEPATH,STAGE2:FILEPATH2,...'
        },
        'playbooks-map': {
            'help': """
                    Path to a file with preconfigured ``--playbooks`` options. If ``STAGE`` is omitted,
                    ``pre-artifact-installation`` is used as a default stage. (default: none).
                    """,
            'action': 'append',
            'default': [],
            'metavar': 'STAGE:FILE,STAGE2:FILE2,...'
        }
    }

    shared_functions = ['setup_guest']

    def _parse_staged_option(
        self,
        option_name,  # type: str
        value_callback,  # type: ConfigValueCallbackType
        stage_initializer=list  # type: Any
    ):
        # type: (...) -> ConfigMapType

        self.debug('parsing value of {} option'.format(option_name))

        # Since one option can carry data for multiple stages, for each stage we gather its data
        # in this dictionary.
        stages = {}  # type: ignore  # ConfigMapType

        values = gluetool.utils.normalize_multistring_option(self.option(option_name))

        for value in values:
            match = STAGE_SPEC_PATTERN.match(value)

            if not match:
                raise gluetool.GlueError(
                    'Cannot parse option value (should be [STAGE:]VALUE format): {}'.format(value)
                )

            stage, actual_value = match.groups()

            # When stage's not set, we use the default one.
            if stage is None:
                stage = 'pre-artifact-installation'

            # If this is the first thing we'd like to save for this stage, we need to initialize stage's
            # storage with the given callback. It is usualy some basic type like dict or list.
            if stage not in stages:
                stages[stage] = stage_initializer()

            # Store the value itself - again, we don't do it ourself, we leave it to the given callback because
            # our caller know better what to do with the value - the caller might verify it somehow before
            # putting it into `stages`.
            value_callback(stages, stage, actual_value.strip())

        return stages

    @gluetool.utils.cached_property
    def _playbooks_map(self):
        # type: () -> ConfigInstructionMapType

        def _load_map(stages, stage, filepath):
            # type: (ConfigMapType, str, str) -> None

            cast(
                ConfigInstructionMapType,
                stages
            )[stage].extend(
                gluetool.utils.load_yaml(filepath, logger=self.logger)
            )

        return cast(
            ConfigInstructionMapType,
            self._parse_staged_option(
                'playbooks-map',
                _load_map
            )
        )

    @gluetool.utils.cached_property
    def _extra_vars(self):
        # type: () -> ConfigFileMapType

        def _to_keyval_pair(stages, stage, keyval_pair):
            # type: (ConfigMapType, str, str) -> None

            key, value = keyval_pair.split('=', 1)

            cast(
                ConfigVarsMapType,
                stages
            )[stage][key.strip()] = value.strip()

        return cast(
            ConfigFileMapType,
            self._parse_staged_option(
                'extra-vars',
                _to_keyval_pair,
                stage_initializer=dict
            )
        )

    @gluetool.utils.cached_property
    def _playbooks(self):
        # type: () -> ConfigVarsMapType

        def _add_playbook_path(stages, stage, filepath):
            # type: (ConfigMapType, str, str) -> None

            cast(
                ConfigFileMapType,
                stages
            )[stage].append(
                gluetool.utils.normalize_path(filepath)
            )

        return cast(
            ConfigVarsMapType,
            self._parse_staged_option(
                'playbooks',
                _add_playbook_path
            )
        )

    def _get_details_from_map(self, guest, stage):
        # type: (gluetool_modules.libs.guest.NetworkedGuest, GuestSetupStage) -> Tuple[List[str], Dict[str, str]]
        """
        Returns a tuple with list of playbooks and extra vars from the processed mapping file
        """

        playbooks = []  # type: List[str]
        extra_vars = {}  # type: Dict[str, Any]

        context = gluetool.utils.dict_update(
            self.shared('eval_context'),
            {
                'GUEST': guest,
                'COMPOSE': self.shared('compose')[0]
            }
        )

        def render_context(playbook):
            # type: (str) -> str

            return render_template(playbook, logger=self.logger, **context)

        playbooks_map = self._playbooks_map.get(stage.value, [])

        for playbooks_set in playbooks_map:
            gluetool.log.log_dict(self.debug, 'evaluating following playbooks set rule', playbooks_set)

            if not self.shared('evaluate_rules',
                               playbooks_set.get('rule', 'False'),
                               context=context):
                self.debug('rule does not match, moving on')
                continue

            if 'playbooks' in playbooks_set:
                playbooks = [render_context(pbook) for pbook in normalize_path_option(playbooks_set['playbooks'])]

                gluetool.log.log_dict(self.debug, 'using these playbooks', playbooks)

            if 'extra_vars' in playbooks_set:
                extra_vars = {
                    key: render_context(value) for key, value in playbooks_set['extra_vars'].iteritems()
                }

                gluetool.log.log_dict(self.debug, 'using these extra vars', extra_vars)

        return (playbooks, extra_vars)

    def setup_guest(self,
                    guest,  # type: gluetool_modules.libs.guest.NetworkedGuest
                    stage=GuestSetupStage.PRE_ARTIFACT_INSTALLATION,  # type: GuestSetupStage
                    variables=None,  # type: Optional[Dict[str, str]]
                    log_dirpath=None,  # type: Optional[str]
                    **kwargs  # type: Any
                   ):  # noqa
        # type: (...) -> SetupGuestReturnType
        """
        Setup provided guest using predefined list of Ansible playbooks.

        Only networked guests, accessible over SSH, are supported.

        :param gluetool_modules.libs.guest.NetworkedGuest guest: Guest to setup.
        :param str stage: pipeline stage in which we're running the playbooks. It is exported to playbooks
            as ``GUEST_SETUP_STAGE`` variable.
        :param dict(str, str) variables: additional variables to pass to each playbook.
        :param str log_dirpath: if specified, try to store all setup logs inside the given directory.
        :param dict kwargs: Additional arguments which will be passed to
          `run_playbook` shared function of :py:class:`gluetool_modules.helpers.ansible.Ansible`
          module.
        """

        self.require_shared('detect_ansible_interpreter')

        assert guest.environment is not None

        log_dirpath = guest_setup_log_dirpath(guest, log_dirpath)
        log_filepath = os.path.join(log_dirpath, 'guest-setup-output-{}.txt'.format(stage.value))

        logger = GuestSetupStageAdapter(guest.logger, stage)

        log_location = artifacts_location(self, log_filepath, logger=logger)
        logger.info('guest setup log is in {}'.format(log_location))

        # Detect playbooks and extra vars from the playbook map...
        playbooks_from_map, variables_from_map = self._get_details_from_map(guest, stage)

        # ... and command-line/config file options.
        playbooks_from_config = self._playbooks.get(stage.value, [])
        variables_from_config = self._extra_vars.get(stage.value, {})

        # For the final list of playbooks, command-line/configuration has higher priority.
        playbooks = playbooks_from_config or playbooks_from_map

        if not playbooks:
            logger.info('no setup playbooks')

            return Ok([])

        # The same applies to extra variables - those specified by command-line/configuration override all other
        # variables.
        if variables_from_config:
            variables = variables_from_config

        else:
            variables = variables or {}

            variables.update(variables_from_map)

        # Make type checking happy
        assert variables is not None

        variables['GUEST_SETUP_STAGE'] = stage.value

        log_dict(logger.debug, 'playbook variables', variables)

        # Detect Python interpreter for Ansible - this depends on the guest, it cannot be based
        # just on the artifact properties (some artifacts may need to be tested on a mixture
        # of different composes with different Python interpreters), therefore detect - unless,
        # of course, told otherwise by the caller.
        #
        # Also if user is specifying it's own playbooks, always autodetect ansible_python_interpreter
        if 'ansible_python_interpreter' not in variables:
            logger.debug('ansible interpreter not specified, trying to autodetect one')

            guest_interpreters = self.shared('detect_ansible_interpreter', guest)

            log_dict(logger.debug, 'detected interpreters', guest_interpreters)

            if not guest_interpreters:
                logger.warn('Cannot deduce Python interpreter for Ansible', sentry=True)

            else:
                variables['ansible_python_interpreter'] = guest_interpreters[0]

        log_dict(logger.debug, 'final playbook variables', variables)

        log_dict(logger.info, 'setting up with playbooks', playbooks)

        with Action(
            'configuring guest with playbooks',
            parent=Action.current_action(),
            logger=logger,
            tags={
                'guest': {
                    'hostname': guest.hostname,
                    'environment': guest.environment.serialize_to_json()
                },
                'playbook-paths': playbooks
            }
        ):
            ansible_output = self.shared(
                'run_playbook',
                playbooks,
                guest,
                variables=variables,
                json_output=False,
                logger=logger,
                log_filepath=log_filepath,
                extra_vars_filename_prefix='extra-vars-{}-'.format(stage.value),
                **kwargs
            )

        return Ok([
            GuestSetupOutput(
                stage=stage,
                label='guest setup',
                log_path=log_filepath,
                additional_data=ansible_output
            )
        ])

    def execute(self):
        # type: () -> None

        self.require_shared('run_playbook')

        if self.option('playbooks-map'):
            self.require_shared('evaluate_rules')
