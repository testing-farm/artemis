# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import re
import stat
import subprocess
import tempfile

import gluetool
from gluetool.action import Action
from gluetool.utils import Command, from_json
from gluetool.log import format_blob, log_blob, log_dict
from gluetool_modules.libs.sentry import PrimaryTaskFingerprintsMixin

# Type annotations
from typing import cast, TYPE_CHECKING, Any, Callable, Dict, List, NamedTuple, Optional, Tuple, Union  # noqa

if TYPE_CHECKING:
    import gluetool_modules.libs.guest  # noqa


# possible python interpreters
DEFAULT_ANSIBLE_PYTHON_INTERPRETERS = ["/usr/bin/python3", "/usr/bin/python2", "/usr/libexec/platform-python"]


# Default name of log file with Ansible output
ANSIBLE_OUTPUT = "ansible-output.txt"

EXTRA_VARS_FILENAME_PREFIX = 'extra-vars-'
EXTRA_VARS_FILENAME_SUFFIX = '.yaml'


#: Represents bundle of information we know about Ansible output.
#:
#: :ivar gluetool.utils.ProcessOutput execution_output: raw output of the command
#:     as returned by :py:meth:`gluetool.utils.Command.run`.
#: :ivar str json_output: if set, a Python data structure representing Ansible output.
#: :ivar str log_filepath: local path to a file with Ansible output.
AnsibleOutput = NamedTuple('AnsibleOutput', (
    ('execution_output', gluetool.utils.ProcessOutput),
    ('json_output', Optional[Any]),
    ('log_filepath', str)
))


class PlaybookError(PrimaryTaskFingerprintsMixin, gluetool.GlueError):
    def __init__(self, task, ansible_output):
        # type: (Any, gluetool.utils.ProcessOutput) -> None

        super(PlaybookError, self).__init__(task, 'Failure during Ansible playbook execution')

        self.ansible_output = ansible_output


class Ansible(gluetool.Module):
    """
    Helper module - give it a playbook, a guest, maybe few additional variables,
    and let Ansible perform it.

    Usually, guests are provided by other provisioning modules, e.g. ``openstack``
    or ``docker-provisioner``, playbooks are up to you.
    """

    name = 'ansible'
    description = 'Run an Ansible playbook on a given guest.'

    # pylint: disable=gluetool-option-hard-default
    options = {
        'ansible-playbook-options': {
            'help': "Additional ansible-playbook options, for example '-vvv'. (default: none)",
            'action': 'append',
            'default': []
        },
        'extra-variables-template-file': {
            'help': """
                    If specified, the templates in files are rendered into a YAML file which is then passed to every
                    playbook via ``--extra-vars="@foo.yaml`` option. (default: none)
                    """,
            'action': 'append',
            'default': []
        },
        'use-pipelining': {
            'help': 'If set, Ansible pipelining would be enabled for playbooks (default: %(default)s).',
            'default': 'no'
        },
        'interpreter-detection-order': {
            'help': 'Comma-separated Python binaries in the order autodetection should try them (default: {}).'.format(
                ','.join(DEFAULT_ANSIBLE_PYTHON_INTERPRETERS)
            ),
            'metavar': 'PATH,',
            'default': [],
            'action': 'append'
        },
        'ansible-playbook-filepath': {
            'help': """
                    Path to ansible-playbook executable file.
                    If not specified, the default executable is used (default: %(default)s).
                    """,
            'metavar': 'PATH',
            'default': subprocess.check_output(
                'command -v ansible-playbook 2> /dev/null || /bin/true',
                shell=True
            ).strip() or '/usr/bin/ansible-playbook'
        }
    }

    shared_functions = ['run_playbook', 'detect_ansible_interpreter']

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    @gluetool.utils.cached_property
    def additional_options(self):
        # type: () -> List[str]

        return gluetool.utils.normalize_multistring_option(self.option('ansible-playbook-options'))

    @gluetool.utils.cached_property
    def extra_variables_template_files(self):
        # type: () -> List[str]

        return gluetool.utils.normalize_path_option(self.option('extra-variables-template-file'))

    def _extra_variables_templates(self, filepaths):
        # type: (List[str]) -> List[str]

        templates = []

        for filepath in filepaths:
            try:
                with open(filepath, 'r') as f:
                    templates.append(f.read())

            except IOError as exc:
                raise gluetool.GlueError('Cannot open template file {}: {}'.format(filepath, exc))

        return templates

    def render_extra_variables_templates(
        self,
        logger,  # type: gluetool.log.ContextAdapter
        context,  # type: Dict[str, Any]
        template_filepaths=None,  # type: Optional[List[str]]
        filepath_dir=None,  # type: Optional[str]
        filename_prefix=EXTRA_VARS_FILENAME_PREFIX,  # type: str
        filename_suffix=EXTRA_VARS_FILENAME_SUFFIX  # type: str
    ):
        # type: (...) -> List[str]
        """
        Render template files. For each template file, a file with rendered content is created.

        :param logger: logger to use for logging.
        :param dict context: context to use for rendering.
        :param str template_filepaths: list of paths to template files. If not set, paths set via
            ``--extra-variables-template-file`` option are used.
        :param str filepath_dir: all files are created in this directory. If not set, current working directory
            is used.
        :param str filename_prefix: all file names begin with this prefix.
        :param str filename_suffix: all file names end with this suffix.
        :returns: list of paths to rendered files, one for each template.
        """

        template_filepaths = template_filepaths or self.extra_variables_template_files
        filepath_dir = filepath_dir or os.getcwd()

        filepaths = []

        for template in self._extra_variables_templates(template_filepaths):
            with tempfile.NamedTemporaryFile(
                prefix=filename_prefix,
                suffix=filename_suffix,
                dir=filepath_dir,
                delete=False
            ) as f:
                f.write(
                    gluetool.utils.render_template(template, logger=logger, **context)
                )

                f.flush()

            # Make the "temporary" file readable for investigation when pipeline's done.
            os.chmod(f.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            filepaths.append(f.name)

        return filepaths

    def detect_ansible_interpreter(self, guest):
        # type: (gluetool_modules.libs.guest.NetworkedGuest) -> List[str]
        """
        Detect Ansible's python interpreter on the given guest and return it.

        :param gluetool_modules.libs.guest.NetworkedGuest guest: Guest for auto-detection
        :returns: List of paths to the auto-detected python interpreters. Empty list if auto-detection failed.
        """

        assert guest.hostname is not None
        assert guest.key is not None

        if self.option('interpreter-detection-order'):
            ansible_python_interpreters = gluetool.utils.normalize_multistring_option(
                self.option('interpreter-detection-order')
            )

        else:
            ansible_python_interpreters = DEFAULT_ANSIBLE_PYTHON_INTERPRETERS

        cmd = [
            'ansible',
            '--inventory', '{},'.format(guest.hostname),
            '--private-key', guest.key,
            '--module-name', 'raw',
            '--args', 'command -v ' + ' '.join(ansible_python_interpreters),
            '--ssh-common-args',
            ' '.join(['-o ' + option for option in guest.options]),
            guest.hostname
        ]

        if guest.username:
            cmd += ['--user', guest.username]

        try:
            ansible_call = Command(cmd, logger=guest.logger).run()

        except gluetool.GlueCommandError as exc:
            self.warn('failed to auto-detect Ansible python interpreter\n{}'.format(
                exc.output.stdout))

            return []

        if not ansible_call.stdout:
            raise gluetool.GlueError('Ansible did not produce usable output')

        available_interpreters = [
            intrp for intrp in ansible_call.stdout.splitlines() if intrp in ansible_python_interpreters
        ]

        log_dict(guest.debug, 'available interpreters', available_interpreters)

        return available_interpreters

    def run_playbook(self,
                     playbook_paths,  # type: Union[str, List[str]]
                     guest,  # type: gluetool_modules.libs.guest.NetworkedGuest
                     variables=None,  # type: Optional[Dict[str, Any]]
                     inventory=None,  # type: Optional[str]
                     cwd=None,  # type: Optional[str]
                     env=None,  # type: Optional[Dict[str, Any]]
                     json_output=False,  # type: bool
                     logger=None,  # type: Optional[gluetool.log.ContextAdapter]
                     log_filepath=None,  # type: Optional[str]
                     extra_vars_filename_prefix=EXTRA_VARS_FILENAME_PREFIX,  # type: str
                     extra_vars_filename_suffix=EXTRA_VARS_FILENAME_SUFFIX,  # type: str
                     ansible_playbook_filepath=None  # type: Optional[str]
                    ):  # noqa
        # type: (...) -> AnsibleOutput
        """
        Run Ansible playbook on a given guest.

        :param str or list playbook_paths: Path to the playbook or a list of playbook paths.
        :param gluetool_modules.libs.guest.NetworkedGuest guest: Guest to run playbooks on.
        :param dict variables: If set, represents additional variables that will
            be passed to ``ansible-playbook`` using ``--extra-vars`` option.
        :param str inventory: A path to the inventory file. You can use it if you
            want to cheat the ansible module e.g. to overshadow localhost with another host.
        :param str cwd: A path to a directory where ansible will be executed from.
        :param dict(str, object) env: environment variables to use instead of the default, inherited environ.
        :param bool json_output: Ansible returns response as json if set.
        :param logger: Optional logger to use for logging. If no set, guest's logger is used by default.
        :param str log_filepath: Path to a file to store Ansible output in. If not set, ``ansible-output.txt``
            is created in the current directory.
        :param str extra_vars_filename_prefix: prefix used to name files generated from extra vars template files.
        :param str extra_vars_filename_suffix: suffix used to name files generated from extra vars template files.
        :returns: Instance of :py:class:`AnsibleOutput`.
        """

        logger = logger or guest.logger

        if isinstance(playbook_paths, str):
            playbook_paths = [playbook_paths]

        log_dict(logger.debug, 'running playbooks', playbook_paths)

        assert guest.key is not None
        assert guest.environment is not None

        inventory = inventory or '{},'.format(guest.hostname)  # note the comma

        env = env or os.environ.copy()

        log_filepath = log_filepath or os.path.join(os.getcwd(), ANSIBLE_OUTPUT)

        ansible_playbook_filepath = ansible_playbook_filepath or self.option('ansible-playbook-filepath')

        cmd = [
            ansible_playbook_filepath,
            '-i', inventory,
            '--private-key', guest.key
        ]

        if guest.username:
            cmd += ['--user', guest.username]

        if variables:
            log_dict(guest.debug, 'variables', variables)

            cmd += [
                '--extra-vars',
                ' '.join(['{}="{}"'.format(k, v) for k, v in variables.iteritems()])
            ]

        # Export common context variables
        context = gluetool.utils.dict_update(
            self.shared('eval_context'),
            {
                'GUEST': guest
            }
        )

        for filepath in self.render_extra_variables_templates(
            logger,
            context,
            filename_prefix=extra_vars_filename_prefix,
            filename_suffix=extra_vars_filename_suffix,
            filepath_dir=os.path.dirname(log_filepath)
        ):
            cmd += [
                '--extra-vars',
                '@{}'.format(filepath)
            ]

        cmd += self.additional_options

        if not self.dryrun_allows('Running a playbook in non-check mode'):
            logger.debug("dry run enabled, telling ansible to use 'check' mode")

            cmd += ['-C']

        def _update_env(var_name, var_value, on_present, on_missing):
            # type: (str, str, Callable[[], None], Callable[[], None]) -> None

            assert env is not None

            if var_name in env and env[var_name] != var_value:
                on_present()

                return

            env.update({
                var_name: var_value
            })

            on_missing()

        if json_output:
            env.update({
                'ANSIBLE_STDOUT_CALLBACK': 'json'
            })

        else:
            # When coupled with `-v`, provides structured and more readable output. But only if user didn't try
            # their own setup.
            def _json_on_present():
                # type: () -> None

                assert logger is not None

                logger.debug('ansible "debug" callback cannot be used, ANSIBLE_STDOUT_CALLBACK is already set')

            _update_env(
                'ANSIBLE_STDOUT_CALLBACK',
                'debug',
                _json_on_present,
                lambda: cmd.append('-v')
            )

        if gluetool.utils.normalize_bool_option(self.option('use-pipelining')):
            # Don't forget to set ANSIBLE_SSH_PIPELINING too, ANSIBLE_PIPELINING alone is not enough.
            def _env_on_missing():
                # type: () -> None

                assert logger is not None

                logger.debug('ansible pipelining cannot be used, ANSIBLE_PIPELINING is already set')

            def _env_on_present():
                # type: () -> None

                assert env is not None

                env.update({
                    'ANSIBLE_SSH_PIPELINING': 'True'
                })

            _update_env(
                'ANSIBLE_PIPELINING',
                'True',
                _env_on_present,
                _env_on_missing
            )

        cmd += [gluetool.utils.normalize_path(path) for path in playbook_paths]

        with Action(
            'running playbooks',
            parent=Action.current_action(),
            logger=logger,
            tags={
                'guest': {
                    'hostname': guest.hostname,
                    'environment': guest.environment.serialize_to_json()
                },
                'playbook-paths': playbook_paths
            }
        ):
            try:
                ansible_call = Command(cmd, logger=logger).run(cwd=cwd, env=env)

            except gluetool.GlueCommandError as exc:
                ansible_call = exc.output

        with open(log_filepath, 'w') as f:
            def _write(label, s):
                # type: (str, str) -> None

                f.write('{}\n{}\n\n'.format(label, s))

            _write('# STDOUT:', format_blob(cast(str, ansible_call.stdout)))
            _write('# STDERR:', format_blob(cast(str, ansible_call.stderr)))

            f.flush()

        def show_ansible_errors(output):
            # type: (gluetool.utils.ProcessOutput) -> None

            assert logger is not None

            if output.stdout:
                log_blob(
                    logger.error,
                    'Last 30 lines of Ansible stdout', '\n'.join(output.stdout.splitlines()[-30:])
                )

            if output.stderr:
                log_blob(
                    logger.error,
                    'Last 30 lines of Ansible stderr', '\n'.join(output.stderr.splitlines()[-30:])
                )

        if json_output:
            # With `-v` option, ansible-playbook produces additional output, placed before the JSON
            # blob. Find the first '{' on a new line, that should be the start of the actual JSON data.
            if not ansible_call.stdout:
                show_ansible_errors(ansible_call)

                raise gluetool.GlueError('Ansible did not produce usable output')

            match = re.search(r'^{', ansible_call.stdout, flags=re.M)
            if not match:
                show_ansible_errors(ansible_call)

                raise gluetool.GlueError('Ansible did not produce JSON output')

            ansible_json_output = from_json(ansible_call.stdout[match.start():])

            log_dict(
                logger.debug,
                'Ansible json output', ansible_json_output
            )

        else:
            ansible_json_output = None

        if ansible_call.exit_code != 0:
            show_ansible_errors(ansible_call)

            primary_task = self.shared('primary_task')
            if primary_task:
                raise PlaybookError(primary_task, ansible_call)

            raise gluetool.GlueError('Failure during Ansible playbook execution')

        return AnsibleOutput(
            execution_output=ansible_call,
            json_output=ansible_json_output,
            log_filepath=log_filepath
        )
