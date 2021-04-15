# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import shlex
import sys

import gluetool
from gluetool.log import log_blob


class ExecuteCommand(gluetool.Module):
    """
    Run an arbitrary command, or their sequence, when the module is executed or destroyed. Log the output.
    Also provides shared function for executing commands during the runtime, on demand of other modules.
    """

    name = 'execute-command'
    description = 'Run an arbitrary command, or their sequence, and log the output.'

    # pylint: disable=gluetool-option-no-default-in-help
    options = {
        'command': {
            'help': 'Command to run.',
            'type': str,
            'action': 'append',
            'default': []
        },
        'script': {
            'help': 'Script - YAML file with a list of commands - to execute.',
            'type': str,
            'action': 'append',
            'default': []
        },
        'on-destroy': {
            'help': 'Execute commands when destroying the module, not when executing it (default: %(default)s).',
            'action': 'store_true',
            'default': 'no'
        }
    }

    shared_functions = ('execute_commands',)

    def _execute_command(self, command, printable=None):
        """
        Run a single command.

        :param list(str) command: A command to execute.
        :param str printable: Printable form of the command, used for logging purposes. If not set, it is created
            from ``command`` by joining its items with a space character (`` ``).
        :rtype: gluetool.utils.ProcessOutput
        :returns: output of the command.
        :raises: gluetool.GlueError when command finished with non-zero exit code.
        """

        printable = printable or ' '.join(command)

        self.info('Running command: {}'.format(printable))

        # Should the command exit with non-zero exit code, there will be an exception raised.
        # We want to do few things in either case, therefore we don't propagate that exception
        # from the `except` clause, but later. That costs us the automagicall exception chaining,
        # to do that manually we need to store exception info on our own.
        exc_info = None

        try:
            output = gluetool.utils.Command(command).run()

        except gluetool.GlueCommandError as exc:
            exc_info = sys.exc_info()

            output = exc.output

        (self.info if output.exit_code == 0 else self.error)('Exited with code {}'.format(output.exit_code))
        log_blob(self.info, 'stdout', output.stdout)
        log_blob(self.error, 'stderr', output.stderr)

        if output.exit_code != 0:
            raise gluetool.GlueError("Command '{}' exited with non-zero exit code".format(printable),
                                     caused_by=exc_info)

        return output

    def _execute_command_templates(self, commands, context_extra=None):
        """
        Execute sequence of commands, represented as a list of templates. Each template is first rendred
        and the resulting string is treated as a command to execute.

        :param list(str) commands: templates of commands to execute.
        :param dict context_extra: if set, it is added to a context used when redering the templates.
        """

        context = gluetool.utils.dict_update(
            self.shared('eval_context'),
            context_extra or {}
        )

        for command in commands:
            rendered_command = gluetool.utils.render_template(command, logger=self.logger, **context)

            self._execute_command(shlex.split(rendered_command), printable=command)

    def execute_commands(self, commands, context_extra=None):
        """
        Execute sequence of commands, represented as a list of templates. Each template is first rendred
        and the resulting string is treated as a command to execute.

        :param list(str) commands: templates of commands to execute.
        :param dict context_extra: if set, it is added to a context used when redering the templates.
        """

        self._execute_command_templates(commands, context_extra=context_extra)

    @gluetool.utils.cached_property
    def _external_commands(self):
        """
        Gather commands specified by module options, and provide them transparently to other parts of the module.

        :rtype: list(str)
        """

        commands = []

        if self.option('command'):
            commands = self.option('command')

        else:
            for script in gluetool.utils.normalize_path_option(self.option('script')):
                script_commands = gluetool.utils.load_yaml(script, logger=self.logger)

                if not isinstance(script_commands, list):
                    raise gluetool.GlueError("Script '{}' does not contain a list of commands".format(script))

                commands += script_commands

        return commands

    def execute(self):
        if gluetool.utils.normalize_bool_option(self.option('on-destroy')):
            return

        self._execute_command_templates(self._external_commands)

    def destroy(self, failure=None):
        if not gluetool.utils.normalize_bool_option(self.option('on-destroy')):
            return

        self._execute_command_templates(self._external_commands, context_extra={
            'FAILURE': failure
        })
