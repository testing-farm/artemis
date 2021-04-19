# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os

import gluetool

from typing import Any, Dict, Optional  # noqa


class TriggerMessage(gluetool.Module):
    """
    Provides access to the message that triggered the current pipeline. Usually, not
    important, unless you bind your pipeline to the Jenkins, in which case the triggering
    message might be exported by Jenkins or its plugins to triggered builds via
    environment variable.

    This module then reads the message, and provides it to the pipeline while converting it
    from a JSON string to internal Python data types and structures.
    """

    name = 'trigger-message'
    description = 'Provides access to the message that triggered the current pipeline.'

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = {
        'source': {
            'help': 'From which source read the message, either ``environment`` or ``file``.',
            'type': str,
            'choices': ('environment', 'file')
        },
        'env-var': {
            'help': 'Environment variable providing the message.',
            'type': str
        },
        'input-file': {
            'help': 'File from which the message is read, when ``source`` is set to ``file``.',
            'type': str
        },
        'output-file': {
            'help': 'If set, the message will be saved into this file.',
            'type': str
        }
    }

    required_options = ('source',)

    shared_functions = ['trigger_message']

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(TriggerMessage, self).__init__(*args, **kwargs)

        self._message = None  # type: Optional[str]

    @property
    def eval_context(self):
        # type: () -> Dict[str, str]
        # pylint: disable=unused-variable
        __content__ = {  # noqa
            'TRIGGER_MESSAGE': """
                               Trigger message.
                               """,
        }

        if not self._message:
            self.debug('No trigger message available, cannot pass it to eval_context')
            return {}

        return {
            'TRIGGER_MESSAGE': self._message
        }

    def trigger_message(self):
        # type: () -> Optional[str]
        return self._message

    def sanity(self):
        # type: () -> None
        if self.option('source') == 'file' and not self.option('input-file'):
            raise gluetool.utils.IncompatibleOptionsError("'file' source requires --input-file option")

        if self.option('source') == 'environment' and not self.option('env-var'):
            raise gluetool.utils.IncompatibleOptionsError("'environment' source requires --env-var option")

    def execute(self):
        # type: () -> None
        if self.option('source') == 'file':
            self._message = gluetool.utils.load_json(self.option('input-file'), logger=self.logger)

        elif self.option('source') == 'environment':
            gluetool.log.log_dict(self.debug, 'current environment variables', dict(os.environ))

            value = os.getenv(self.option('env-var'), None)

            if value is None:
                raise gluetool.GlueError("Environment variable '{}' not set.".format(self.option('env-var')))

            self._message = gluetool.utils.from_json(value)

        gluetool.log.log_dict(self.debug, 'triggering message', self._message)

        if self.option('output-file'):
            gluetool.utils.dump_yaml(self._message, self.option('output-file'), logger=self.logger)

            self.info("Message saved into '{}'".format(self.option('output-file')))
