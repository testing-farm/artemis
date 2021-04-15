# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from gluetool import SoftGlueError
from gluetool.utils import Command
from gluetool_modules.libs import run_and_log

# Type annotations
from typing import TYPE_CHECKING, List, Callable  # noqa

if TYPE_CHECKING:
    import gluetool # noqa
    import gluetool.utils # noqa


class BrewBuildFailedError(SoftGlueError):
    def __init__(self, message, output):
        # type: (str, gluetool.utils.ProcessOutput) -> None

        super(BrewBuildFailedError, self).__init__(message)
        self.output = output


def executor(command):
    # type: (List[str]) -> gluetool.utils.ProcessOutput
    return Command(command).run()


def run_command(command, log_path, comment, executor=executor):
    # type: (List[str], str, str, Callable[[List[str]], gluetool.utils.ProcessOutput]) -> gluetool.utils.ProcessOutput
    command_failed, err_msg, output = run_and_log(command=command,
                                                  log_filepath=log_path,
                                                  executor=executor
                                                  )

    if command_failed:
        raise BrewBuildFailedError('{} failed.'.format(comment), output)
    return output
