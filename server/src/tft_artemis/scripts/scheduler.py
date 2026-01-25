# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os
import shutil
import sys

import click

from .. import get_logger
from . import find_task_modules

PERIODIQ_PATH = shutil.which('periodiq')


@click.command()
@click.option(
    '-T',
    '--tasks',
    metavar='MODULE',
    multiple=True,
    help='If specified, only tasks from these modules will run. (default: unset, all tasks will run)',
    default=[],
)
def cmd_root(tasks: list[str]) -> None:
    logger = get_logger()

    if PERIODIQ_PATH is None:
        logger.error('no "periodiq" executable found')

        sys.exit(1)

    cmd: list[str] = ['periodiq']

    if tasks:
        logger.info(f'scheduling limited set of tasks: {", ".join(tasks)}')

        cmd += tasks

    else:
        logger.info('scheduling all tasks from tft_artemis.tasks package')

        cmd += list(find_task_modules())

    os.execve(PERIODIQ_PATH, cmd, os.environ.copy())


if __name__ == '__main__':
    cmd_root()
