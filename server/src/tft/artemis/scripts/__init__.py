# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pkgutil
from typing import Generator

from .. import tasks


def find_task_modules() -> Generator[str, None, None]:
    yield 'tft.artemis.tasks'

    for mi in sorted(pkgutil.iter_modules(tasks.__path__), key=lambda x: x.name):
        yield f'tft.artemis.tasks.{mi.name}'
