# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import multiprocessing
import os
import pkgutil
import shutil
import sys
from typing import Generator, List, Optional

import click

from .. import get_logger, tasks

# Worker threads default is hard to pick, it can be literally any integer. While for processes,
# experience tends to map them to CPU cores, threads are harder to set. Therefor picking one low
# integer just to be done with it.
DEFAULT_PROCESS_COUNT = multiprocessing.cpu_count()
DEFAULT_THREAD_COUNT = 4

DRAMATIQ_PATH = shutil.which('dramatiq')


def find_task_modules() -> Generator[str, None, None]:
    yield 'tft.artemis.tasks'

    for mi in sorted(pkgutil.iter_modules(tasks.__path__), key=lambda x: x.name):  # type: ignore[attr-defined]
        yield f'tft.artemis.tasks.{mi.name}'


@click.command()
@click.option(
    '-p', '--processes',
    metavar='PROCESSES',
    help=f'Number of worker processes to spawn. (default: {DEFAULT_PROCESS_COUNT})',
    default=None,
    envvar='ARTEMIS_WORKER_PROCESSES'
)
@click.option(
    '-t', '--threads',
    metavar='THREADS',
    help=f'Number of worker threads to spawn per process. (default: {DEFAULT_THREAD_COUNT})',
    default=None,
    envvar='ARTEMIS_WORKER_THREADS'
)
@click.option(
    '-q', '--queue',
    metavar='QUEUE',
    multiple=True,
    help='If specified, worker will listen to only the given queues. (default: unset, all queues are followed)',
    default=[],
    envvar='ARTEMIS_WORKER_QUEUES'
)
@click.option(
    '-T', '--tasks',
    metavar='MODULE',
    multiple=True,
    help='If specified, only tasks from these modules will run. (default: unset, all tasks will run)',
    default=[]
)
@click.option(
    '--queue-prefetch',
    metavar='N',
    help='Number of messages to prefetch from regular queues. (default: 2 for each worker thread)',
    default=None,
    envvar='ARTEMIS_WORKER_PREFETCH'
)
@click.option(
    '--delay-queue-prefetch',
    metavar='N',
    help='Number of messages to prefetch from delay queues. (default: 1000 for each worker thread)',
    default=None,
    envvar='ARTEMIS_WORKER_PREFETCH_DELAYED'
)
def cmd_root(
    processes: Optional[int],
    threads: Optional[int],
    queue: List[str],
    tasks: List[str],
    queue_prefetch: Optional[int],
    delay_queue_prefetch: Optional[int]
) -> None:
    logger = get_logger()

    if DRAMATIQ_PATH is None:
        logger.error('no "dramatiq" executable found')

        sys.exit(1)

    cmd: List[str] = [
        'dramatiq'
    ]

    if processes is not None:
        logger.info(f'spawning {processes} worker processes')

        cmd += ['--processes', str(processes)]

    else:
        logger.warning('spawning *default* number of worker processes')

    if threads is not None:
        logger.info(f'spawning {threads} worker threads per process')

        cmd += ['--threads', str(threads)]

    else:
        logger.warning('spawning *default* number of worker threads per process')

    if queue:
        logger.info(f'listening to limited number of queues: {", ".join(queue)}')

        # It should work as separate items, but for some reason, Dramatiq refuses to accept such a form.
        # Therefore merging value with option into a single cmd item.
        cmd += [f'--queues={" ".join(queue)}']

    else:
        logger.info('listening to all queues')

    if tasks:
        logger.info(f'running limited set of tasks: {", ".join(tasks)}')

        cmd += tasks

    else:
        logger.info('running all tasks from tft.artemis.tasks package')

        cmd += list(find_task_modules())

    env = os.environ.copy()

    if queue_prefetch is not None:
        logger.info(f'pre-fetching {queue_prefetch} messages per worker process')

        env['dramatiq_queue_prefetch'] = str(queue_prefetch)

    else:
        logger.warning('pre-fetching *default* number of messages per worker process')

    if delay_queue_prefetch is not None:
        logger.info(f'pre-fetching {delay_queue_prefetch} delayed messages per worker process')

        env['dramatiq_delay_queue_prefetch'] = str(delay_queue_prefetch)

    else:
        logger.warning('pre-fetching *default* number of delayed messages per worker process')

    os.execve(
        DRAMATIQ_PATH,
        cmd,
        env
    )


if __name__ == '__main__':
    cmd_root()
