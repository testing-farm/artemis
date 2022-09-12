# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule and execute a dummy task serving as an end-to-end check of worker stability.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import cast

import gluetool.log
import periodiq
import sqlalchemy.orm.session

from ..db import DB
from ..knobs import Knob
from ..metrics import WorkerMetrics
from . import _ROOT_LOGGER, DoerReturnType, DoerType, TaskLogger
from . import Workspace as _Workspace
from . import step, task, task_core

KNOB_WORKER_PING_TASK_SCHEDULE: Knob[str] = Knob(
    'actor.worker-ping.schedule',
    'When to run worker ping task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_WORKER_PING_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *'
)


class Workspace(_Workspace):
    """
    Workspace for worker ping task.
    """

    TASKNAME = 'worker-ping'

    @step
    def entry(self) -> None:
        """
        Begin the dispatching with nice logging.
        """

        self.handle_success('entered-task')

    @step
    def update_metrics(self) -> None:
        WorkerMetrics.update_worker_ping()

    @step
    def exit(self) -> None:
        """
        Wrap up the dispatching with final logging.
        """

        self.result = self.handle_success('finished-task')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :returns: newly created workspace.
        """

        return cls(logger, session, cancel, db=db, task=Workspace.TASKNAME)

    @classmethod
    def worker_ping(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event
    ) -> DoerReturnType:
        """
        Update worker ping timestamp.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel) \
            .entry() \
            .update_metrics() \
            .exit() \
            .final_result


@task(periodic=periodiq.cron(KNOB_WORKER_PING_TASK_SCHEDULE.value))
def worker_ping() -> None:
    """
    Update worker ping timestamp.
    """

    task_core(
        cast(DoerType, Workspace.worker_ping),
        logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME)
    )
