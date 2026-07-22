# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule and execute a dummy task serving as an end-to-end check of worker stability.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
from typing import cast

import gluetool.log
import periodiq
import sqlalchemy.orm.session

from ..db import DB, DMLResult, GuestLog, GuestRequest
from ..knobs import Knob
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    TaskLogger,
    TaskPriority,
    TaskQueue,
    Workspace as _Workspace,
    step,
    task,
    task_core,
)

KNOB_GC_GUEST_LOGS_SCHEDULE: Knob[str] = Knob(
    'gc.guest-logs.schedule',
    'When to run garbage collection task for guest request logs.',
    has_db=False,
    envvar='ARTEMIS_GC_GUEST_LOGS_SCHEDULE',
    cast_from_str=str,
    default='15 */4 * * *',
)


KNOB_GC_GUEST_LOGS_THRESHOLD: Knob[int] = Knob(
    'gc.guest-logs.threshold',
    'How old must the guest logs be to be removed, in seconds.',
    has_db=False,
    envvar='ARTEMIS_GC_GUEST_LOGS_THRESHOLD',
    cast_from_str=int,
    default=86400 * 30,  # 30 days
)


class Workspace(_Workspace):
    """
    Workspace for garbage collection of guest logs.
    """

    TASKNAME = 'gc-guest-logs'

    @step
    def run(self) -> None:
        deadline = datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_GUEST_LOGS_THRESHOLD.value)

        self.logger.info(f'removing guest logs older than {deadline}')

        with self.transaction() as transaction:
            # TODO: INTERVAL is PostgreSQL-specific. We don't plan to use another DB, but, if we chose to,
            # this would have to be rewritten.
            guest_count_subquery = self.session.query(GuestRequest.guestname).subquery('t')

            query = sqlalchemy.delete(GuestLog)
            query = query.where(GuestLog.guestname.not_in(guest_count_subquery))  # type: ignore[arg-type]
            query = query.where(
                sqlalchemy.func.age(GuestLog.updated)
                >= sqlalchemy.func.cast(
                    f'{KNOB_GC_GUEST_LOGS_THRESHOLD.value} SECONDS',  # type: ignore[arg-type]
                    sqlalchemy.dialects.postgresql.INTERVAL,
                )
            )

            r: DMLResult[GuestLog] = transaction.execute_dml(self.logger, query)

            if r.is_error:
                return self._error(transaction, r, 'failed to remove guest logs')

            self.logger.info(f'removed {r.unwrap().rowcount} guest logs')

    @classmethod
    def create(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: newly created workspace.
        """

        return cls(logger, session, db=db, task=Workspace.TASKNAME)

    @classmethod
    def gc_guest_logs(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session
    ) -> DoerReturnType:
        """
        Remove old guest logs.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: task result.
        """

        return cls.create(logger, db, session).begin().run().complete().final_result


@task(
    singleton=True,
    singleton_no_retry_on_lock_fail=True,
    periodic=periodiq.cron(KNOB_GC_GUEST_LOGS_SCHEDULE.value),
    priority=TaskPriority.LOW,
    queue_name=TaskQueue.PERIODIC,
)
def gc_guest_logs() -> None:
    """
    Remove old guest logs.
    """

    task_core(cast(DoerType, Workspace.gc_guest_logs), logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME))
