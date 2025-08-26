# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
from typing import cast

import gluetool.log
import periodiq
import sqlalchemy.dialects
import sqlalchemy.dialects.postgresql
import sqlalchemy.orm.session

from ..db import DB, DMLResult, GuestEvent, GuestRequest, execute_dml
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

KNOB_GC_EVENTS_SCHEDULE: Knob[str] = Knob(
    'gc.events.schedule',
    'When to run garbage collection task for guest request events.',
    has_db=False,
    envvar='ARTEMIS_GC_EVENTS_SCHEDULE',
    cast_from_str=str,
    default='15 */4 * * *',
)


KNOB_GC_EVENTS_THRESHOLD: Knob[int] = Knob(
    'gc.events.threshold',
    'How old must the guest events be to be removed, in seconds.',
    has_db=False,
    envvar='ARTEMIS_GC_EVENTS_THRESHOLD',
    cast_from_str=int,
    default=86400 * 30,  # 30 days
)


class Workspace(_Workspace):
    """
    Workspace for worker ping task.
    """

    TASKNAME = 'gc-guest-events'

    @step
    def run(self) -> None:
        deadline = datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value)

        self.logger.info(f'removing events older than {deadline}')

        with self.transaction():
            # TODO: INTERVAL is PostgreSQL-specific. We don't plan to use another DB, but, if we chose to,
            # this would have to be rewritten.
            guest_count_subquery = self.session.query(GuestRequest.guestname)

            query = (
                sqlalchemy.delete(GuestEvent)
                .where(GuestEvent.guestname.not_in(guest_count_subquery))
                .where(
                    sqlalchemy.func.age(GuestEvent.updated)
                    >= sqlalchemy.func.cast(
                        sqlalchemy.func.concat(str(KNOB_GC_EVENTS_THRESHOLD.value), ' SECONDS'),
                        sqlalchemy.dialects.postgresql.INTERVAL,
                    )
                )
            )

            r_execute: DMLResult[GuestEvent] = execute_dml(self.logger, self.session, query)

            if r_execute.is_error:
                return self._error(r_execute, 'failed to select')

            self.logger.info(f'removed {r_execute.unwrap().rowcount} events')

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
    def gc_guest_events(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session
    ) -> DoerReturnType:
        """
        Update worker ping timestamp.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: task result.
        """

        return cls.create(logger, db, session).begin().run().complete().final_result


@task(
    singleton=True,
    singleton_no_retry_on_lock_fail=True,
    periodic=periodiq.cron(KNOB_GC_EVENTS_SCHEDULE.value),
    priority=TaskPriority.LOW,
    queue_name=TaskQueue.PERIODIC,
)
def gc_guest_events() -> None:
    task_core(cast(DoerType, Workspace.gc_guest_events), logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME))
