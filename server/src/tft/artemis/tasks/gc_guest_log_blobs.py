# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule and execute a dummy task serving as an end-to-end check of worker stability.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
import threading
from typing import cast

import gluetool.log
import periodiq
import sqlalchemy.orm.session

from ..db import DB, GuestLogBlob, GuestRequest, execute_dml
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType, TaskLogger
from . import Workspace as _Workspace
from . import step, task, task_core

KNOB_GC_GUEST_LOG_BLOBS_SCHEDULE: Knob[str] = Knob(
    'gc.guest-log-blobs.schedule',
    'When to run garbage collection task for guest request log blobs.',
    has_db=False,
    envvar='ARTEMIS_GC_GUEST_LOG_BLOBS_SCHEDULE',
    cast_from_str=str,
    default='15 */4 * * *'
)


KNOB_GC_GUEST_LOG_BLOBS_THRESHOLD: Knob[int] = Knob(
    'gc.guest-log-blobs.threshold',
    'How old must the guest log blobs be to be removed, in seconds.',
    has_db=False,
    envvar='ARTEMIS_GC_GUEST_LOG_BLOBS_THRESHOLD',
    cast_from_str=int,
    default=86400 * 30  # 30 days
)


class Workspace(_Workspace):
    """
    Workspace for garbage collection of guest log blobs.
    """

    TASKNAME = 'gc-guest-log-blobs'

    @step
    def run(self) -> None:
        deadline = datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_GUEST_LOG_BLOBS_THRESHOLD.value)

        self.logger.info(f'removing events older than {deadline}')

        with self.transaction():
            # TODO: INTERVAL is PostgreSQL-specific. We don't plan to use another DB, but, if we chose to,
            # this would have to be rewritten.
            guest_count_subquery = self.session.query(
                GuestRequest.guestname
            ).subquery('t')

            query = sqlalchemy \
                .delete(
                    GuestLogBlob.__table__
                ) \
                .where(GuestLogBlob.guestname.notin_(guest_count_subquery)) \
                .where(sqlalchemy.func.age(GuestLogBlob.ctime) >= sqlalchemy.func.cast(
                    f'{KNOB_GC_GUEST_LOG_BLOBS_THRESHOLD.value} SECONDS',
                    sqlalchemy.dialects.postgresql.INTERVAL
                ))

            r = execute_dml(self.logger, self.session, query)

            if r.is_error:
                return self._error(r, 'failed to remove guest log blobs')

            self.logger.info(f'removed {r.unwrap().rowcount} guest log blobs')

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
    def gc_guest_log_blobs(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event
    ) -> DoerReturnType:
        """
        Remove old guest log blobs.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(periodic=periodiq.cron(KNOB_GC_GUEST_LOG_BLOBS_SCHEDULE.value))
def worker_ping() -> None:
    """
    Remove old guest log blobs.
    """

    task_core(
        cast(DoerType, Workspace.gc_guest_log_blobs),
        logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME)
    )
