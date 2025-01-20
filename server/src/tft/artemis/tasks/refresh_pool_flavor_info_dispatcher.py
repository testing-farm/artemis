# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import periodiq
import sqlalchemy.orm.session

from ..db import DB
from ..knobs import Knob
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    TaskLogger,
    TaskPriority,
    TaskQueue,
    Workspace as _Workspace,
    get_pool_logger,
    step,
    task,
    task_core,
)
from .refresh_pool_flavor_info import refresh_pool_flavor_info

KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-flavor-info.schedule',
    'When to run OpenStack flavor info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_FLAVOR_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *'
)


class Workspace(_Workspace):
    """
    Workspace for hostname groups refresh dispatcher.
    """

    TASKNAME = 'refresh-pool-flavor-info-dispatcher'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_pools()

            if self.result:
                return

            self._progress('scheduling pool flavor info refresh')

            for pool in self.pools:
                if self.result:
                    return

                self.dispatch_task(
                    refresh_pool_flavor_info,
                    pool.poolname,
                    logger=get_pool_logger(Workspace.TASKNAME, self.logger, pool.poolname)
                )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
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
    def refresh_pool_flavor_info_dispatcher(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session
    ) -> DoerReturnType:
        """
        Schedule refresh of hostname groups to avoid for suitable pools.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: task result.
        """

        return cls.create(logger, db, session) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(
    singleton=True,
    singleton_no_retry_on_lock_fail=True,
    periodic=periodiq.cron(KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC
)
def refresh_pool_flavor_info_dispatcher() -> None:
    """
    Dispatcher-like task for pool flavor info refresh. It is being scheduled periodically (by Periodiq),
    and it refreshes nothing on its own - instead, it gets a list of pools, and dispatches the actual refresh
    task for each pool.

    This way, we can use Periodiq (or similar package), which makes it much simpler to run tasks in
    a cron-like fashion, to schedule the task. It does not support this kind of scheduling with different
    parameters, so we have this task that picks parameters for its kids.

    We don't care about rescheduling or retries - this task would be executed again very soon, exponential
    retries would make the metrics more outdated.
    """

    task_core(
        cast(DoerType, Workspace.refresh_pool_flavor_info_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME)
    )
