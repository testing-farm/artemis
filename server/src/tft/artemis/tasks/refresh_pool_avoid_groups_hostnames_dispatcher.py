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
from ..drivers.beaker import BeakerDriver
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
from .refresh_pool_avoid_groups_hostnames import refresh_pool_avoid_groups_hostnames

KNOB_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-avoid-groups-hostnames.schedule',
    'When to run refresh of Beaker avoid groups hostnames, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *',
)


class Workspace(_Workspace):
    """
    Workspace for hostname groups refresh dispatcher.
    """

    TASKNAME = 'refresh-pool-avoid-groups-hostnames-dispatcher'

    @step
    def run(self) -> None:
        """
        Foo.
        """

        with self.transaction():
            self.load_pools()

        if self.result:
            return

        self._progress('scheduling pool group avoidance hostnames refresh')

        for pool in self.pools:
            if self.result:
                return

            if not isinstance(pool, BeakerDriver):
                continue

            self.dispatch_task(
                refresh_pool_avoid_groups_hostnames,
                pool.poolname,
                logger=get_pool_logger(Workspace.TASKNAME, self.logger, pool.poolname),
            )

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
    def refresh_pool_avoid_groups_hostnames_dispatcher(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session
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

        return cls.create(logger, db, session).begin().run().complete().final_result


@task(
    periodic=periodiq.cron(KNOB_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC,
)
def refresh_pool_avoid_groups_hostnames_dispatcher() -> None:
    """
    Schedule refresh of hostname groups to avoid for suitable pools.
    """

    task_core(
        cast(DoerType, Workspace.refresh_pool_avoid_groups_hostnames_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME),
        session_read_only=True,
    )
