# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

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
from ..drivers.beaker import BeakerDriver
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType, TaskLogger, TaskPriority, TaskQueue
from . import Workspace as _Workspace
from . import get_pool_logger, refresh_pool_avoid_groups_hostnames, step, task, task_core

KNOB_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-avoid-groups-hostnames.schedule',
    'When to run refresh of Beaker avoid groups hostnames, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *'
)


class Workspace(_Workspace):
    """
    Workspace for hostname groups refresh dispatcher.
    """

    TASKNAME = 'refresh-pool-avoid-groups-hostnames-dispatcher'

    @step
    def entry(self) -> None:
        """
        Begin the dispatching with nice logging.
        """

        self.handle_success('entered-task')

    @step
    def dispatch_refresh(self) -> None:
        """
        For each Beaker pool, dispatch a refresh of its hostname groups.
        """

        for pool in self.pools:
            if self.result:
                break

            if not isinstance(pool, BeakerDriver):
                continue

            self.dispatch_task(
                refresh_pool_avoid_groups_hostnames,
                pool.poolname,
                logger=get_pool_logger(Workspace.TASKNAME, self.logger, pool.poolname)
            )

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
    def refresh_pool_avoid_groups_hostnames_dispatcher(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event
    ) -> DoerReturnType:
        """
        Schedule refresh of hostname groups to avoid for suitable pools.

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
            .load_pools() \
            .dispatch_refresh() \
            .exit() \
            .final_result


@task(
    periodic=periodiq.cron(KNOB_REFRESH_POOL_AVOID_GROUPS_HOSTNAMES_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC
)
def refresh_pool_avoid_groups_hostnames_dispatcher() -> None:
    """
    Schedule refresh of hostname groups to avoid for suitable pools.
    """

    task_core(
        cast(DoerType, Workspace.refresh_pool_avoid_groups_hostnames_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME)
    )
