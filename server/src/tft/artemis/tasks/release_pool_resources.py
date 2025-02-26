# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule release of guest request and all its resources.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import PoolDriver
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    TaskLogger,
    TaskPriority,
    Workspace as _Workspace,
    get_guest_logger,
    step,
    task,
    task_core,
)


class Workspace(_Workspace):
    """
    Workspace for guest request release task.
    """

    TASKNAME = 'release-pool-resources'

    poolname: str
    serialized_resource_ids: str

    @step
    def run(self) -> None:
        with self.transaction():
            r_pool = PoolDriver.load(self.logger, self.session, self.poolname)

            if r_pool.is_error:
                return self._error(r_pool, 'pool sanity failed')

            pool = r_pool.unwrap()

            r_release = pool.release_pool_resources(self.logger, self.serialized_resource_ids)

            if r_release.is_error:
                # Irrecoverable failures in release-pool-resources chain shouldn't influence the guest request.
                # The release process is decoupled, and therefore pool outages should no longer affect the request.
                failure = r_release.unwrap_error()
                failure.fail_guest_request = False

                return self._error(r_release, 'failed to release pool resources')

            self._progress('released')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname: str,
        serialized_resource_ids: str,
        guestname: Optional[str]
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, task=Workspace.TASKNAME)

        workspace.poolname = poolname
        workspace.serialized_resource_ids = serialized_resource_ids
        workspace.guestname = guestname

        return workspace

    @classmethod
    def release_pool_resources(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname: str,
        serialized_resource_ids: str,
        guestname: Optional[str]
    ) -> DoerReturnType:
        """
        Schedule release of guest request resources.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, poolname, serialized_resource_ids, guestname) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(priority=TaskPriority.LOW)
def release_pool_resources(poolname: str, resource_ids: str, guestname: Optional[str]) -> None:
    if guestname:
        logger = get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname)

    else:
        logger = TaskLogger(_ROOT_LOGGER, Workspace.TASKNAME)

    task_core(
        cast(DoerType, Workspace.release_pool_resources),
        logger=logger,
        doer_args=(poolname, resource_ids, guestname)
    )
