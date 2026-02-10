# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import PoolDriver
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    TaskPriority,
    TaskQueue,
    Workspace as _Workspace,
    get_pool_logger,
    step,
    task,
    task_core,
)


# TODO: this belongs to Beaker driver, but there's no mechanism in place for easy custom tasks.
class Workspace(_Workspace):
    """
    Workspace for worker ping task.
    """

    TASKNAME = 'refresh-pool-flavor-info'

    poolname: str

    @step
    def run(self) -> None:
        # Handling errors is slightly different in this task. While we fully use `handle_error()`,
        # we do not return `RESCHEDULE` or `Error()` from this doer. This particular task is being
        # rescheduled regularly anyway, and we probably do not want exponential delays, because
        # they wouldn't make data any fresher when we'd finally succeed talking to the pool.
        #
        # On the other hand, we schedule next iteration of this task here, and it seems to make sense
        # to retry if we fail to schedule it - without this, the "it will run once again anyway" concept
        # breaks down.

        with self.transaction():
            r_pool = PoolDriver.load(self.logger, self.session, self.poolname)

            if r_pool.is_error:
                return self._error(r_pool, 'failed to load pool')

            pool = r_pool.unwrap()

            r_enabled = pool.is_enabled(self.session)

            if r_enabled.is_error:
                return self._error(r_enabled, 'failed to inspect pool')

        if r_enabled.unwrap() is not True:
            self._progress('pool-disabled')

            return None

        r_refresh = pool.refresh_cached_pool_flavor_info()

        if r_refresh.is_error:
            return self._error(r_refresh, 'failed to refresh pool flavor info')

    @classmethod
    def create(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, poolname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, db=db, task=Workspace.TASKNAME)
        workspace.poolname = poolname

        return workspace

    @classmethod
    def refresh_pool_flavor_info(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, poolname: str
    ) -> DoerReturnType:
        return cls.create(logger, db, session, poolname).begin().run().complete().final_result


@task(
    singleton=True,
    singleton_no_retry_on_lock_fail=True,
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.POOL_DATA_REFRESH,
)
def refresh_pool_flavor_info(poolname: str) -> None:
    task_core(
        cast(DoerType, Workspace.refresh_pool_flavor_info),
        logger=get_pool_logger(Workspace.TASKNAME, _ROOT_LOGGER, poolname),
        doer_args=(poolname,),
        session_read_only=True,
    )
