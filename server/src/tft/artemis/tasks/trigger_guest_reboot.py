# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Trigger a hard guest reboot.
"""

from typing import cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB
from ..guest import GuestState
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    GuestRequestWorkspace as _Workspace,
    get_guest_logger,
    step,
    task,
    task_core,
)


class Workspace(_Workspace):
    TASKNAME = 'trigger-guest-reboot'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.READY)
            self.load_gr_pool()
            self.test_pool_enabled()

            if self.result:
                return

            if not self.is_pool_enabled:
                self._guest_request_event('pool-disabled')

                return

            assert self.gr
            assert self.pool

            r = self.pool.trigger_reboot(self.logger, self.gr)

            if r.is_error:
                return self._error(r, 'failed to trigger guest reboot')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        return cls(logger, session, db, guestname, task=Workspace.TASKNAME)

    @classmethod
    def trigger_guest_reboot(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Trigger a hard guest reboot.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task()
def trigger_guest_reboot(guestname: str) -> None:
    """
    Trigger a hard guest reboot.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.trigger_guest_reboot),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
