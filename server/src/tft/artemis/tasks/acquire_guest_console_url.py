# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast

import gluetool.log
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
    """
    Workspace for guest request update task.
    """

    TASKNAME = 'acquire-guest-console-url'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname)
            self.load_gr_pool()

            if self.result:
                return None

            assert self.pool
            assert self.gr
            # assert workspace.gr.poolname

            r_console = self.pool.acquire_console_url(self.logger, self.gr)

            if r_console.is_error:
                self._error(r_console, 'failed to get guest console', no_effect=True)

                return self._reschedule()

            console_url_data = r_console.unwrap()

            self.update_guest_state(
                GuestState(self.gr.state),
                set_values={
                    'console_url': console_url_data.url,
                    'console_url_expires': console_url_data.expires,
                },
                current_pool_data=self.gr._pool_data,
            )

    @classmethod
    def create(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
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
    def acquire_guest_console_url(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task()
def acquire_guest_console_url(guestname: str) -> None:
    task_core(
        cast(DoerType, Workspace.acquire_guest_console_url),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
