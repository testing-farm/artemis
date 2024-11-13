# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule release of guest request and all its resources.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, DMLResult, GuestRequest, execute_dml
from ..drivers import PoolData
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import GuestRequestWorkspace as _Workspace
from . import get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest request release task.
    """

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.CONDEMNED)

            if self.result:
                return

            assert self.gr

            if self.gr.poolname is not None and not PoolData.is_empty(self.gr):
                self.mark_note_poolname()
                self.load_gr_pool()

                if self.result:
                    return

                assert self.pool

                r_release = self.pool.release_guest(self.logger, self.gr)

                if r_release.is_error:
                    return self._error(r_release, 'failed to release guest')

            r_delete: DMLResult[GuestRequest] = execute_dml(
                self.logger,
                self.session,
                sqlalchemy
                .delete(GuestRequest)
                .where(GuestRequest.guestname == self.guestname)
                .where(GuestRequest.state == GuestState.CONDEMNED)
            )

            if r_delete.is_error:
                return self._error(r_delete, 'failed to remove guest request record')

            self._progress('released')

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

        return cls(logger, session, db, guestname, task='release-guest-request')

    @classmethod
    def release_guest_request(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Schedule release of guest request resources.

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
def release_guest_request(guestname: str) -> None:
    """
    Schedule release of guest request resources.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.release_guest_request),
        logger=get_guest_logger('release-guest-request', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
