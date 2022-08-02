# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Schedule release of guest request and all its resources.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, GuestRequest, safe_db_change
from ..drivers import PoolData
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest request release task.
    """

    # current_pool_data: PoolData
    # provisioning_progress: ProvisioningProgress
    # new_guest_data: Dict[str, Union[str, int, None, datetime.datetime, GuestState]]

    @step
    def entry(self) -> None:
        """
        Begin the release process with nice logging and loading request data and pool.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.CONDEMNED)

    @step
    def load_pool(self) -> None:
        assert self.gr

        if self.gr.poolname is None or PoolData.is_empty(self.gr):
            return

        self.mark_note_poolname()
        self.load_gr_pool()

    @step
    def handle_pool_resources(self) -> None:
        assert self.gr

        if self.pool is None:
            return

        r_release = self.pool.release_guest(self.logger, self.gr)

        if r_release.is_error:
            self.result = self.handle_error(r_release, 'failed to release guest')
            return

    @step
    def remove_guest_request(self) -> None:
        query = sqlalchemy \
            .delete(GuestRequest.__table__) \
            .where(GuestRequest.guestname == self.guestname) \
            .where(GuestRequest.state == GuestState.CONDEMNED)

        r_delete = safe_db_change(self.logger, self.session, query)

        if r_delete.is_error:
            self.result = self.handle_error(r_delete, 'failed to remove guest request record')
            return

        # We ignore the actual return value: the query was executed, but we either removed exactly one record,
        # which is good, or we removed 0 records, which is also acceptable, as somebody already did that for us.
        # We did schedule the release of resources successfully, which means we left no loose ends.
        self.handle_success('released')

    @step
    def exit(self) -> None:
        """
        Wrap up the routing process by updating metrics & final logging.
        """

        self.result = self.handle_success('finished-task')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        return cls(logger, session, cancel, db=db, guestname=guestname, task='release-guest-request')

    @classmethod
    def release_guest_request(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Schedule release of guest request resources.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel, guestname) \
            .entry() \
            .load_pool() \
            .handle_pool_resources() \
            .remove_guest_request() \
            .exit() \
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
