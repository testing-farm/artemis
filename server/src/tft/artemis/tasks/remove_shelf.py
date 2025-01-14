# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Remove shelf and schedule the removal of all shelved guests

.. note::

    Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
    MUST preserve consistent and restartable state.
"""
from typing import List, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, DMLResult, GuestRequest, GuestShelf, SafeQuery, execute_dml
from ..guest import GuestState
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    Workspace as _Workspace,
    _update_guest_state_and_request_task,
    get_guest_logger,
    get_shelf_logger,
    step,
    task,
    task_core,
)


class Workspace(_Workspace):
    """
    Workspace for shelf removal process.
    """

    TASKNAME = 'remove-shelf'
    shelved_guests: List[GuestRequest]

    @step
    def run(self) -> None:
        with self.transaction():
            assert self.shelfname

            self.load_shelf(self.shelfname, state=GuestState.CONDEMNED)

            if self.result:
                return

            r_guests = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.shelfname == self.shelfname) \
                .filter(GuestRequest.state == GuestState.SHELVED) \
                .all()

            if r_guests.is_error:
                return self._error(r_guests, 'failed to load shelved guests')

            shelved_guests: List[GuestRequest] = r_guests.unwrap()

            from .release_guest_request import release_guest_request

            for guest in shelved_guests:
                r = _update_guest_state_and_request_task(
                    get_guest_logger(Workspace.TASKNAME, self.logger, guest.guestname),
                    self.session,
                    guest.guestname,
                    GuestState.CONDEMNED,
                    release_guest_request,
                    guest.guestname,
                    current_state=GuestState.SHELVED,
                    set_values={
                        'shelfname': None
                    },
                    poolname=guest.poolname
                )

                if r.is_error:
                    return self._error(r, f'failed to update guest {guest.guestname} and schedule its release')

            update_query = sqlalchemy.update(GuestRequest) \
                .where(GuestRequest.shelfname == self.shelfname) \
                .values(shelfname=None)

            r_update: DMLResult[GuestRequest] = execute_dml(self.logger, self.session, update_query)

            if r_update.is_error:
                return self._error(r_update, 'failed to remove shelf from active guest requests')

            delete_query = sqlalchemy.delete(GuestShelf) \
                .where(GuestShelf.shelfname == self.shelfname) \
                .where(GuestShelf.state == GuestState.CONDEMNED)

            r_delete: DMLResult[GuestShelf] = execute_dml(self.logger, self.session, delete_query)

            if r_delete.is_error:
                return self._error(r, 'failed to remove shelf record')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        shelfname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param shelfname: name of the shelf to process.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, db=db, task=cls.TASKNAME)
        workspace.shelfname = shelfname

        return workspace

    @classmethod
    def remove_shelf(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        shelfname: str
    ) -> DoerReturnType:
        """
        Schedule the release of all guests belonging to shelf, remove the shelf from all active GRs, and remove the
        shelf itself.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param shelfname: name of the shelf to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, shelfname) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task()
def remove_shelf(shelfname: str) -> None:
    """
    Remove shelf and schedule release of all shelved guests.

    :param shelfname: name of the shelf to release.
    """

    task_core(
        cast(DoerType, Workspace.remove_shelf),
        logger=get_shelf_logger(Workspace.TASKNAME, _ROOT_LOGGER, shelfname),
        doer_args=(shelfname,)
    )
