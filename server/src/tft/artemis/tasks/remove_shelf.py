# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Remove shelf and schedule the removal of all shelved guests

.. note::

    Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
    MUST preserve consistent and restartable state.
"""
import threading
from typing import List, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from .. import Failure
from ..db import DB, GuestRequest, GuestShelf, SafeQuery, safe_db_change
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import Workspace as _Workspace
from . import _update_guest_state_and_request_task, get_guest_logger, get_shelf_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for shelf removal process.
    """

    TASKNAME = 'remove-shelf'
    shelved_guests: List[GuestRequest]

    @step
    def entry(self) -> None:
        assert self.shelfname

        self.handle_success('entered-task')

        self.load_shelf(self.shelfname, state=GuestState.CONDEMNED)

    @step
    def load_shelved_guests(self) -> None:
        """
        Load a list containing all shelved guests.
        """

        assert self.shelfname

        r_guests = SafeQuery.from_session(self.session, GuestRequest) \
            .filter(GuestRequest.shelfname == self.shelfname) \
            .filter(GuestRequest.state == GuestState.SHELVED) \
            .all()

        if r_guests.is_error:
            self.result = self.handle_error(r_guests, 'failed to load shelved guests')
            return

        self.shelved_guests = r_guests.unwrap()

    @step
    def schedule_release_of_shelved_gr(self) -> None:
        """
        Schedule the release of shelved guests
        """

        from .release_guest_request import release_guest_request

        for guest in self.shelved_guests:
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
                }
            )

            if r.is_error:
                self.result = self.handle_error(r, f'failed to update guest {guest.guestname} and schedule its release')
                return

            if not r.unwrap():
                self.result = self.handle_failure(
                    Failure('foo'),
                    f'failed to update guest {guest.guestname} and schedule its release'
                )
                return

    @step
    def remove_shelf_from_active_gr(self) -> None:
        """
        Remove shelf association from active guests.
        """

        assert self.shelfname

        query = sqlalchemy.update(GuestRequest.__table__) \
            .where(GuestRequest.shelfname == self.shelfname) \
            .values(shelfname=None)

        r_update = safe_db_change(self.logger, self.session, query)

        if r_update.is_error:
            self.result = self.handle_error(r_update, 'failed to remove shelf from active guest requests')

    @step
    def delete_shelf(self) -> None:
        """
        Remove the entry of the actual shelf.
        """

        assert self.shelfname

        query = sqlalchemy.delete(GuestShelf.__table__) \
            .where(GuestShelf.shelfname == self.shelfname) \
            .where(GuestShelf.state == GuestState.CONDEMNED)

        r_delete = safe_db_change(self.logger, self.session, query)

        if r_delete.is_error:
            self.result = self.handle_error(r_delete, 'failed to remove shelf record')

    @step
    def exit(self) -> None:
        """
        Wrap up the shelf removal process.
        """

        self.result = self.handle_success('finished-task')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        shelfname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param shelfname: name of the shelf to process.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, cancel, db=db, task=cls.TASKNAME)
        workspace.shelfname = shelfname

        return workspace

    @classmethod
    def remove_shelf(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        shelfname: str
    ) -> DoerReturnType:
        """
        Schedule the release of all guests belonging to shelf, remove the shelf from all active GRs, and remove the
        shelf itself.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param shelfname: name of the shelf to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel, shelfname) \
            .entry() \
            .load_shelved_guests() \
            .schedule_release_of_shelved_gr() \
            .remove_shelf_from_active_gr() \
            .delete_shelf() \
            .exit() \
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
