# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
If applicable, return the guest to a shelf, otherwise schedule a full release.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, GuestRequest, GuestShelf, SafeQuery
from ..guest import GuestState
from ..knobs import KNOB_SHELF_MAX_GUESTS
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest return to a shelf.
    """

    TASKNAME = 'return-guest-to-shelf'

    shelf: Optional[GuestShelf]
    shelved_count: int

    @step
    def entry(self) -> None:
        """
        Begin the process with nice logging and loading request data.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.CONDEMNED)

    @step
    def load_valid_shelf(self) -> None:
        """
        Load a shelf if specified in guest request
        """

        assert self.gr

        # Verify we can return the guest to the shelf
        # TODO: Determine if session isolation (REPEATABLE READ) access is required
        r_shelf = SafeQuery.from_session(self.session, GuestShelf) \
            .filter(GuestShelf.shelfname == self.gr.shelfname) \
            .filter(GuestShelf.state == GuestState.READY) \
            .one_or_none()

        if r_shelf.is_error:
            self.result = self.handle_error(r_shelf, 'failed to load shelf')
            return

        self.shelf = r_shelf.unwrap()

    @step
    def load_shelved_count(self) -> None:
        """
        Load the number of guests currently present in a shelf.
        """

        if self.shelf is None:
            return

        r_shelved_count = SafeQuery.from_session(self.session, GuestRequest) \
            .filter(GuestRequest.shelfname == self.shelf.shelfname) \
            .filter(GuestRequest.state == GuestState.SHELVED) \
            .count()

        if r_shelved_count.is_error:
            self.result = self.handle_error(r_shelved_count, 'failed to load the number of shelved guests')
            return

        self.shelved_count = r_shelved_count.unwrap()

    @step
    def load_shelf_max_guests(self) -> None:
        """
        Load the maximum number of guests allowed for a shelf.
        """

        if self.shelf is None:
            return

        r_shelf_max_guests = KNOB_SHELF_MAX_GUESTS.get_value(session=self.session, entityname=self.shelf.shelfname)

        if r_shelf_max_guests.is_error:
            self.result = self.handle_error(r_shelf_max_guests, 'failed to obtain the maximum allowed number of guests')
            return

        self.shelf_max_guests = r_shelf_max_guests.unwrap()

    @step
    def return_guest(self) -> None:
        """
        Return the guest to a shelf if possible.
        """

        assert self.gr

        if self.shelf is None:
            return

        # Don't shelve special guests containing HW requirements or post-install script for now
        # TODO: Add support to properly handle special guests
        if self.gr.post_install_script is not None or self.gr.environment.hw.constraints is not None:
            self.logger.debug('guest request specified post-install script or HW constraints, guest will be released')
            return

        if self.shelved_count >= self.shelf_max_guests:
            self.logger.debug(f'shelf {self.shelf.shelfname} is full, guest will be released')
            # Possibly schedule a task to release other guests if count > max??
            return

        # TODO: Dispatch WDOG task to verify the guest is reachable while shelved
        self.update_guest_state(GuestState.SHELVED, current_state=GuestState.CONDEMNED)

        self.result = self.handle_success('finished-task')

    @step
    def dispatch_release(self) -> None:
        """
        Dispatch guest release if we were not able to return it to a shelf.
        """

        from .release_guest_request import release_guest_request

        self.dispatch_task(release_guest_request, self.guestname)

    @step
    def exit(self) -> None:
        """
        Wrap up the shelf lookup process by updating metrics & final logging.
        """

        self.result = self.handle_success('finished-task')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> 'Workspace':
        return Workspace(logger, session, cancel, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def return_guest_to_shelf(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Try to return the guest to a shelf. Otherwise dispatch guest release.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, session, cancel, guestname) \
            .entry() \
            .load_valid_shelf() \
            .load_shelved_count() \
            .load_shelf_max_guests() \
            .return_guest() \
            .dispatch_release() \
            .exit() \
            .final_result


@task()
def return_guest_to_shelf(guestname: str) -> None:
    """
    Return the guest back to shelf (if specified).

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.return_guest_to_shelf),
        logger=get_guest_logger('return-guest-to-shelf', _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
