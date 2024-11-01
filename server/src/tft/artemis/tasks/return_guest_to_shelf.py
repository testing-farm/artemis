# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
If applicable, return the guest to a shelf, otherwise schedule a full release.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, GuestRequest, GuestShelf, SafeQuery
from ..guest import GuestState
from ..knobs import KNOB_SHELF_MAX_GUESTS
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import GuestRequestWorkspace as _Workspace
from . import get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest return to a shelf.
    """

    TASKNAME = 'return-guest-to-shelf'

    # shelf: Optional[GuestShelf]
    # shelved_count: int
    current_state: GuestState

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=self.current_state)

            if self.result:
                return

            assert self.gr

            # Verify we can return the guest to the shelf
            r_shelf = SafeQuery.from_session(self.session, GuestShelf) \
                .filter(GuestShelf.shelfname == self.gr.shelfname) \
                .filter(GuestShelf.state == GuestState.READY) \
                .one_or_none()

            if r_shelf.is_error:
                return self._error(r_shelf, 'failed to load shelf')

            def _release() -> None:
                from .release_guest_request import release_guest_request

                if self.current_state == GuestState.CONDEMNED:
                    self.request_task(release_guest_request, self.guestname)

                else:
                    self.update_guest_state_and_request_task(
                        GuestState.CONDEMNED,
                        release_guest_request,
                        self.guestname,
                        current_state=self.current_state
                    )

            shelf: Optional[GuestShelf] = r_shelf.unwrap()

            if shelf is None:
                _release()
                return

            r_shelved_count = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.shelfname == shelf.shelfname) \
                .filter(GuestRequest.state == GuestState.SHELVED) \
                .count()

            if r_shelved_count.is_error:
                return self._error(r_shelved_count, 'failed to load the number of shelved guests')

            shelved_count = r_shelved_count.unwrap()

            r_shelf_max_guests = KNOB_SHELF_MAX_GUESTS.get_value(session=self.session, entityname=shelf.shelfname)

            if r_shelf_max_guests.is_error:
                return self._error(r_shelf_max_guests, 'failed to obtain the maximum allowed number of guests')

            shelf_max_guests = r_shelf_max_guests.unwrap()

            # Don't shelve special guests containing HW requirements or post-install script for now
            # TODO: Add support to properly handle special guests
            if self.gr.post_install_script is not None or self.gr.environment.hw.constraints is not None:
                self.logger.debug('guest request specified extra post-install script or HW constraints')

                return _release()

            if shelved_count >= shelf_max_guests:
                self.logger.debug(f'shelf {shelf.shelfname} is full, guest will be released')

                return _release()

            # Switch state to SHELVED and dispatch a watchdog task
            from .shelved_guest_watchdog import shelved_guest_watchdog

            self.update_guest_state_and_request_task(
                GuestState.SHELVED,
                shelved_guest_watchdog,
                self.guestname,
                current_state=self.current_state
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        db: DB,
        guestname: str,
        current_state: GuestState
    ) -> 'Workspace':
        workspace = Workspace(logger, session, db, guestname=guestname, task=cls.TASKNAME)

        workspace.current_state = current_state

        return workspace

    @classmethod
    def return_guest_to_shelf(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        current_state: str
    ) -> DoerReturnType:
        """
        Try to return the guest to a shelf. Otherwise dispatch guest release.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :param current_state: current state of the guest request to be shelved.
        :returns: task result.
        """

        return cls \
            .create(logger, session, db, guestname, GuestState(current_state)) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task()
def return_guest_to_shelf(guestname: str, current_state: str) -> None:
    """
    Return the guest back to shelf (if specified).

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.return_guest_to_shelf),
        logger=get_guest_logger('return-guest-to-shelf', _ROOT_LOGGER, guestname),
        doer_args=(guestname, current_state)
    )
