# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Try to find a suitable guest, which can satisfy the request from the specified shelf.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import random
import threading
from typing import List, Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, GuestRequest, SafeQuery, safe_db_change
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import get_guest_logger, guest_request_prepare_finalize_pre_connect, step, task, task_core
from .route_guest_request import route_guest_request


class Workspace(_Workspace):
    """
    Workspace for guest shelf lookup task.
    """

    TASKNAME = 'guest-shelf-lookup'

    shelved_guests: List[GuestRequest]
    selected_guest: Optional[GuestRequest] = None

    @step
    def entry(self) -> None:
        """
        Begin the routing process with nice logging and loading request data.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.SHELF_LOOKUP)

    @step
    def shelf_query(self) -> None:
        """
        Query for guests in cache.
        """

        # Access shelf, and try to choose a guest
        assert self.gr

        r_guests = SafeQuery.from_session(self.session, GuestRequest) \
            .filter(GuestRequest.shelfname == self.gr.shelfname) \
            .filter(GuestRequest.state == GuestState.SHELVED) \
            .all()

        if r_guests.is_error:
            self.result = self.handle_error(r_guests, 'failed to load shelved guests')
            return

        self.shelved_guests = r_guests.unwrap()

    @step
    def select_guest(self) -> None:
        """
        Find a suitable guest.
        """

        assert self.gr

        # TODO: if number of guests low start falling back to full provisioning
        # Try to find a suitable guest if the shelf is not empty
        while self.shelved_guests:
            guest = self.shelved_guests.pop(random.randrange(0, len(self.shelved_guests)))

            # TODO: Better environment and log types validation?
            if self.gr.ssh_keyname == guest.ssh_keyname \
                    and self.gr.environment == guest.environment \
                    and self.gr.skip_prepare_verify_ssh == guest.skip_prepare_verify_ssh \
                    and self.gr.log_types == guest.log_types \
                    and self.gr.post_install_script == guest.post_install_script:
                self.selected_guest = guest

    @step
    def use_guest(self) -> None:
        """
        Use the found shelved guest to serve the current request.
        """

        if not self.selected_guest:
            return

        # Use this guest to serve the GR
        self.update_guest_state_and_request_task(
            GuestState.PREPARING,
            guest_request_prepare_finalize_pre_connect,
            self.guestname,
            current_state=GuestState.SHELF_LOOKUP,
            set_values={
                attr: getattr(self.selected_guest, attr)
                for attr in ['poolname', 'address', 'ssh_port', 'ssh_username', 'pool_data']
            }
        )

    @step
    def remove_shelved_gr(self) -> None:
        """
        Delete the old guest entry in the DB as its parameters were copied to the new GR
        """

        if not self.selected_guest:
            return

        query = sqlalchemy.delete(GuestRequest.__table__) \
            .where(GuestRequest.guestname == self.selected_guest.guestname) \
            .where(GuestRequest.state == GuestState.SHELVED)

        r_delete = safe_db_change(self.logger, self.session, query)

        if r_delete.is_error:
            self.result = self.handle_error(r_delete, 'failed to remove the original guest request record')
            return

        self.result = self.handle_success('finished-task')

    @step
    def shelf_miss(self) -> None:
        """
        Switch to routing if shelf lookup failed.
        """

        self.update_guest_state_and_request_task(
            GuestState.ROUTING,
            route_guest_request,
            self.guestname,
            current_state=GuestState.SHELF_LOOKUP
        )

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
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls(logger, session, cancel, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def guest_shelf_lookup(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Try to find and use a suitable guest from the specified shelf. Otherwise dispatch routing.

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
            .shelf_query() \
            .select_guest() \
            .use_guest() \
            .remove_shelved_gr() \
            .shelf_miss() \
            .exit() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.SHELF_LOOKUP, GuestState.SHELF_LOOKUP))
def guest_shelf_lookup(guestname: str) -> None:
    """
    Attempt to find a suitable guest in a shelf (if specified).

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.guest_shelf_lookup),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
        session_isolation=True
    )
