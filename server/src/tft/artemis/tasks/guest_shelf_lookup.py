# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Try to find a suitable guest, which can satisfy the request from the specified shelf.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import random
from typing import List, Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from ..db import DB, DMLResult, GuestRequest, SafeQuery, execute_dml
from ..guest import GuestState
from ..metrics import ShelfMetrics
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    GuestRequestWorkspace as _Workspace,
    ProvisioningTailHandler,
    get_guest_logger,
    step,
    task,
    task_core,
)
from .prepare_finalize_pre_connect import prepare_finalize_pre_connect
from .route_guest_request import route_guest_request


class Workspace(_Workspace):
    """
    Workspace for guest shelf lookup task.
    """

    TASKNAME = 'guest-shelf-lookup'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.SHELF_LOOKUP)

            if self.result:
                return

            assert self.gr

            if not self.gr.shelfname or self.gr.bypass_shelf_lookup is True:
                self.update_guest_state_and_request_task(
                    GuestState.ROUTING, route_guest_request, self.guestname, current_state=GuestState.SHELF_LOOKUP
                )

                return

            selected_guest: Optional[GuestRequest] = None

            r_guests = (
                SafeQuery.from_session(self.session, GuestRequest)
                .filter(GuestRequest.shelfname == self.gr.shelfname)
                .filter(GuestRequest.state == GuestState.SHELVED)
                .all()
            )

            if r_guests.is_error:
                return self._error(r_guests, 'failed to load shelved guests')

            shelved_guests: List[GuestRequest] = r_guests.unwrap()

            # TODO: if number of guests low start falling back to full provisioning
            # Try to find a suitable guest if the shelf is not empty
            while shelved_guests:
                guest = shelved_guests.pop(random.randrange(0, len(shelved_guests)))

                # TODO: Better environment and log types validation?
                if (
                    self.gr.ssh_keyname == guest.ssh_keyname
                    and self.gr.environment == guest.environment
                    and self.gr.skip_prepare_verify_ssh == guest.skip_prepare_verify_ssh
                    and self.gr.log_types == guest.log_types
                    and self.gr.post_install_script == guest.post_install_script
                ):
                    selected_guest = guest

                    ShelfMetrics.inc_hits(self.gr.shelfname)

                    # Use this guest to serve the GR
                    self.update_guest_state_and_request_task(
                        GuestState.PREPARING,
                        prepare_finalize_pre_connect,
                        self.guestname,
                        current_state=GuestState.SHELF_LOOKUP,
                        set_values={
                            attr: getattr(selected_guest, attr)
                            for attr in ['poolname', 'address', 'ssh_port', 'ssh_username', '_pool_data']
                        },
                    )

                    r_delete: DMLResult[GuestRequest] = execute_dml(
                        self.logger,
                        self.session,
                        sqlalchemy.delete(GuestRequest)
                        .where(GuestRequest.guestname == selected_guest.guestname)
                        .where(GuestRequest.state == GuestState.SHELVED),
                    )

                    if r_delete.is_error:
                        return self._error(r_delete, 'failed to remove the original guest request record')

                    ShelfMetrics.inc_removals(self.gr.shelfname)

            else:
                ShelfMetrics.inc_misses(self.gr.shelfname)

                self.update_guest_state_and_request_task(
                    GuestState.ROUTING, route_guest_request, self.guestname, current_state=GuestState.SHELF_LOOKUP
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
        :returns: task result.
        """

        return cls(logger, session, db, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def guest_shelf_lookup(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        """
        Try to find and use a suitable guest from the specified shelf. Otherwise dispatch routing.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


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
    )
