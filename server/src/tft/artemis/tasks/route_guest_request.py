# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from .. import metrics
from ..db import DB
from ..guest import GuestState
from ..routing_policies import PolicyReturnType
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
from .acquire_guest_request import acquire_guest_request


class Workspace(_Workspace):
    """
    Workspace for guest request routing task.
    """

    @step
    def run(self) -> None:
        """
        Foo.
        """

        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.ROUTING)
            self.load_pools()

            if self.result:
                return

            assert self.gr

            r_ruling = cast(
                PolicyReturnType,
                self.run_hook(
                    'ROUTE',
                    session=self.session,
                    guest_request=self.gr,
                    pools=self.pools
                )
            )

            if r_ruling.is_error:
                return self._error(r_ruling, 'routing hook failed')

            ruling = r_ruling.unwrap()

            if ruling.cancel:
                self._progress('routing-cancelled')

                self.update_guest_state(
                    GuestState.ERROR,
                    current_state=GuestState.ROUTING
                )

                return

            # If no suitable pools found
            if not ruling.allows_pools:
                metrics.ProvisioningMetrics.inc_empty_routing(self.gr.last_poolname)

                return self._reschedule()

            # At this point, all pools are equally worthy: we may very well use the first one.
            current_poolname = self.gr.poolname
            new_poolname = ruling.allowed_rulings[0].pool.poolname

            self.update_guest_state_and_request_task(
                GuestState.PROVISIONING,
                acquire_guest_request,
                self.guestname,
                current_state=GuestState.ROUTING,
                set_values={
                    'poolname': new_poolname
                },
                poolname=new_poolname
            )

            # If new pool has been chosen, log failover.
            if new_poolname != current_poolname:
                self._event(
                    'routing-failover',
                    current_pool=current_poolname,
                    new_pool=new_poolname
                )

                metrics.ProvisioningMetrics.inc_failover(current_poolname, new_poolname)

    @staticmethod
    def route_guest_request(
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Find the most suitable pool for a given request, and dispatch its provisioning.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return Workspace(logger, session, db, guestname=guestname, task='route-guest-request') \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.ROUTING, GuestState.ERROR))
def route_guest_request(guestname: str) -> None:
    """
    Route guest request to the most suitable pool.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.route_guest_request),
        logger=get_guest_logger('route-guest-request', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
