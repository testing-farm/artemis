# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import Optional, cast

import gluetool.log
import sqlalchemy.orm.session

from .. import metrics
from ..db import DB
from ..drivers import PoolDriver
from ..guest import GuestState
from ..routing_policies import PolicyRuling
from . import _ROOT_LOGGER, RESCHEDULE, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import acquire_guest_request, get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest request routing task.
    """

    ruling: Optional[PolicyRuling] = None
    current_poolname: Optional[str] = None
    new_pool: Optional[PoolDriver] = None

    @step
    def entry(self) -> None:
        """
        Begin the routing process with nice logging and loading request data.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.ROUTING)

    @step
    def query_policies(self) -> None:
        """
        Query routing policies to find out what shall be done with the request.
        """

        self.ruling = cast(
            PolicyRuling,
            self.run_hook(
                'ROUTE',
                session=self.session,
                guest_request=self.gr,
                pools=self.pools
            )
        )

    @step
    def evaluate_ruling(self) -> None:
        """
        Evaluate routing policies ruling, and make changes according to its content.

        This includes picking one of the selected pools, or cancelling the request entirely.
        """

        assert self.ruling

        if self.ruling.cancel:
            self.handle_success('routing-cancelled')

            self.update_guest_state(
                GuestState.ERROR,
                current_state=GuestState.ROUTING
            )

            if self.result:
                return

            self.result = self.handle_success('finished-task')

            return

        # If no suitable pools found
        if not self.ruling.allowed_pools:
            self.result = RESCHEDULE

            return

        # At this point, all pools are equally worthy: we may very well use the first one.
        self.new_pool = self.ruling.allowed_pools[0]

    @step
    def switch_to_provisioning(self) -> None:
        """
        Move the guest request to :py:attr:`GuestRequest.PROVISIONING` state.
        """

        assert self.guestname
        assert self.gr
        assert self.new_pool

        # If we fail to move guest to PROVISIONING state, it's likely another instance of this task changed
        # guest's state instead of us, which means we should throw everything away because our decisions no
        # longer matter. But we cannot simply mark the job as done - what if we failed to change the state because
        # of network issue? We need to try the task again, and, should the above be correct, we wouldn't find
        # the guest in ROUTING state, and we'd quit right away.

        self.update_guest_state_and_request_task(
            GuestState.PROVISIONING,
            acquire_guest_request,
            self.guestname,
            self.new_pool.poolname,
            current_state=GuestState.ROUTING,
            set_values={
                'poolname': self.new_pool.poolname
            },
            poolname=self.new_pool.poolname
        )

    @step
    def exit(self) -> None:
        """
        Wrap up the routing process by updating metrics & final logging.
        """

        # If new pool has been chosen, log failover.
        if self.current_poolname and self.new_pool and self.new_pool.poolname != self.current_poolname:
            self.logger.warning(f'failover: switched {self.current_poolname} => {self.new_pool.poolname}')

            metrics.ProvisioningMetrics.inc_failover(self.current_poolname, self.new_pool.poolname)

        self.result = self.handle_success('finished-task')

    @staticmethod
    def route_guest_request(
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
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
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return Workspace(logger, session, cancel, guestname=guestname, task='route-guest-request') \
            .entry() \
            .load_pools() \
            .query_policies() \
            .evaluate_ruling() \
            .switch_to_provisioning() \
            .exit() \
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
        doer_args=(guestname,),
        session_isolation=True
    )
