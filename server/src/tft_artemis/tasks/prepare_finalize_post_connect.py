# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
from typing import Optional, cast

import gluetool.log
import sqlalchemy.orm.session

from .. import metrics
from ..db import DB
from ..guest import GuestState
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    GuestRequestWorkspace as _Workspace,
    ProvisioningTailHandler,
    get_guest_logger,
    resolve_actor,
    step,
    task,
    task_core,
)
from .guest_request_watchdog import KNOB_GUEST_REQUEST_WATCHDOG_DISPATCH_DELAY, guest_request_watchdog


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    TASKNAME = 'prepare-finalize-post-connect'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.load_gr_pool()

            if self.result:
                return

            assert self.gr
            # assert self.gr.poolname
            assert self.pool

            # Set the custom watchdog dispatch delay if set by the user
            if self.gr.watchdog_dispatch_delay is not None:
                delay = self.gr.watchdog_dispatch_delay

            else:
                r_guest_watchdog_dispatch_delay = KNOB_GUEST_REQUEST_WATCHDOG_DISPATCH_DELAY.get_value(
                    entityname=self.pool.poolname, session=self.session
                )

                if r_guest_watchdog_dispatch_delay.is_error:
                    return self._error(r_guest_watchdog_dispatch_delay, 'failed to fetch pool watchdog dispatch delay')

                delay = r_guest_watchdog_dispatch_delay.unwrap()

            self.update_guest_state_and_request_task(
                GuestState.READY,
                guest_request_watchdog,
                self.guestname,
                current_state=GuestState.PREPARING,
                delay=delay,
            )

            if self.result:
                return

            self._progress('successfully provisioned')

            # calculate provisioning duration time
            provisioning_duration = (datetime.datetime.utcnow() - self.gr.ctime).total_seconds()
            self.logger.info(f'provisioning duration: {provisioning_duration}s')

            # update provisioning duration metrics
            metrics.ProvisioningMetrics.inc_provisioning_durations(provisioning_duration)

            # check if this was a failover and mark it in metrics
            self.load_guest_events(eventname='error')

            if self.result:
                return

            assert self.guest_events is not None

            # If the list of events is empty, it means the provisioning did not run into any error at all.
            # Which means, we are not dealing with a failover.
            if self.guest_events:
                # detect and log successful first failover
                previous_poolname: Optional[str] = None

                for event in self.guest_events:
                    if not event.details:
                        continue

                    if 'failure' not in event.details or 'poolname' not in event.details['failure']:
                        continue

                    previous_poolname = event.details['failure']['poolname']

                    break

                # assert workspace.gr
                # assert workspace.gr.poolname

                poolname = self.gr.poolname

                if previous_poolname and previous_poolname != poolname:
                    self.logger.warning(f'successful failover - from pool {previous_poolname} to {poolname}')
                    metrics.ProvisioningMetrics.inc_failover_success(previous_poolname, poolname)

            # update metrics counter for successfully provisioned guest requests
            metrics.ProvisioningMetrics.inc_success(self.gr.poolname)

            # Dispatch a followup task if specified.
            for taskname, arguments in self.gr.on_ready:
                if self.result:
                    return

                r_actor = resolve_actor(taskname)

                if r_actor.is_error:
                    return self._error(r_actor, 'failed to find task')

                self.request_task(r_actor.unwrap(), self.guestname, *arguments)

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
        :returns: newly created workspace.
        """

        return cls(logger, session, db, guestname, task=Workspace.TASKNAME)

    @classmethod
    def prepare_finalize_post_connect(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.SHELF_LOOKUP))
def prepare_finalize_post_connect(guestname: str) -> None:
    task_core(
        cast(DoerType, Workspace.prepare_finalize_post_connect),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
