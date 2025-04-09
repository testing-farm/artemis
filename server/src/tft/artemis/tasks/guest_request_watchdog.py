# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Run watchdog tasks for a guest request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import WatchdogState
from ..guest import GuestState
from ..knobs import Knob
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

KNOB_GUEST_REQUEST_WATCHDOG_DISPATCH_DELAY: Knob[int] = Knob(
    'actor.guest-request-watchdog.dispatch.delay',
    """
    A delay, in seconds, between successful provisioning and dispatching of
    guest request watchdog tasks.
    """,
    has_db=True,
    per_entity=True,
    envvar='ARTEMIS_ACTOR_GUEST_REQUEST_WATCHDOG_DISPATCH_DELAY',
    cast_from_str=int,
    default=600
)


KNOB_GUEST_REQUEST_WATCHDOG_DISPATCH_PERIOD: Knob[int] = Knob(
    'actor.guest-request-watchdog.dispatch.period',
    """
    A delay, in seconds, after which new guest request watchdog task is scheduled.
    """,
    has_db=True,
    per_entity=True,
    envvar='ARTEMIS_ACTOR_GUEST_REQUEST_WATCHDOG_DISPATCH_PERIOD',
    cast_from_str=int,
    default=3600
)


class Workspace(_Workspace):
    """
    Workspace for guest request watchdog.
    """

    TASKNAME = 'guest-request-watchdog'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.READY)

            if self.result:
                return

            assert self.gr

            if self.gr.poolname is None or self.gr.pool_data.is_empty(self.gr.poolname):
                return

            self.load_gr_pool()
            self.test_pool_enabled()

            if self.result:
                return

            assert self.pool

            if self.is_pool_enabled:
                r = self.pool.guest_watchdog(self.logger, self.session, self.gr)

                if r.is_error:
                    return self._error(r, 'failed to watchdog guest')

                watchdog_state: WatchdogState = r.unwrap()

                if watchdog_state == WatchdogState.COMPLETE:
                    return

            else:
                self._guest_request_event('pool-disabled')

            # Set the custom watchdog period delay if set by the user
            if self.gr.watchdog_period_delay is not None:
                delay = self.gr.watchdog_period_delay

            else:
                r_delay = KNOB_GUEST_REQUEST_WATCHDOG_DISPATCH_PERIOD.get_value(
                    entityname=self.pool.poolname,
                    session=self.session
                )

                if r_delay.is_error:
                    return self._error(r, 'failed to fetch pool watchdog dispatch period')

                delay = r_delay.unwrap()

            self.dispatch_task(
                guest_request_watchdog,
                self.guestname,
                delay=delay
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        return cls(logger, session, db, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def guest_request_watchdog(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Invoke driver's watchdog task for a given guest request.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        final_result = cls.create(logger, db, session, guestname) \
            .begin() \
            .run() \
            .complete() \
            .final_result

        if final_result.is_error:
            final_result.unwrap_error().fail_guest_request = False

        return final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.READY, GuestState.ERROR))
def guest_request_watchdog(guestname: str) -> None:
    """
    Invoke driver's watchdog task for a given guest request.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.guest_request_watchdog),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
