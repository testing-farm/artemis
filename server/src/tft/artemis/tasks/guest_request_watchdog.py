# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Run watchdog tasks for a guest request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import PoolData, WatchdogState
from ..guest import GuestState
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core

KNOB_DISPATCH_GUEST_REQUEST_WATCHDOG_DELAY: Knob[int] = Knob(
    'actor.dispatch-guest-request-watchdog.delay',
    """
    A delay, in seconds, between successful provisioning and dispatching of
    guest request watchdog tasks.
    """,
    has_db=False,
    envvar='ARTEMIS_ACTOR_DISPATCH_GUEST_REQUEST_WATCHDOG_DELAY',
    cast_from_str=int,
    default=600
)


class Workspace(_Workspace):
    """
    Workspace for guest request watchdog.
    """

    TASKNAME = 'guest-request-watchdog'

    watchdog_state: WatchdogState

    @step
    def entry(self) -> None:
        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.READY)

    @step
    def load_pool(self) -> None:
        assert self.gr

        if self.gr.poolname is None or PoolData.is_empty(self.gr):
            return

        self.mark_note_poolname()
        self.load_gr_pool()

    @step
    def call_watchdog(self) -> None:
        assert self.gr
        assert self.pool

        r = self.pool.guest_watchdog(self.logger, self.session, self.gr)

        if r.is_error:
            self.result = self.handle_error(r, 'failed to watchdog guest')
            return

        self.watchdog_state = r.unwrap()

    @step
    def schedule_followup(self) -> None:
        if self.watchdog_state != WatchdogState.CONTINUE:
            return

        self.dispatch_task(
            guest_request_watchdog,
            self.guestname,
            delay=KNOB_DISPATCH_GUEST_REQUEST_WATCHDOG_DELAY.value
        )

    @step
    def exit(self) -> None:
        self.result = self.handle_success('finished-task')

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
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
        :returns: newly created workspace.
        """

        return cls(logger, session, cancel, db=db, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def guest_request_watchdog(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
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
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel, guestname) \
            .entry() \
            .load_pool() \
            .call_watchdog() \
            .schedule_followup() \
            .exit() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.READY, GuestState.ERROR))
def guest_request_watchdog(guestname: str) -> None:
    """
    Invoke driver's watchdog task for a given guest request.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.guest_request_watchdog),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
        session_isolation=True
    )
