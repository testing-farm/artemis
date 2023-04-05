# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Run watchdog task testing a connection to a guest while present on a shelf.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import ping_shell_remote
from ..guest import GuestState
from ..knobs import Knob
from ..metrics import ShelfMetrics
from . import _ROOT_LOGGER, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core

KNOB_SHELVED_GUEST_WATCHDOG_DISPATCH_PERIOD: Knob[int] = Knob(
    'actor.shelved-guest-watchdog.dispatch.delay',
    'A delay, in seconds, between watchdog runs.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_SHELVED_GUEST_WATCHDOG_DISPATCH_PERIOD',
    cast_from_str=int,
    default=600
)

KNOB_SHELVED_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'actor.shelved-guest-watchdog.connect-timeout',
    'Shelved guest watchdog SSH connection timeout.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_SHELVED_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15
)


class Workspace(_Workspace):
    """
    Workspace for shelved guest watchdog.
    """

    TASKNAME = 'shelved-guest-watchdog'

    guest_reachable: bool
    ssh_connect_timeout: int

    @step
    def entry(self) -> None:
        """
        Begin the update process with nice logging and loading request data and pool.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.SHELVED)
        self.load_gr_pool()

    @step
    def end_if_ssh_disabled(self) -> None:
        """
        End watchdog if SSH ping was disabled by the user.
        """

        assert self.gr

        if self.gr.skip_prepare_verify_ssh is True:
            self.logger.warning('SSH ping is disabled, watchdog will not continue')
            self.result = self.handle_success('finished-task')

    @step
    def load_ssh_timeout(self) -> None:
        """
        Load SSH timeout
        """

        assert self.pool

        r = KNOB_SHELVED_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT.get_value(session=self.session, poolname=self.pool.poolname)

        if r.is_error:
            self.result = self.handle_error(r, 'failed to obtain SSH timeout value')
            return

        self.ssh_connect_timeout = r.unwrap()

    @step
    def run_watchdog(self) -> None:
        """
        Try to "ping" the guest to verify it is still accessible
        """

        assert self.gr
        assert self.pool
        assert self.master_key

        r_ping = ping_shell_remote(
            self.logger,
            self.gr,
            key=self.master_key,
            ssh_timeout=self.ssh_connect_timeout,
            ssh_options=self.pool.ssh_options,
            poolname=self.pool.poolname,
            commandname=f'{Workspace.TASKNAME}.shell-ping',
            cause_extractor=self.pool.cli_error_cause_extractor
        )

        self.guest_ping_result = r_ping

        if r_ping.is_error:
            self.logger.error('ping failed, guest is inaccessible')

    @step
    def dispatch_release(self) -> None:
        """
        If ping failed, schedule release of the affected guest
        """

        if self.guest_ping_result.is_error:
            from .release_guest_request import release_guest_request

            assert self.gr

            ShelfMetrics.inc_dead(self.gr.shelfname)

            self.update_guest_state_and_request_task(
                GuestState.CONDEMNED,
                release_guest_request,
                self.guestname,
                current_state=GuestState.SHELVED
            )

            ShelfMetrics.inc_removals(self.gr.shelfname)

            self.result = self.handle_error(self.guest_ping_result, 'ping failed')

    @step
    def schedule_followup(self) -> None:
        """
        Schedule followup for the watchdog
        """

        assert self.guestname

        self.dispatch_task(
            shelved_guest_watchdog,
            self.guestname,
            delay=KNOB_SHELVED_GUEST_WATCHDOG_DISPATCH_PERIOD.value
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
        :returns: newly created workspace.
        """

        return cls(logger, session, cancel, guestname=guestname, task=cls.TASKNAME)

    @classmethod
    def shelved_guest_watchdog(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Invoke watchdog task to verify a shelved guest is still reachable and a viable candidate to serve another GR.

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
            .end_if_ssh_disabled() \
            .load_ssh_timeout() \
            .run_watchdog() \
            .dispatch_release() \
            .schedule_followup() \
            .exit() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.READY, GuestState.ERROR))
def shelved_guest_watchdog(guestname: str) -> None:
    """
    Invoke driver's watchdog task for a given guest request.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.shelved_guest_watchdog),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
