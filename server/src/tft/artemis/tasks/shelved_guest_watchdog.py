# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Run watchdog task testing a connection to a guest while present on a shelf.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import ping_shell_remote
from ..guest import GuestState
from ..knobs import Knob
from ..metrics import ShelfMetrics
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import GuestRequestWorkspace as _Workspace
from . import ProvisioningTailHandler, get_guest_logger, step, task, task_core

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
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.SHELVED)

            if self.result:
                return

            assert self.gr

            if self.gr.skip_prepare_verify_ssh is True:
                return self._progress('shelved-guest-watchdog-cancelled')

            self.load_gr_pool()
            self.load_master_ssh_key()

            if self.result:
                return

            assert self.pool
            assert self.master_key

            r_timeout = KNOB_SHELVED_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT.get_value(
                session=self.session,
                entityname=self.pool.poolname
            )

            if r_timeout.is_error:
                return self._error(r_timeout, 'failed to obtain SSH timeout value')

            r_ping = ping_shell_remote(
                self.logger,
                self.gr,
                key=self.master_key,
                ssh_timeout=r_timeout.unwrap(),
                ssh_options=self.pool.ssh_options,
                poolname=self.pool.poolname,
                commandname=f'{Workspace.TASKNAME}.shell-ping',
                cause_extractor=self.pool.cli_error_cause_extractor
            )

            if r_ping.is_error:
                from .release_guest_request import release_guest_request

                self._error(r_ping, 'ping failed, guest is inaccessible', no_effect=True)

                ShelfMetrics.inc_dead(self.gr.shelfname)

                self.update_guest_state_and_request_task(
                    GuestState.CONDEMNED,
                    release_guest_request,
                    self.guestname,
                    current_state=GuestState.SHELVED
                )

                ShelfMetrics.inc_removals(self.gr.shelfname)

            else:
                self.dispatch_task(
                    shelved_guest_watchdog,
                    self.guestname,
                    delay=KNOB_SHELVED_GUEST_WATCHDOG_DISPATCH_PERIOD.value
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
    def shelved_guest_watchdog(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
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
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname) \
            .begin() \
            .run() \
            .complete() \
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
