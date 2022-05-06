# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Verify guest is reachable over SSH.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import threading
from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from .. import Failure
from ..db import DB
from ..drivers import ping_shell_remote
from ..guest import GuestState
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core

KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'actor.verify-ssh.connect-timeout',
    'Prepare stage SSH timeout.',
    per_pool=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15
)


class Workspace(_Workspace):
    """
    Workspace for SSH verification task.
    """

    # current_pool_data: PoolData
    # provisioning_progress: ProvisioningProgress
    # new_guest_data: Dict[str, Union[str, int, None, datetime.datetime, GuestState]]

    ssh_connect_timeout: int

    @step
    def entry(self) -> None:
        """
        Begin the update process with nice logging and loading request data and pool.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.PREPARING)
        self.load_gr_pool()

    @step
    def load_ssh_timeout(self) -> None:
        r = KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value(session=self.session, pool=self.pool)

        if r.is_error:
            self.result = self.handle_error(r, 'failed to obtain SSH timeout value')
            return

        self.ssh_connect_timeout = r.unwrap()

    @step
    def ping(self) -> None:
        assert self.gr
        assert self.pool
        assert self.master_key

        r_ping = ping_shell_remote(
            self.logger,
            self.gr,
            key=self.master_key,
            ssh_timeout=self.ssh_connect_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-verify-ssh.shell-ping',
            cause_extractor=self.pool.cli_error_cause_extractor
        )

        if r_ping.is_error:
            # We do not want the generic "failed CLI" error here, to make SSH verification issues stand out more.
            self.result = self.handle_failure(
                Failure.from_failure('failed to verify SSH', r_ping.unwrap_error()),
                'failed to verify SSH'
            )

    @step
    def exit(self) -> None:
        """
        Wrap up the routing process by updating metrics & final logging.
        """

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

        return cls(logger, session, cancel, db=db, guestname=guestname, task='prepare-verify-ssh')

    @classmethod
    def prepare_verify_ssh(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Verify guest's SSH connection is up and ready.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel, guestname) \
            .entry() \
            .mark_note_poolname() \
            .load_ssh_timeout() \
            .load_master_ssh_key() \
            .ping() \
            .exit() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.ROUTING))
def prepare_verify_ssh(guestname: str) -> None:
    """
    Verify guest's SSH connection is up and ready.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.prepare_verify_ssh),
        logger=get_guest_logger('prepare-verify-ssh', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
