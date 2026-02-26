# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Verify guest is reachable over SSH.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session
from returns.pipeline import is_successful

from .. import Failure
from ..db import DB
from ..drivers import ping_shell_remote
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
from .prepare_finalize_pre_connect import prepare_finalize_pre_connect
from .prepare_kickstart import prepare_kickstart

KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'actor.verify-ssh.connect-timeout',
    'Prepare stage SSH timeout.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15,
)


class Workspace(_Workspace):
    """
    Workspace for SSH verification task.
    """

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.load_gr_pool()
            self.load_master_ssh_key()

            if self.result:
                return None

            assert self.gr
            assert self.pool
            assert self.master_key

            r = KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value(session=self.session, entityname=self.pool.poolname)

            if r.is_error:
                return self._error(r, 'failed to obtain SSH timeout value')

            ssh_connect_timeout = r.unwrap()

            r_ping = ping_shell_remote(
                self.logger,
                self.gr,
                key=self.master_key,
                ssh_timeout=ssh_connect_timeout,
                ssh_options=self.pool.ssh_options,
                guestname=self.guestname,
                poolname=self.pool.poolname,
                commandname='prepare-verify-ssh.shell-ping',
                cause_extractor=self.pool.cli_error_cause_extractor,
            )

            if r_ping.is_error:
                # We do not want the generic "failed CLI" error here, to make SSH verification issues stand out more.
                return self._fail(
                    Failure.from_failure('failed to verify SSH', r_ping.unwrap_error()), 'failed to verify SSH'
                )

            next_task = prepare_finalize_pre_connect

            # If we need to perform kickstart setup, divert into this task instead
            r_capabilities = self.pool.capabilities()

            if not is_successful(r_capabilities):
                return self._error_v2(r_capabilities, 'could not get pool capabilities')

            if self.gr.environment.has_ks_specification and not r_capabilities.unwrap().supports_native_kickstart:
                next_task = prepare_kickstart

            self.request_task(next_task, self.guestname)

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

        return cls(logger, session, db=db, guestname=guestname, task='prepare-verify-ssh')

    @classmethod
    def prepare_verify_ssh(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        """
        Verify guest's SSH connection is up and ready.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.SHELF_LOOKUP))
def prepare_verify_ssh(guestname: str) -> None:
    """
    Verify guest's SSH connection is up and ready.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.prepare_verify_ssh),
        logger=get_guest_logger('prepare-verify-ssh', _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
