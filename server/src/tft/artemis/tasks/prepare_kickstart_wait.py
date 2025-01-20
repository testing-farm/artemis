# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Wait for kickstart installation to complete.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from .. import Failure
from ..db import DB
from ..drivers import ping_shell_remote, run_remote
from ..guest import GuestState
from ..knobs import Knob
from . import (
    _ROOT_LOGGER,
    SUCCESS,
    DoerReturnType,
    DoerType,
    ProvisioningTailHandler,
    Workspace as _Workspace,
    get_guest_logger,
    step,
    task,
    task_core,
)
from .prepare_kickstart import KNOB_PREPARE_KICKSTART_SSH_TIMEOUT

TASK_NAME = 'prepare-kickstart-wait'

KNOB_PREPARE_KICKSTART_WAIT_INITIAL_DELAY: Knob[int] = Knob(
    'actor.kickstart-wait.initial-delay',
    'Delay before attempting to check the kickstart installation completion.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_KICKSTART_WAIT_INITIAL_DELAY',
    cast_from_str=int,
    default=300
)

KNOB_PREPARE_KICKSTART_WAIT_RETRY_DELAY: Knob[int] = Knob(
    'actor.kickstart-wait.retry-delay',
    'Delay between kickstart installation completion checks.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_KICKSTART_WAIT_RETRY_DELAY',
    cast_from_str=int,
    default=120
)


class Workspace(_Workspace):
    """
    Workspace to handle checking the kickstart installation concluded.
    """

    @step
    def run(self) -> None:
        """
        Wrap the steps within a transaction.
        """

        from .prepare_finalize_pre_connect import prepare_finalize_pre_connect

        assert self.guestname

        with self.transaction():
            # Load GR, pool and SSH key
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.mark_note_poolname()
            self.load_gr_pool()
            self.load_master_ssh_key()

            if self.result:
                return

            assert self.gr
            assert self.master_key
            assert self.pool

            # Load the SSH timeout value.
            r_ssh_timeout = KNOB_PREPARE_KICKSTART_SSH_TIMEOUT.get_value(
                session=self.session,
                entityname=self.pool.poolname
            )

            if r_ssh_timeout.is_error:
                return self._error(r_ssh_timeout, 'failed to obtain SSH timeout value')

            ssh_timeout = r_ssh_timeout.unwrap()

            # Check the guest is accessible
            r_ping = ping_shell_remote(
                self.logger,
                self.gr,
                key=self.master_key,
                ssh_timeout=ssh_timeout,
                ssh_options=self.pool.ssh_options,
                poolname=self.pool.poolname,
                commandname='prepare-verify-ssh.shell-ping',
                cause_extractor=self.pool.cli_error_cause_extractor
            )

            if r_ping.is_error:
                return self._fail(
                    Failure.from_failure('failed to connect to the guest', r_ping.unwrap_error()),
                    'failed to connect to the guest'
                )

            # Try to determine whether the installation in progress
            r_inprogress = run_remote(
                self.logger,
                self.gr,
                ['/bin/ls', '/.ksinprogress'],
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart-wait.check-inprogress'
            )

            if not r_inprogress.is_error:
                # Check if the installation had not errored out
                r_iserror = run_remote(
                    self.logger,
                    self.gr,
                    ['/bin/ls', '/.kserror'],
                    key=self.master_key,
                    ssh_options=self.pool.ssh_options,
                    ssh_timeout=ssh_timeout,
                    poolname=self.pool.poolname,
                    commandname='prepare-kickstart-wait.check-error'
                )

                if not r_iserror.is_error:
                    # End the provisioning here as there's nothing else to do
                    return self._fail(
                        Failure.from_failure(
                            'the installation terminated with an error',
                            r_iserror.unwrap_error(),
                            recoverable=False
                        ),
                        'the installation terminated with an error'
                    )

                self._progress('install-inprogress')

                r_delay = KNOB_PREPARE_KICKSTART_WAIT_RETRY_DELAY.get_value(
                    session=self.session,
                    entityname=self.pool.poolname
                )

                if r_delay.is_error:
                    return self._error(r_delay, 'failed to load task retry delay')

                self.request_task(
                    prepare_kickstart_wait,
                    self.guestname,
                    delay=r_delay.unwrap()
                )

                self.result = SUCCESS

            # A sanity check to verify the kickstart installation did happen.
            r_install = run_remote(
                self.logger,
                self.gr,
                ['/bin/ls', '/.ksinstall'],
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart-wait.check-inprogress'
            )

            if r_install.is_error:
                self._error(r_install, 'failed to verify the kickstart installation was performed')

            # Dispatch next task.
            self.request_task(
                prepare_finalize_pre_connect,
                self.guestname
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> 'Workspace':
        return cls(logger, session, db=db, guestname=guestname, task=TASK_NAME)

    @classmethod
    def prepare_kickstart_wait(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        return cls.create(logger, db, session, guestname) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.ERROR))
def prepare_kickstart_wait(guestname: str) -> None:
    """
    Wait for the kickstart installation to finish and verify the guest is accessible.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.prepare_kickstart_wait),
        logger=get_guest_logger(TASK_NAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
