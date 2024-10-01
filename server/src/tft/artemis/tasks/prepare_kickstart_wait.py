# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Wait for kickstart installation to complete.

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
from ..drivers import ping_shell_remote, run_remote
from ..guest import GuestState
from ..knobs import Knob
from . import _ROOT_LOGGER, SUCCESS, DoerReturnType, DoerType, ProvisioningTailHandler, TaskCall
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core
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

    ssh_timeout: int

    @step
    def load_gr_and_pool(self) -> None:
        """
        Load necessary elements.
        """

        assert self.guestname

        self.load_guest_request(self.guestname, state=GuestState.PREPARING)
        self.mark_note_poolname()
        self.load_gr_pool()
        self.load_master_ssh_key()

    @step
    def load_ssh_timeout(self) -> None:
        """
        Load the SSH timeout value.
        """

        assert self.pool

        r = KNOB_PREPARE_KICKSTART_SSH_TIMEOUT.get_value(session=self.session, entityname=self.pool.poolname)

        if r.is_error:
            return self._error(r, 'failed to obtain SSH timeout value')

        self.ssh_timeout = r.unwrap()

    @step
    def check_accessible(self) -> None:
        """
        Verify the guest can be accessed.
        """

        assert self.gr
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        r = ping_shell_remote(
            self.logger,
            self.gr,
            key=self.master_key,
            ssh_timeout=self.ssh_timeout,
            ssh_options=self.pool.ssh_options,
            poolname=self.pool.poolname,
            commandname='prepare-verify-ssh.shell-ping',
            cause_extractor=self.pool.cli_error_cause_extractor
        )

        if r.is_error:
            return self._fail(
                Failure.from_failure('failed to connect to the guest', r.unwrap_error()),
                'failed to connect to the guest'
            )

    @step
    def check_inprogress(self) -> None:
        """
        Check whether the installation is still ongoing.
        """

        assert self.gr
        assert self.guestname
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        r = run_remote(
            self.logger,
            self.gr,
            ['/bin/ls', '/.ksinprogress'],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart-wait.check-inprogress'
        )

        if not r.is_error:
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

    @step
    def check_error(self) -> None:
        """
        Check the installation did not error out.
        """

        assert self.gr
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        r = run_remote(
            self.logger,
            self.gr,
            ['/bin/ls', '/.kserror'],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart-wait.check-inprogress'
        )

        if not r.is_error:
            # End the provisioning here as there's nothing else to do
            self._error(r, 'the installation terminated with an error')

            ProvisioningTailHandler(GuestState.PREPARING, GuestState.ERROR).handle_tail(
                self.logger,
                self.db,
                self.session,
                TaskCall(
                    actor=prepare_kickstart_wait,
                    args=(self.guestname,),
                    arg_names=('guestname',)
                )
            )

            return

    @step
    def check_complete(self) -> None:
        """
        A sanity check to verify the kickstart installation did happen.
        """

        assert self.gr
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        r = run_remote(
            self.logger,
            self.gr,
            ['/bin/ls', '/.ksinstall'],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart-wait.check-inprogress'
        )

        if r.is_error:
            self._error(r, 'failed to verify the kickstart installation was performed')

    @step
    def dispatch_finalize(self) -> None:
        """
        Dispatch next task.
        """

        assert self.guestname

        from .prepare_finalize_pre_connect import prepare_finalize_pre_connect

        self.request_task(
            prepare_finalize_pre_connect,
            self.guestname
        )

    def run(self) -> 'Workspace':
        with self.transaction():
            return self.load_gr_and_pool() \
                .load_ssh_timeout() \
                .check_accessible() \
                .check_inprogress() \
                .check_error() \
                .check_complete() \
                .dispatch_finalize()

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
