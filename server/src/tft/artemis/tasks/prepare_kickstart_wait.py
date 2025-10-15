# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Wait for kickstart installation to complete.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import enum
import os
import tempfile
from typing import cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import DB, GuestLog, GuestLogContentType, GuestLogState, SafeQuery
from ..drivers import (
    GuestLogBlob,
    copy_from_remote,
    ping_shell_remote,
    run_remote,
)
from ..guest import GuestState
from ..knobs import Knob
from . import (
    _ROOT_LOGGER,
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
    default=300,
)

KNOB_PREPARE_KICKSTART_WAIT_RETRY_DELAY: Knob[int] = Knob(
    'actor.kickstart-wait.retry-delay',
    'Delay between kickstart installation completion checks.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_KICKSTART_WAIT_RETRY_DELAY',
    cast_from_str=int,
    default=120,
)


class AnacondaLogType(enum.Enum):
    """
    Anaconda generates a number of logs: anaconda steps, external program calls, storage and DNF package installation.
    """

    ANACONDA = 'anaconda'
    STORAGE = 'storage'
    PROGRAM = 'program'
    PACKAGING = 'packaging'


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
            self.load_gr_pool()
            self.load_master_ssh_key()

            if self.result:
                return

            assert self.gr
            assert self.master_key
            assert self.pool

            # Load the SSH timeout value.
            r_ssh_timeout = KNOB_PREPARE_KICKSTART_SSH_TIMEOUT.get_value(
                session=self.session, entityname=self.pool.poolname
            )

            if r_ssh_timeout.is_error:
                return self._error(r_ssh_timeout, 'failed to obtain SSH timeout value')

            ssh_timeout = r_ssh_timeout.unwrap()

            def _pull_log(log_type: AnacondaLogType, finished: bool = False) -> None:
                """
                Pull the specified log from the system.
                """

                assert self.gr
                assert self.master_key
                assert self.pool

                # After a successful installation, the logs are preserved
                log_src_path = f'/var/log/anaconda/{log_type.value}.log' if finished else f'/tmp/{log_type.value}.log'

                with tempfile.TemporaryDirectory() as tmpdir:
                    dst = os.path.join(tmpdir, f'{log_type.value}.log')

                    copy_from_remote(
                        self.logger,
                        self.gr,
                        log_src_path,
                        dst,
                        key=self.master_key,
                        ssh_options=self.pool.ssh_options,
                        ssh_timeout=ssh_timeout,
                        poolname=self.pool.poolname,
                        commandname='prepare-kickstart-wait.fetch-log',
                    )

                    with open(dst) as f:
                        blob = GuestLogBlob.from_content(f.read())
                        logname = f'{log_type.value}.log:dump'

                        r_guest_log = (
                            SafeQuery.from_session(self.session, GuestLog)
                            .filter(GuestLog.guestname == self.gr.guestname)
                            .filter(GuestLog.logname == logname)
                            .filter(GuestLog.contenttype == GuestLogContentType.BLOB)
                            .one_or_none()
                        )

                        if r_guest_log.is_error:
                            return self._error(r_guest_log, f'failed to load the log {logname}', no_effect=True)

                        log = r_guest_log.unwrap()

                        if log is not None:
                            r_store_log = log.update(self.logger, self.session, GuestLogState.COMPLETE)

                            if r_store_log.is_error:
                                return self._error(r_store_log, f'failed to update the log {logname}', no_effect=True)
                        else:
                            r_create_log = GuestLog.create(
                                self.logger,
                                self.session,
                                self.gr.guestname,
                                logname,
                                GuestLogContentType.BLOB,
                                GuestLogState.COMPLETE,
                            )

                            if r_create_log.is_error:
                                return self._error(r_create_log, f'failed to create the log {logname}', no_effect=True)

                            log = r_create_log.unwrap()

                        r_store_blob = blob.save(self.logger, self.session, log, overwrite=True)

                        if r_store_blob.is_error:
                            return self._error(
                                r_store_blob, f'failed to store the blob for the log {logname}', no_effect=True
                            )

            def _pull_logs(finished: bool = False) -> Result[None, Failure]:
                try:
                    for log_type in AnacondaLogType:
                        _pull_log(log_type, finished)
                except Exception as exc:
                    return Error(Failure.from_exc('failed getting logs from the guest', exc))

                self._guest_request_event('installation-logs-downloaded')

                return Ok(None)

            # Check the guest is accessible
            r_ping = ping_shell_remote(
                self.logger,
                self.gr,
                key=self.master_key,
                ssh_timeout=ssh_timeout,
                ssh_options=self.pool.ssh_options,
                poolname=self.pool.poolname,
                commandname='prepare-verify-ssh.shell-ping',
                cause_extractor=self.pool.extract_error_cause_from_cli,
            )

            if r_ping.is_error:
                return self._fail(
                    Failure.from_failure('failed to connect to the guest', r_ping.unwrap_error()),
                    'failed to connect to the guest',
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
                commandname='prepare-kickstart-wait.check-inprogress',
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
                    commandname='prepare-kickstart-wait.check-error',
                )

                if not r_iserror.is_error:
                    # End the provisioning here as there's nothing else to do
                    r_logs = _pull_logs(finished=False)

                    if r_logs.is_error:
                        self._fail(r_logs.unwrap_error(), 'failed to fetch and store kickstart logs', no_effect=True)

                    return self._fail(
                        Failure('the installation terminated with an error', recoverable=False),
                        'the installation terminated with an error',
                    )

                self._progress('install-inprogress')

                r_delay = KNOB_PREPARE_KICKSTART_WAIT_RETRY_DELAY.get_value(
                    session=self.session, entityname=self.pool.poolname
                )

                if r_delay.is_error:
                    return self._error(r_delay, 'failed to load task retry delay')

                self.request_task(prepare_kickstart_wait, self.guestname, delay=r_delay.unwrap())

                return

            # A sanity check to verify the kickstart installation did happen.
            r_install = run_remote(
                self.logger,
                self.gr,
                ['/bin/ls', '/.ksinstall'],
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart-wait.check-inprogress',
            )

            if r_install.is_error:
                return self._error(r_install, 'failed to verify the kickstart installation was performed')

            # Pull logs once we are done
            r_logs = _pull_logs(finished=True)

            if r_logs.is_error:
                self._fail(r_logs.unwrap_error(), 'failed to fetch and store kickstart logs', no_effect=True)

            # Dispatch next task.
            self.request_task(prepare_finalize_pre_connect, self.guestname)

    @classmethod
    def create(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> 'Workspace':
        return cls(logger, session, db=db, guestname=guestname, task=TASK_NAME)

    @classmethod
    def prepare_kickstart_wait(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.ERROR))
def prepare_kickstart_wait(guestname: str) -> None:
    """
    Wait for the kickstart installation to finish and verify the guest is accessible.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.prepare_kickstart_wait),
        logger=get_guest_logger(TASK_NAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
