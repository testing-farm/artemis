# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import GuestRequestWorkspace as _Workspace
from . import ProvisioningTailHandler, get_guest_logger, step, task, task_core

POST_INSTALL_SCRIPT_REMOTE_FILEPATH = '/tmp/artemis-post-install-script.sh'


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    @step
    def run(self) -> None:
        # Avoid circular imports
        from ..drivers import copy_to_remote, create_tempfile, run_remote
        from .prepare_finalize_post_connect import prepare_finalize_post_connect
        from .prepare_verify_ssh import KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT

        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.mark_note_poolname()
            self.load_gr_pool()
            self.load_master_ssh_key()

            assert self.gr
            assert self.pool
            assert self.master_key

            r_ssh_timeout = KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value(
                session=self.session,
                entityname=self.pool.poolname
            )

            if r_ssh_timeout.is_error:
                return self._error(r_ssh_timeout, 'failed to obtain ssh timeout value')

            with create_tempfile(file_contents=self.gr.post_install_script) as post_install_filepath:
                r_upload = copy_to_remote(
                    self.logger,
                    self.gr,
                    post_install_filepath,
                    POST_INSTALL_SCRIPT_REMOTE_FILEPATH,
                    key=self.master_key,
                    ssh_timeout=r_ssh_timeout.unwrap(),
                    ssh_options=self.pool.ssh_options,
                    poolname=self.pool.poolname,
                    commandname='prepare-post-install-script.copy-to-remote',
                    cause_extractor=self.pool.cli_error_cause_extractor
                )

            if r_upload.is_error:
                return self._error(r_upload, 'failed to upload post-install script')

            r_ssh = run_remote(
                self.logger,
                self.gr,
                ['/bin/sh', POST_INSTALL_SCRIPT_REMOTE_FILEPATH],
                key=self.master_key,
                ssh_timeout=r_ssh_timeout.unwrap(),
                poolname=self.pool.poolname,
                commandname='prepare-post-install-script.execute',
                cause_extractor=self.pool.cli_error_cause_extractor
            )

            if r_ssh.is_error:
                return self._error(r_ssh, 'failed to execute post-install script successfully')

            self.dispatch_task(prepare_finalize_post_connect, self.guestname)

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

        return cls(logger, session, db, guestname, task='prepare-finalize-pre-connect')

    @classmethod
    def prepare_post_install_script(
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


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.SHELF_LOOKUP))
def prepare_post_install_script(guestname: str) -> None:
    task_core(
        cast(DoerType, Workspace.prepare_post_install_script),
        logger=get_guest_logger('prepare-post-install-script', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
