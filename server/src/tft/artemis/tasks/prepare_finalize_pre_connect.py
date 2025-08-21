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


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    TASKNAME = 'prepare-finalize-pre-connect'

    @step
    def run(self) -> None:
        from .prepare_finalize_post_connect import prepare_finalize_post_connect
        from .prepare_post_install_script import prepare_post_install_script

        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.load_gr_pool()

            if self.result:
                return

            assert self.gr

            # Running post-install script is optional - the driver might have done it already.
            if self.gr.post_install_script:
                assert self.pool

                r_capabilities = self.pool.capabilities()

                if r_capabilities.is_error:
                    return self._error(r_capabilities, 'failed to fetch pool capabilities')

                if r_capabilities.unwrap().supports_native_post_install_script is False:
                    self.dispatch_task(prepare_post_install_script, self.guestname)

                else:
                    self.dispatch_task(prepare_finalize_post_connect, self.guestname)

            else:
                self.dispatch_task(prepare_finalize_post_connect, self.guestname)

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

        return cls(logger, session, db, guestname, task=Workspace.TASKNAME)

    @classmethod
    def prepare_finalize_pre_connect(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.SHELF_LOOKUP))
def prepare_finalize_pre_connect(guestname: str) -> None:
    task_core(
        cast(DoerType, Workspace.prepare_finalize_pre_connect),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
