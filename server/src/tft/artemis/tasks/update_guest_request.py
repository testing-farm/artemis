# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
from typing import Dict, Union, cast

import gluetool.log
import sqlalchemy.orm.session

from .. import Failure
from ..db import DB
from ..drivers import PoolData, ProvisioningProgress, ProvisioningState
from ..guest import GuestState
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    GuestRequestWorkspace as _Workspace,
    ProvisioningTailHandler,
    TaskCall,
    get_guest_logger,
    step,
    task,
    task_core,
)


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    @step
    def run(self) -> None:
        """
        Foo.
        """

        skip_prepare_verify_ssh: bool

        current_pool_data: PoolData
        provisioning_progress: ProvisioningProgress
        new_guest_data: Dict[str, Union[str, int, None, datetime.datetime, GuestState]]

        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PROMISED)
            self.load_gr_pool()
            self.test_pool_enabled()

            if self.result:
                return

            assert self.gr
            assert self.pool

            if self.is_pool_enabled:
                skip_prepare_verify_ssh = self.gr.skip_prepare_verify_ssh
                current_pool_data = self.pool.pool_data_class.unserialize(self.gr)

                r_progress = self.pool.update_guest(self.logger, self.session, self.gr)

                if r_progress.is_error:
                    return self._error(r_progress, 'failed to update guest')

                provisioning_progress = r_progress.unwrap()

                new_guest_data = {
                    'pool_data': provisioning_progress.pool_data.serialize()
                }

                if provisioning_progress.ssh_info is not None:
                    new_guest_data.update({
                        'ssh_username': provisioning_progress.ssh_info.username,
                        'ssh_port': provisioning_progress.ssh_info.port
                    })

                if provisioning_progress.address is not None:
                    new_guest_data['address'] = provisioning_progress.address

            else:
                provisioning_progress = ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=self.pool.pool_data_class.unserialize(self.gr),
                    pool_failures=[Failure('pool is disabled')]
                )

            # not returning here - pool was able to recover and proceed
            for failure in provisioning_progress.pool_failures:
                self._fail(failure, 'pool encountered failure during update', no_effect=True)

            if provisioning_progress.state == ProvisioningState.PENDING:
                self._progress('pending')

                self.update_guest_state_and_request_task(
                    GuestState.PROMISED,
                    update_guest_request,
                    self.guestname,
                    current_state=GuestState.PROMISED,
                    set_values=new_guest_data,
                    current_pool_data=current_pool_data.serialize(),
                    delay=provisioning_progress.delay_update
                )

            elif provisioning_progress.state == ProvisioningState.CANCEL:
                assert self.db

                self._progress('canceled-by-pool')

                if not ProvisioningTailHandler(GuestState.PROMISED, GuestState.ROUTING).handle_tail(
                    self.logger,
                    self.db,
                    self.session,
                    TaskCall(
                        actor=update_guest_request,
                        args=(self.guestname,),
                        arg_names=('guestname',)
                    )
                ):
                    self._reschedule()

            elif provisioning_progress.state == ProvisioningState.COMPLETE:
                self._progress('address-assigned', address=provisioning_progress.address)

                # Running verify-ssh step is optional - user might have requested us to skip the step.
                if skip_prepare_verify_ssh:
                    from .prepare_finalize_pre_connect import prepare_finalize_pre_connect

                    self.update_guest_state_and_request_task(
                        GuestState.PREPARING,
                        prepare_finalize_pre_connect,
                        self.guestname,
                        current_state=GuestState.PROMISED,
                        set_values=new_guest_data,
                        current_pool_data=current_pool_data.serialize()
                    )

                else:
                    from . import KNOB_DISPATCH_PREPARE_DELAY
                    from .prepare_verify_ssh import prepare_verify_ssh

                    self.update_guest_state_and_request_task(
                        GuestState.PREPARING,
                        prepare_verify_ssh,
                        self.guestname,
                        current_state=GuestState.PROMISED,
                        set_values=new_guest_data,
                        current_pool_data=current_pool_data.serialize(),
                        delay=KNOB_DISPATCH_PREPARE_DELAY.value
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

        return cls(logger, session, db, guestname, task='update-guest-request')

    @classmethod
    def update_guest_request(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

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


@task(tail_handler=ProvisioningTailHandler(GuestState.PROMISED, GuestState.SHELF_LOOKUP))
def update_guest_request(guestname: str) -> None:
    """
    Update guest request provisioning progress.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.update_guest_request),
        logger=get_guest_logger('update-guest-request', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
