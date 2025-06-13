# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import cast

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
    GuestFieldStates,
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

    TASKNAME = 'acquire-guest-request'

    @step
    def run(self) -> None:
        with self.transaction():
            self.load_guest_request(self.guestname, state=GuestState.PROVISIONING)
            self.load_gr_pool()
            self.test_pool_enabled()

            if self.result:
                return

            assert self.gr
            assert self.pool
            assert self.gr.poolname

            if self.is_pool_enabled:
                skip_prepare_verify_ssh = self.gr.skip_prepare_verify_ssh

                result = self.pool.acquire_guest(self.logger, self.session, self.gr)

                if result.is_error:
                    return self._error(result, 'failed to provision')

                provisioning_progress = result.unwrap()

                # not returning here - pool was able to recover and proceed
                for failure in provisioning_progress.pool_failures:
                    self._fail(failure, 'pool encountered failure during acquisition', no_effect=True)

                # We have a guest, we can move the guest record to the next state. The guest may be unfinished,
                # in that case we should schedule a task for driver's update_guest method. Otherwise, we must
                # save guest's address. In both cases, we must be sure nobody else did any changes before us.
                new_guest_values: GuestFieldStates = {
                    '_pool_data': self.gr.pool_data.update(self.gr.poolname, provisioning_progress.pool_data),
                }

                if provisioning_progress.ssh_info is not None:
                    new_guest_values.update(
                        {
                            'ssh_username': provisioning_progress.ssh_info.username,
                            'ssh_port': provisioning_progress.ssh_info.port,
                        }
                    )

            else:
                provisioning_progress = ProvisioningProgress(
                    state=ProvisioningState.CANCEL, pool_data=PoolData(), pool_failures=[Failure('pool is disabled')]
                )

            if provisioning_progress.state == ProvisioningState.PENDING:
                self.allocated_resources(provisioning_progress.pool_data)

                from .update_guest_request import update_guest_request

                self.update_guest_state_and_request_task(
                    GuestState.PROMISED,
                    update_guest_request,
                    self.guestname,
                    current_state=GuestState.PROVISIONING,
                    set_values=new_guest_values,
                    pool=self.gr.poolname,
                    pool_data=self.gr.pool_data.update(self.gr.poolname, provisioning_progress.pool_data),
                    delay=provisioning_progress.delay_update,
                )

                if self.result:
                    # TODO: we failed to save pool data & request follow-up task, must retry - and that will
                    # cause acquire-guest-task to allocate new resources while those we have *now* would not
                    # be tracked.
                    return

                self._progress('pool-resources-requested', pool_data=provisioning_progress.pool_data.serialize())

            elif provisioning_progress.state == ProvisioningState.CANCEL:
                self._progress('provisioning cancelled')

                # This may fail, and re-running task should be correct - probably nothing was allocated.
                r_release = self.pool.release_guest(self.logger, self.session, self.gr)

                if r_release.is_error:
                    return self._error(r_release, 'failed to release after cancel')

                if not ProvisioningTailHandler(GuestState.PROVISIONING, GuestState.SHELF_LOOKUP).handle_tail(
                    self.logger,
                    self.db,
                    self.session,
                    TaskCall(
                        actor=acquire_guest_request,
                        args=(self.gr.guestname, self.pool.poolname),
                        arg_names=('guestname', 'poolname'),
                    ),
                ):
                    self._reschedule()

            else:
                self.allocated_resources(provisioning_progress.pool_data)

                assert provisioning_progress.address

                self._progress('address-assigned', address=provisioning_progress.address)

                new_guest_values['address'] = provisioning_progress.address

                # Running verify-ssh step is optional - user might have requested us to skip the step.
                if skip_prepare_verify_ssh:
                    from .prepare_finalize_pre_connect import prepare_finalize_pre_connect

                    self.update_guest_state_and_request_task(
                        GuestState.PREPARING,
                        prepare_finalize_pre_connect,
                        self.guestname,
                        current_state=GuestState.PROVISIONING,
                        address=provisioning_progress.address,
                        set_values=new_guest_values,
                        pool=self.gr.poolname,
                        pool_data=self.gr.pool_data.update(self.gr.poolname, provisioning_progress.pool_data),
                    )

                else:
                    from . import KNOB_DISPATCH_PREPARE_DELAY
                    from .prepare_verify_ssh import prepare_verify_ssh

                    self.update_guest_state_and_request_task(
                        GuestState.PREPARING,
                        prepare_verify_ssh,
                        self.guestname,
                        current_state=GuestState.PROVISIONING,
                        address=provisioning_progress.address,
                        set_values=new_guest_values,
                        pool=self.gr.poolname,
                        current_pool_data=self.gr.pool_data.update(self.gr.poolname, provisioning_progress.pool_data),
                        delay=KNOB_DISPATCH_PREPARE_DELAY.value,
                    )

                if self.result:
                    # TODO: we failed to save pool data & request follow-up task, must retry - and that will
                    # cause acquire-guest-task to allocate new resources while those we have *now* would not
                    # be tracked.
                    return

                self._progress('successfully acquired')

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
    def acquire_guest_request(
        cls, logger: gluetool.log.ContextAdapter, db: DB, session: sqlalchemy.orm.session.Session, guestname: str
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname).begin().run().complete().final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PROVISIONING, GuestState.SHELF_LOOKUP))
def acquire_guest_request(guestname: str) -> None:
    task_core(
        cast(DoerType, Workspace.acquire_guest_request),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,),
    )
