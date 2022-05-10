# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
import threading
from typing import Dict, Union, cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..drivers import PoolData, ProvisioningProgress, ProvisioningState
from ..guest import GuestState
from . import _ROOT_LOGGER, RESCHEDULE, DoerReturnType, DoerType, ProvisioningTailHandler, TaskCall
from . import Workspace as _Workspace
from . import dispatch_preparing_pre_connect, get_guest_logger, step, task, task_core


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    current_pool_data: PoolData
    provisioning_progress: ProvisioningProgress
    new_guest_data: Dict[str, Union[str, int, None, datetime.datetime, GuestState]]

    @step
    def entry(self) -> None:
        """
        Begin the update process with nice logging and loading request data and pool.
        """

        assert self.guestname

        self.handle_success('entered-task')

        self.load_guest_request(self.guestname, state=GuestState.PROMISED)
        self.load_gr_pool()

    @step
    def save_current_data(self) -> None:
        """
        Save current request properties for later use.
        """

        assert self.gr
        assert self.pool

        self.current_pool_data = self.pool.pool_data_class.unserialize(self.gr)

    @step
    def query_driver(self) -> None:
        """
        Query pool driver for update on provisioning progress.
        """

        assert self.gr
        assert self.pool

        r_progress = self.pool.update_guest(self.logger, self.session, self.gr)

        if r_progress.is_error:
            self.result = self.handle_error(r_progress, 'failed to update guest')
            return

        self.provisioning_progress = r_progress.unwrap()

        self.new_guest_data = {
            'pool_data': self.provisioning_progress.pool_data.serialize()
        }

        if self.provisioning_progress.ssh_info is not None:
            self.new_guest_data.update({
                'ssh_username': self.provisioning_progress.ssh_info.username,
                'ssh_port': self.provisioning_progress.ssh_info.port
            })

        if self.provisioning_progress.address is not None:
            self.new_guest_data['address'] = self.provisioning_progress.address

    @step
    def log_minor_failures(self) -> None:
        """
        Log all non-fatal failures reported by driver.
        """

        # not returning here - pool was able to recover and proceed
        for failure in self.provisioning_progress.pool_failures:
            self.handle_failure(failure, 'pool encountered failure during update')

    @step
    def handle_pending(self) -> None:
        """
        Handle the ongoing provisioning.
        """

        if self.provisioning_progress.state != ProvisioningState.PENDING:
            return

        self.update_guest_state(
            GuestState.PROMISED,
            current_state=GuestState.PROMISED,
            set_values=self.new_guest_data,
            current_pool_data=self.current_pool_data.serialize()
        )

    @step
    def handle_cancel(self) -> None:
        """
        Handle the canceled provisioning, and move the guest request to :py:attr:`GuestRequest.ROUTING` state.
        """

        if self.provisioning_progress.state != ProvisioningState.CANCEL:
            return

        assert self.gr
        assert self.db

        if ProvisioningTailHandler(GuestState.PROMISED, GuestState.ROUTING).handle_tail(
            self.logger,
            self.db,
            self.session,
            TaskCall(
                actor=update_guest_request,
                args=(self.gr.guestname,),
                arg_names=('guestname',)
            )
        ):
            self.result = self.handle_success('finished-task')
            return

        self.result = self.handle_success('finished-task', return_value=RESCHEDULE)

    @step
    def handle_complete(self) -> None:
        """
        Handle the completed provisioning, and move the guest request to :py:attr:`GuestRequest.PREPARING` state.
        """

        if self.provisioning_progress.state != ProvisioningState.COMPLETE:
            return

        self.update_guest_state(
            GuestState.PREPARING,
            current_state=GuestState.PROMISED,
            set_values=self.new_guest_data,
            current_pool_data=self.current_pool_data.serialize()
        )

    @step
    def dispatch_followup(self) -> None:
        """
        Dispatch the provisioning tasks.

        After successfull switch to :py:attr:`GuestState.PROVISIONING`, we are sure to be the first routing task
        that got this far with the routing of this request, therefore we can safely dispatch the provisioning task.
        """

        if self.provisioning_progress.state == ProvisioningState.PENDING:
            self.dispatch_task(update_guest_request, self.guestname, delay=self.provisioning_progress.delay_update)

        elif self.provisioning_progress.state == ProvisioningState.COMPLETE:
            dispatch_preparing_pre_connect(self.logger, self)

        if self.result:
            self.ungrab_guest_request(GuestState.PREPARING, GuestState.PROMISED)

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

        return cls(logger, session, cancel, db=db, guestname=guestname, task='update-guest-request')

    @classmethod
    def update_guest_request(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

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
            .save_current_data() \
            .query_driver() \
            .log_minor_failures() \
            .handle_pending() \
            .handle_cancel() \
            .handle_complete() \
            .dispatch_followup() \
            .exit() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PROMISED, GuestState.ROUTING))
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
