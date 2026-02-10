# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

from typing import Any, Optional, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Ok, Result
from returns.pipeline import is_successful

from .. import Failure
from ..db import DB, GuestLog, GuestLogContentType, GuestLogState, SafeQuery
from ..drivers import KNOB_UPDATE_GUEST_REQUEST_LOG_TICK, GuestLogUpdateProgress
from ..guest import GuestState
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    GuestRequestWorkspace as _Workspace,
    LoggingTailHandler,
    get_guest_logger,
    step,
    task,
    task_core,
)


class Workspace(_Workspace):
    """
    Workspace for guest request update task.
    """

    TASKNAME = 'update-guest-log'

    logname: str
    contenttype: GuestLogContentType

    @step
    def run(self) -> None:
        """
        Foo.
        """

        with self.transaction():
            self.load_guest_request(self.guestname)

            if self.result:
                return None

            assert self.gr

            r_guest_log = (
                SafeQuery.from_session(self.session, GuestLog)
                .filter(GuestLog.guestname == self.gr.guestname)
                .filter(GuestLog.logname == self.logname)
                .filter(GuestLog.contenttype == self.contenttype)
                .one_or_none()
            )

            if r_guest_log.is_error:
                return self._error(r_guest_log, 'failed to fetch the log')

            guest_log: Optional[GuestLog] = r_guest_log.unwrap()

            def _log_state_event(resolution: Optional[str] = None, new_state: Optional[GuestLogState] = None) -> None:
                assert guest_log is not None
                assert self.gr is not None

                kwargs: dict[str, Any] = {}

                if resolution is not None:
                    kwargs['resolution'] = resolution

                if new_state is not None:
                    kwargs['new_state'] = new_state.value

                self._guest_request_event(
                    'guest-log-updated',
                    logname=guest_log.logname,
                    contenttype=guest_log.contenttype.value,
                    current_state=guest_log.state.value,
                    **kwargs,
                )

            if guest_log is None:
                return self._fail(Failure('no such guest log'), 'no such guest log')

            if guest_log.state == GuestLogState.ERROR:
                # TODO logs: there is a corner case: log crashes because of flapping API, the guest is reprovisioned
                # to different pool, and here the could succeed - but it's never going to be tried again since it's
                # in ERROR state and there's no way to "reset" the state - possibly do that in API via POST.

                return _log_state_event(resolution='guest-log-in-error-state')

            # TODO logs: it'd be nice to change logs' state to something final
            if self.gr.state in (GuestState.CONDEMNED, GuestState.ERROR):
                _log_state_event(resolution='guest-condemned')

                r_log_update = guest_log.update(
                    self.logger,
                    self.session,
                    state=GuestLogState.COMPLETE,
                    expires=guest_log.expires,
                    url=guest_log.url,
                )

                if r_log_update.is_error:
                    return self._error(r_log_update, 'failed to update the log')

                return None

            if self.gr.pool is None:
                _log_state_event(resolution='guest-not-routed')

                return self._reschedule()

            self.load_gr_pool()

            if self.result:
                return None

            assert self.pool
            assert self.gr.poolname

            r_delay_update = KNOB_UPDATE_GUEST_REQUEST_LOG_TICK.get_value(
                entityname=f'{self.gr.poolname}:{guest_log.logname}/{guest_log.contenttype.value}'
            )

            if r_delay_update.is_error:
                return self._error(r_delay_update, 'failed to load update delay')

            r_capabilities = self.pool.capabilities()

            if not is_successful(r_capabilities):
                return self._error_v2(r_capabilities, 'failed to fetch pool capabilities')

            capabilities = r_capabilities.unwrap()

            if not capabilities.supports_guest_log(self.logname, self.contenttype):
                # If the guest request reached its final states, there's no chance for a pool change in the future,
                # therefore UNSUPPORTED becomes final state as well.
                if self.gr.state in (GuestState.READY, GuestState.CONDEMNED):
                    _log_state_event(resolution='unsupported-and-guest-complete')

                    r_log_update = guest_log.update(
                        self.logger,
                        self.session,
                        state=GuestLogState.UNSUPPORTED,
                        expires=guest_log.expires,
                        url=guest_log.url,
                    )

                    if r_log_update.is_error:
                        return self._error(r_log_update, 'failed to update the log')

                    return None

                r_update: Result[GuestLogUpdateProgress, Failure] = Ok(
                    GuestLogUpdateProgress(state=GuestLogState.UNSUPPORTED)
                )

            elif guest_log.state == GuestLogState.UNSUPPORTED:
                # If the guest request reached its final states, there's no chance for a pool change in the future,
                # therefore UNSUPPORTED becomes final state as well.
                if self.gr.state in (GuestState.READY, GuestState.CONDEMNED):
                    _log_state_event(resolution='unsupported-and-guest-complete')

                    r_log_update = guest_log.update(
                        self.logger,
                        self.session,
                        state=GuestLogState.UNSUPPORTED,
                        expires=guest_log.expires,
                        url=guest_log.url,
                    )

                    if r_log_update.is_error:
                        return self._error(r_log_update, 'failed to update the log')

                    return None

                r_update = self.pool.update_guest_log(self.logger, self.gr, guest_log)

            elif guest_log.state == GuestLogState.COMPLETE:
                if not guest_log.is_expired:
                    _log_state_event(resolution='complete-not-expired')

                    return None

                r_update = self.pool.update_guest_log(self.logger, self.gr, guest_log)

            elif guest_log.state == GuestLogState.PENDING or guest_log.state == GuestLogState.IN_PROGRESS:
                r_update = self.pool.update_guest_log(self.logger, self.gr, guest_log)

            if r_update.is_error:
                return self._error(r_update, 'failed to update the log')

            update_progress = r_update.unwrap()

            _log_state_event(new_state=update_progress.state)

            r_log_update = guest_log.update(
                self.logger,
                self.session,
                state=update_progress.state,
                expires=update_progress.expires,
                url=update_progress.url,
            )

            if r_log_update.is_error:
                return self._error(r_log_update, 'failed to update the log')

            for blob in update_progress.blobs:
                r_blob_update = blob.save(self.logger, self.session, guest_log, overwrite=update_progress.overwrite)

                if r_blob_update.is_error:
                    return self._error(r_blob_update, 'failed to store a log blob')

            if update_progress.state == GuestLogState.COMPLETE:
                return None

            if update_progress.state == GuestLogState.ERROR:
                return None

            # PENDING, IN_PROGRESS and UNSUPPORTED proceed the same way
            self.request_task(
                update_guest_log,
                self.guestname,
                self.logname,
                self.contenttype.value,
                delay=update_progress.delay_update or r_delay_update.unwrap(),
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        logname: str,
        contenttype: GuestLogContentType,
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, db, guestname, task=Workspace.TASKNAME)

        workspace.logname = logname
        workspace.contenttype = contenttype

        return workspace

    @classmethod
    def update_guest_log(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        logname: str,
        contenttype: GuestLogContentType,
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname, logname, contenttype).begin().run().complete().final_result


@task(tail_handler=LoggingTailHandler())
def update_guest_log(guestname: str, logname: str, contenttype: str) -> None:
    task_core(
        cast(DoerType, Workspace.update_guest_log),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname, logname, GuestLogContentType(contenttype)),
    )
