# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import datetime
from typing import Any, Dict, Optional, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Ok, Result

from .. import Failure
from ..db import DB, GuestLog, GuestLogBlob, GuestLogContentType, GuestLogState, SafeQuery, execute_dml
from ..drivers import GuestLogBlob as GuestLogBlobProgress
from ..drivers import GuestLogUpdateProgress
from ..guest import GuestState
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import GuestRequestWorkspace as _Workspace
from . import LoggingTailHandler, get_guest_logger, step, task, task_core

#: A delay, in second, between successful acquire of a cloud instance and dispatching of post-acquire preparation tasks.
KNOB_UPDATE_GUEST_LOG_DELAY: Knob[int] = Knob(
    'actor.dispatch-preparing.delay',
    'How often to run guest log update',
    has_db=False,
    envvar='ARTEMIS_LOGS_UPDATE_TICK',
    cast_from_str=int,
    default=60
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
                return

            assert self.gr

            r_guest_log = SafeQuery.from_session(self.session, GuestLog) \
                .filter(GuestLog.guestname == self.gr.guestname) \
                .filter(GuestLog.logname == self.logname) \
                .filter(GuestLog.contenttype == self.contenttype) \
                .one_or_none()

            if r_guest_log.is_error:
                return self._error(r_guest_log, 'failed to fetch the log')

            guest_log: Optional[GuestLog] = r_guest_log.unwrap()

            def _log_state_event(resolution: Optional[str] = None, new_state: Optional[GuestLogState] = None) -> None:
                assert guest_log is not None
                assert self.gr is not None

                kwargs: Dict[str, Any] = {}

                if resolution is not None:
                    kwargs['resolution'] = resolution

                if new_state is not None:
                    kwargs['new_state'] = new_state.value

                self._event(
                    'guest-log-updated',
                    logname=guest_log.logname,
                    # ignore[attr-defined]: some issue with annotations of SafeQuery, the real type
                    # seems to be hidden :/
                    contenttype=guest_log.contenttype.value,  # type: ignore[attr-defined]
                    current_state=guest_log.state.value,  # type: ignore[attr-defined]
                    **kwargs
                )

            def _insert_blob(blob: GuestLogBlobProgress) -> None:
                assert guest_log is not None

                blob_query = sqlalchemy \
                    .insert(GuestLogBlob.__table__) \
                    .values(
                        guestname=guest_log.guestname,
                        logname=guest_log.logname,
                        contenttype=guest_log.contenttype,
                        ctime=blob.ctime,
                        content=blob.content,
                        content_hash=blob.content_hash
                    )

                r_store = execute_dml(self.logger, self.session, blob_query)

                if r_store.is_error:
                    return self._error(r_store, 'failed to store guest log blob')

                # return SUCCESS

            def _update_blob(blob: GuestLogBlob, content: str, content_hash: str) -> None:
                assert guest_log is not None

                blob_query = sqlalchemy \
                    .update(GuestLogBlob.__table__) \
                    .where(GuestLogBlob.guestname == guest_log.guestname) \
                    .where(GuestLogBlob.logname == guest_log.logname) \
                    .where(GuestLogBlob.contenttype == guest_log.contenttype) \
                    .where(GuestLogBlob.ctime == blob.ctime) \
                    .where(GuestLogBlob.content_hash == blob.content_hash) \
                    .values(
                        content=content,
                        content_hash=content_hash
                    )

                r_store = execute_dml(self.logger, self.session, blob_query)

                if r_store.is_error:
                    return self._error(r_store, 'failed to update guest log blob')

                # return SUCCESS

            def _update_log(progress: GuestLogUpdateProgress) -> None:
                assert guest_log is not None
                assert self.gr is not None

                query = sqlalchemy \
                    .update(GuestLog.__table__) \
                    .where(GuestLog.guestname == self.gr.guestname) \
                    .where(GuestLog.logname == guest_log.logname) \
                    .where(GuestLog.contenttype == guest_log.contenttype) \
                    .where(GuestLog.state == guest_log.state) \
                    .where(GuestLog.updated == guest_log.updated) \
                    .where(GuestLog.url == guest_log.url) \
                    .values(
                        url=progress.url,
                        updated=datetime.datetime.utcnow(),
                        state=progress.state,
                        expires=progress.expires
                    )

                r_store = execute_dml(self.logger, self.session, query)

                if r_store.is_error:
                    return self._error(r_store, 'failed to update guest log')

                if progress.overwrite:
                    assert progress.blobs

                    current_blob: Optional[GuestLogBlob] = guest_log.blobs[0] if guest_log.blobs else None
                    new_blob = progress.blobs[0]

                    if current_blob:
                        return _update_blob(current_blob, new_blob.content, new_blob.content_hash)

                    return _insert_blob(new_blob)

                for blob in progress.blobs:
                    if self.result:
                        return

                    _insert_blob(blob)

            if guest_log is None:
                return self._fail(
                    Failure(
                        'no such guest log'
                    ),
                    'no such guest log'
                )

            if guest_log.state == GuestLogState.ERROR:  # type: ignore[comparison-overlap]
                # TODO logs: there is a corner case: log crashes because of flapping API, the guest is reprovisioned
                # to different pool, and here the could succeed - but it's never going to be tried again since it's
                # in ERROR state and there's no way to "reset" the state - possibly do that in API via POST.

                return _log_state_event(resolution='guest-log-in-error-state')

            # TODO logs: it'd be nice to change logs' state to something final
            if self.gr.state in (GuestState.CONDEMNED, GuestState.ERROR):  # type: ignore[comparison-overlap]
                # logger.warning('guest can no longer provide any useful logs')

                _log_state_event(resolution='guest-condemned')

                return _update_log(GuestLogUpdateProgress(
                    state=GuestLogState.COMPLETE,
                    url=guest_log.url,
                    expires=guest_log.expires
                ))

            if self.gr.pool is None:
                # logger.warning('guest request has no pool at this moment, reschedule')

                _log_state_event(resolution='guest-not-routed')

                return self._reschedule()

            self.load_gr_pool()

            if self.result:
                return

            assert self.pool

            r_capabilities = self.pool.capabilities()

            if r_capabilities.is_error:
                return self._error(r_capabilities, 'failed to fetch pool capabilities')

            capabilities = r_capabilities.unwrap()

            if not capabilities.supports_guest_log(self.logname, self.contenttype):
                # If the guest request reached its final states, there's no chance for a pool change in the future,
                # therefore UNSUPPORTED becomes final state as well.
                if self.gr.state in (GuestState.READY.value, GuestState.CONDEMNED.value):
                    _log_state_event(resolution='unsupported-and-guest-complete')

                    return _update_log(GuestLogUpdateProgress(
                        state=GuestLogState.UNSUPPORTED,
                        url=guest_log.url,
                        expires=guest_log.expires
                    ))

                r_update: Result[GuestLogUpdateProgress, Failure] = Ok(GuestLogUpdateProgress(
                    state=GuestLogState.UNSUPPORTED
                ))

            elif guest_log.state == GuestLogState.UNSUPPORTED:  # type: ignore[comparison-overlap]
                # If the guest request reached its final states, there's no chance for a pool change in the future,
                # therefore UNSUPPORTED becomes final state as well.
                if self.gr.state in (GuestState.READY.value, GuestState.CONDEMNED.value):
                    _log_state_event(resolution='unsupported-and-guest-complete')

                    return _update_log(GuestLogUpdateProgress(
                        state=GuestLogState.UNSUPPORTED,
                        url=guest_log.url,
                        expires=guest_log.expires
                    ))

                r_update = self.pool.update_guest_log(
                    self.logger,
                    self.gr,
                    guest_log
                )

            elif guest_log.state == GuestLogState.COMPLETE:  # type: ignore[comparison-overlap]
                if not guest_log.is_expired:
                    _log_state_event(resolution='complete-not-expired')

                    return

                r_update = self.pool.update_guest_log(
                    self.logger,
                    self.gr,
                    guest_log
                )

            elif guest_log.state == GuestLogState.PENDING:  # type: ignore[comparison-overlap]
                r_update = self.pool.update_guest_log(
                    self.logger,
                    self.gr,
                    guest_log
                )

            elif guest_log.state == GuestLogState.IN_PROGRESS:  # type: ignore[comparison-overlap]
                r_update = self.pool.update_guest_log(
                    self.logger,
                    self.gr,
                    guest_log
                )

            if r_update.is_error:
                return self._error(r_update, 'failed to update the log')

            update_progress = r_update.unwrap()

            _log_state_event(new_state=update_progress.state)

            _update_log(update_progress)

            if self.result:
                return

            if update_progress.state == GuestLogState.COMPLETE:
                return

            if update_progress.state == GuestLogState.ERROR:
                return

            # PENDING, IN_PROGRESS and UNSUPPORTED proceed the same way
            self.request_task(
                update_guest_log,
                self.guestname,
                self.logname,
                self.contenttype.value,
                delay=update_progress.delay_update or KNOB_UPDATE_GUEST_LOG_DELAY.value
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        logname: str,
        contenttype: GuestLogContentType
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
        contenttype: GuestLogContentType
    ) -> DoerReturnType:
        """
        Inspect the provisioning progress of a given request, and update info Artemis holds for this request.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname, logname, contenttype) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(tail_handler=LoggingTailHandler())
def update_guest_log(guestname: str, logname: str, contenttype: str) -> None:
    task_core(
        cast(DoerType, Workspace.update_guest_log),
        logger=get_guest_logger(Workspace.TASKNAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname, logname, GuestLogContentType(contenttype))
    )
