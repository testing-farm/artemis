# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import time

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session
from dramatiq.errors import ActorNotFound

from . import Failure, get_db, get_logger
from .db import SafeQuery, SnapshotRequest, TaskRequest, execute_db_statement
from .guest import GuestState
from .tasks import BROKER, TaskLogger, _update_snapshot_state, dispatch_task, get_snapshot_logger

# Some tasks may seem to be unused, but they *must* be imported and known to broker
# for transactional outbox to work correctly.
from .tasks import acquire_guest_request  # noqa: F401, isort:skip
from .tasks import route_snapshot_request  # noqa: F401, isort:skip
from .tasks import release_guest_request  # noqa: F401, isort:skip
from .tasks import release_snapshot_request  # noqa: F401, isort:skip
from .tasks import restore_snapshot_request  # noqa: F401, isort:skip
from .tasks import route_guest_request  # noqa: F401, isort:skip
from .tasks import guest_request_watchdog  # noqa: F401, isort:skip


def _dispatch_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-create', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Release the snapshot to the next stage. If this succeeds, dispatcher will no longer have any power
    # over the snapshot, and completion of the request would be taken over by a set of tasks.
    if not _update_snapshot_state(
        logger,
        session,
        snapshot.snapshotname,
        snapshot.guestname,
        GuestState.PENDING,
        GuestState.ROUTING
    ):
        # Somebody already did our job, the snapshot request is not in PENDING state anymore.
        logger.finished()
        return

    dispatch_task(logger, route_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _release_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-release', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot request.
    dispatch_task(logger, release_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _restore_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-restore', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot equest.
    dispatch_task(logger, restore_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def handle_task_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    task_request: TaskRequest
) -> None:
    logger = TaskLogger(root_logger, f'task-request#{task_request.id}')

    logger.begin()

    task_arguments = tuple(task_request.arguments)

    # TODO: teach format_task_invocation() to accept actor name so we could log task before
    # we try to find its actor
    formatted_args = [
        str(arg) for arg in task_arguments
    ]

    if task_request.delay is not None:
        formatted_args.append(f'delay={task_request.delay}')

    logger.info(f'about to schedule task {task_request.taskname}({", ".join(formatted_args)})')

    def _log_failure(failure: Failure, message: str) -> None:
        failure.update(
            task_name=task_request.taskname,
            task_args=task_request.arguments
        ).handle(logger, message)

        logger.finished()

    try:
        actor = BROKER.get_actor(task_request.taskname)

    except ActorNotFound as exc:
        return _log_failure(Failure.from_exc('failed to find task', exc), 'failed to find task')

    r_dispatch = dispatch_task(
        logger,
        actor,
        *task_arguments,
        delay=task_request.delay,
        task_request_id=task_request.id
    )

    if r_dispatch.is_error:
        return _log_failure(r_dispatch.unwrap_error(), 'failed to dispatch task')

    r_delete = execute_db_statement(
        logger,
        session,
        sqlalchemy.delete(TaskRequest.__table__).where(TaskRequest.id == task_request.id)
    )

    if r_delete.is_error:
        return _log_failure(r_dispatch.unwrap_error(), 'failed to remove task request')

    logger.finished()


def main() -> None:
    root_logger = get_logger()
    db = get_db(root_logger, application_name='artemis-dispatcher')

    # Spawn HTTP server to provide metrics for Prometheus
    # ...

    while True:
        root_logger.info('tick...')

        with db.get_session() as session:
            r_pending_tasks = SafeQuery.from_session(session, TaskRequest) \
                .all()

            if r_pending_tasks.is_error:
                Failure.from_failure(
                    'failed to fetch pending tasks',
                    r_pending_tasks.unwrap_error()
                ).handle(root_logger)

            else:
                for task_request in r_pending_tasks.unwrap():
                    handle_task_request(root_logger, session, task_request)

        # For each pending guest request, start their processing by submitting the first, routing task.
        with db.get_session() as session:
            r_pending_sr = SafeQuery.from_session(session, SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.PENDING) \
                .all()

            if r_pending_sr.is_ok:
                for snapshot in r_pending_sr.unwrap():
                    _dispatch_snapshot_request(root_logger, session, snapshot)

            else:
                Failure('failed to fetch pending snapshot requests').handle(root_logger)

            r_restoring_sr = SafeQuery.from_session(session, SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.CONDEMNED) \
                .all()

            if r_restoring_sr.is_ok:
                for snapshot in r_restoring_sr.unwrap():
                    _release_snapshot_request(root_logger, session, snapshot)

            else:
                Failure('failed to fetch condemned snapshot requests').handle(root_logger)

            r_restoring_sr = SafeQuery.from_session(session, SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.RESTORING) \
                .all()

            if r_restoring_sr.is_ok:
                for snapshot in r_restoring_sr.unwrap():
                    _restore_snapshot_request(root_logger, session, snapshot)

            else:
                Failure('failed to fetch restoring snapshot requests').handle(root_logger)

        time.sleep(10)


if __name__ == '__main__':
    main()
