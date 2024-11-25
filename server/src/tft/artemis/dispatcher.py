# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import time
from typing import Optional

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from . import Failure, Sentry, get_db, get_logger
from .context import DATABASE, LOGGER, SESSION
from .db import DMLResult, SafeQuery, TaskRequest, execute_dml, transaction
from .tasks import TaskCall, TaskLogger, dispatch_task

# Some tasks may seem to be unused, but they *must* be imported and known to broker
# for transactional outbox to work correctly.
from .tasks import update_guest_log  # noqa: F401, isort:skip


def handle_task_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    task_request: TaskRequest
) -> None:
    with Sentry.start_span('dispatch_task_request', op='function') as tracing_span:
        logger = TaskLogger(root_logger, f'task-request#{task_request.id}')

        LOGGER.set(logger)

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

        r_task_call = TaskCall.from_task_request(task_request)

        if r_task_call.is_error:
            return _log_failure(r_task_call.unwrap_error(), 'failed to find task')

        task_call = r_task_call.unwrap()

        tracing_span.set_tag('task_call', task_call.serialize())

        r_dispatch = dispatch_task(
            logger,
            task_call.actor,
            *task_arguments,
            delay=task_request.delay,
            task_request_id=task_request.id
        )

        if r_dispatch.is_error:
            return _log_failure(r_dispatch.unwrap_error(), 'failed to dispatch task')

        r_delete: DMLResult[TaskRequest] = execute_dml(
            logger,
            session,
            sqlalchemy.delete(TaskRequest).where(TaskRequest.id == task_request.id)
        )

        if r_delete.is_error:
            return _log_failure(r_dispatch.unwrap_error(), 'failed to remove task request')

        logger.finished()


def pick_task_request(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> bool:
    LOGGER.set(logger)

    with Sentry.start_span('pick_task_request', op='function'), \
            transaction(logger, session) as transaction_result:
        r_pending_task = SafeQuery.from_session(session, TaskRequest) \
            .limit(1) \
            .one_or_none()

        if r_pending_task.is_error:
            Failure.from_failure(
                'failed to fetch pending task',
                r_pending_task.unwrap_error()
            ).handle(logger)

            return False

        task_request: Optional[TaskRequest] = r_pending_task.unwrap()

        if task_request is None:
            return False

        handle_task_request(logger, session, task_request)

        LOGGER.set(logger)

    if not transaction_result.complete:
        assert transaction_result.failure is not None

        transaction_result.failure.handle(logger)

    return transaction_result.complete


def main() -> None:
    logger = TaskLogger(get_logger(), 'dispatcher')
    db = get_db(logger, application_name='artemis-dispatcher')

    LOGGER.set(logger)
    DATABASE.set(db)

    # Spawn HTTP server to provide metrics for Prometheus
    # ...

    while True:
        logger.info('tick...')

        with Sentry.start_transaction(op='function', name='dispatcher_session'), db.get_session(logger) as session:
            SESSION.set(session)

            while pick_task_request(logger, session):
                pass

        time.sleep(10)


if __name__ == '__main__':
    main()
