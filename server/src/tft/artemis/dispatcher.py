# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import time
from typing import Optional

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from . import Failure, Sentry, TracingOp, get_db, get_logger, get_worker_name, log_dict_yaml
from .context import DATABASE, LOGGER, SESSION
from .db import DMLResult, SafeQuery, TaskRequest, TaskSequenceRequest, execute_dml, transaction
from .metrics import DispatcherMetrics
from .tasks import TaskCall, TaskLogger, dispatch_sequence, dispatch_task

# Some tasks may seem to be unused, but they *must* be imported and known to broker
# for transactional outbox to work correctly.
from .tasks import update_guest_log  # noqa: F401, isort:skip


def handle_task_request(
    root_logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, task_request: TaskRequest
) -> None:
    with Sentry.start_span(TracingOp.FUNCTION, description='dispatch_task_request') as tracing_span:
        logger = TaskLogger(root_logger, f'task-request#{task_request.id}')

        LOGGER.set(logger)

        logger.begin()

        task_arguments = tuple(task_request.arguments)

        # TODO: teach format_task_invocation() to accept actor name so we could log task before
        # we try to find its actor
        formatted_args = [str(arg) for arg in task_arguments]

        if task_request.delay is not None:
            formatted_args.append(f'delay={task_request.delay}')

        logger.info(f'about to schedule task {task_request.taskname}({", ".join(formatted_args)})')

        def _log_failure(failure: Failure, message: str) -> None:
            failure.update(task_name=task_request.taskname, task_args=task_request.arguments).handle(logger, message)

            DispatcherMetrics.inc_failed_dispatched_tasks()

            logger.finished()

        r_task_call = TaskCall.from_task_request(task_request)

        if r_task_call.is_error:
            return _log_failure(r_task_call.unwrap_error(), 'failed to find task')

        task_call = r_task_call.unwrap()

        tracing_span.set_tag('taskname', task_call.actor.actor_name)
        tracing_span.set_data('task_call', task_call.serialize())

        r_dispatch = dispatch_task(
            logger, task_call.actor, *task_arguments, delay=task_request.delay, task_request_id=task_request.id
        )

        if r_dispatch.is_error:
            return _log_failure(r_dispatch.unwrap_error(), 'failed to dispatch task')

        r_delete: DMLResult[TaskRequest] = execute_dml(
            logger, session, sqlalchemy.delete(TaskRequest).where(TaskRequest.id == task_request.id)
        )

        if r_delete.is_error:
            return _log_failure(r_delete.unwrap_error(), 'failed to remove task request')

        DispatcherMetrics.inc_successful_dispatched_tasks(task_call.actor.actor_name)

        logger.finished()


def handle_task_sequence_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    task_sequence_request: TaskSequenceRequest,
) -> None:
    with Sentry.start_span(TracingOp.FUNCTION, description='dispatch_task_sequence_request') as tracing_span:
        logger = TaskLogger(root_logger, f'task-sequence-request#{task_sequence_request.id}')

        LOGGER.set(logger)

        logger.begin()

        r_task_requests = (
            SafeQuery.from_session(session, TaskRequest)
            .filter(TaskRequest.task_sequence_request_id == task_sequence_request.id)
            .order_by(TaskRequest.id.asc())
            .all()
        )

        if r_task_requests.is_error:
            Failure.from_failure('failed to fetch task requests', r_task_requests.unwrap_error()).handle(logger)

            return None

        def _log_failure(failure: Failure, message: str) -> None:
            failure.handle(logger, message)

            DispatcherMetrics.inc_failed_dispatched_task_sequences()

            logger.finished()

        task_calls: list[TaskCall] = []

        for task_request in r_task_requests.unwrap():
            r_task_call = TaskCall.from_task_request(task_request)

            if r_task_call.is_error:
                return _log_failure(r_task_call.unwrap_error(), 'failed to find task')

            task_calls.append(r_task_call.unwrap())

        log_dict_yaml(
            logger.info,
            f'about to schedule task sequence #{task_sequence_request.id}',
            [repr(task_call) for task_call in task_calls],
        )

        tracing_span.set_data('task_sequence_call', [task_call.serialize() for task_call in task_calls])

        r_dispatch = dispatch_sequence(
            logger,
            [(task_call.task_request_id, task_call.actor, task_call.args) for task_call in task_calls],
            delay=task_calls[0].delay,
            task_sequence_request_id=task_sequence_request.id,
        )

        if r_dispatch.is_error:
            return _log_failure(r_dispatch.unwrap_error(), 'failed to dispatch task sequence')

        for task_call in task_calls:
            r_delete: DMLResult[TaskRequest] = execute_dml(
                logger, session, sqlalchemy.delete(TaskRequest).where(TaskRequest.id == task_call.task_request_id)
            )

            if r_delete.is_error:
                return _log_failure(r_delete.unwrap_error(), 'failed to remove task request')

        r_sequence_delete: DMLResult[TaskSequenceRequest] = execute_dml(
            logger,
            session,
            sqlalchemy.delete(TaskSequenceRequest).where(TaskSequenceRequest.id == task_sequence_request.id),
        )

        if r_sequence_delete.is_error:
            return _log_failure(r_sequence_delete.unwrap_error(), 'failed to remove task sequence request')

        DispatcherMetrics.inc_successful_dispatched_task_sequence(
            [task_call.actor.actor_name for task_call in task_calls]
        )

        logger.finished()


def pick_task_request(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> bool:
    LOGGER.set(logger)

    DispatcherMetrics.inc_dispatched_task_invocations()

    with Sentry.start_transaction(TracingOp.FUNCTION, 'dispatcher') as tracing_transaction:
        with (
            Sentry.start_span(TracingOp.FUNCTION, 'handle_task_request'),
            transaction(logger, session) as transaction_result,
        ):
            r_pending_task = (
                SafeQuery.from_session(session, TaskRequest)
                .filter(TaskRequest.task_sequence_request_id.is_(None))
                .limit(1)
                .with_skip_locked()
                .one_or_none()
            )

            if r_pending_task.is_error:
                Failure.from_failure('failed to fetch pending task', r_pending_task.unwrap_error()).handle(logger)

                return False

            task_request: Optional[TaskRequest] = r_pending_task.unwrap()

            if task_request is None:
                return False

            tracing_transaction.set_tag('taskname', task_request.taskname)

            handle_task_request(logger, session, task_request)

            LOGGER.set(logger)

        if not transaction_result.complete:
            assert transaction_result.failure is not None

            transaction_result.failure.handle(logger)

        return transaction_result.complete


def pick_task_sequence_request(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> bool:
    LOGGER.set(logger)

    DispatcherMetrics.inc_dispatched_task_sequence_invocations()

    with Sentry.start_transaction(TracingOp.FUNCTION, 'dispatcher'):
        with (
            Sentry.start_span(TracingOp.FUNCTION, 'handle_task_sequence_request'),
            transaction(logger, session) as transaction_result,
        ):
            r_pending_task_sequence = SafeQuery.from_session(session, TaskSequenceRequest).limit(1).one_or_none()

            if r_pending_task_sequence.is_error:
                Failure.from_failure(
                    'failed to fetch task sequence request', r_pending_task_sequence.unwrap_error()
                ).handle(logger)

                return False

            task_sequence_request: Optional[TaskSequenceRequest] = r_pending_task_sequence.unwrap()

            if task_sequence_request is None:
                return False

            handle_task_sequence_request(logger, session, task_sequence_request)

            LOGGER.set(logger)

        if not transaction_result.complete:
            assert transaction_result.failure is not None

            transaction_result.failure.handle(logger)

        return transaction_result.complete


def main() -> None:
    logger = TaskLogger(get_logger(), 'dispatcher')
    db = get_db(logger, application_name=f'dispatcher: {get_worker_name()}')

    LOGGER.set(logger)
    DATABASE.set(db)

    # Spawn HTTP server to provide metrics for Prometheus
    # ...

    while True:
        logger.info('tick...')

        with db.get_session(logger) as session:
            SESSION.set(session)

            while pick_task_sequence_request(logger, session):
                pass

            while pick_task_request(logger, session):
                pass

        time.sleep(10)


if __name__ == '__main__':
    main()
