import asyncio
import json
import os
import threading

import dramatiq
import gluetool.log
import sqlalchemy
import sqlalchemy.orm.exc
import sqlalchemy.orm.session
import stackprinter

from gluetool.result import Result, Ok, Error

import artemis
import artemis.db
import artemis.guest
import artemis.drivers.openstack
import artemis.script
import artemis.drivers.aws
import artemis.drivers.beaker

from artemis import Failure, safe_call, safe_db_execute, log_guest_event, log_error_guest_event
from artemis.db import GuestRequest, SnapshotRequest

from typing import cast, Any, Callable, Dict, List, Optional, Tuple
from typing_extensions import Protocol

DEFAULT_MIN_BACKOFF_SECONDS = 15
DEFAULT_MAX_BACKOFF_SECONDS = 60

# There is a very basic thing we must be aware of: a task - the Python function below - can run multiple times,
# sequentialy or in parallel. It's like multithreading application above a database, without any locks available.
# Tasks must be aware of this and carefully plan their workflow, to employ database queries to help with the
# synchronization, and tasks must be always ready to rollback their changes as much as possible.
#
#   "Ask for forgiveness, not for permission."
#
# Stick to the basic principles:
#
# * a task *must be* idenpotent.
# * a task *must be* atomic.
# * a task must not wait for other tasks to complete.
# * a task should not return any result - we're using database to store the state.
# * no complex object as task parameters, always use primitive data types.
#
# In the case of doubts, let's examine the checklist and discuss: https://devchecklists.com/celery-tasks-checklist/
#

#
# How we're running our tasks
#
# dramatiq will start a task by executing its corresponding function in the context of a thread within a worker
# process - let's call it thread A. This thread runs the task's function, and it will be send asynchronous exceptions
# such as TimeLimitExceeded or Shutdown. Given that our tasks must be able to rollback any changes they perform in the
# case of an error, they have to somehow keep their progress inernally, and mark down actions they need to unroll when
# the time comes. However, in the environment where the task can be interrupted by an *asynchronous* exception, it is
# not possible to implement this rollback consistently *in a readable fashion*. The opportunity for a race condition
# between the action and unroll note could be solved by wrapping each action with try-catch, catching these
# asynchronous exceptions, taking necessary steps in except/finally branches. This would of course make the code
# hard to read, with all that exception handling, leaving us with spagetti code everywhere.
#
# So, asyncio to the rescue! Let's cheat a bit. Thread A will spawn - with the help of asyncio, futures and event
# loop - new thread, B, which will run the actual code of the task. In thread A we'll have the event loop code, which,
# when receiving the asynchronous exceptions, would set "cancel?" event which was passed to the task in thread B.
# After that, thread A would continue running the event loop, waiting for thread B to finish.
#
# Thread B started running the task, and will check "canceled?" event from time to time. Should the event become set,
# it can safely unroll & quit. Asynchronous exceptions are delivered to the thread A, no need to fear them in thread B.
# We don't need to *kill* thread B when asynchronous exception arrived to thread A, we just need to tell it to quit
# as soon as possible.
#
# When thread B finishes, successfully or by raising an exception, its "return value" is "picked up" by thread A,
# possibly raising the original exception raised in thread B, giving thread A a chance to react to them even more.

#
# TODO:
# - support queue name when sending messages - we want our tasks to use different queues.
# - allow retries modification and tweaking
# - "lazy actor" wrapper to avoid the necessity of initializing dramatiq at the import time


# initialize database ONCE per worker
root_logger = artemis.get_logger()
db = artemis.get_db(root_logger)


# This should be correct type, but mypy has some issue with it :/
#
#   Argument 4 to "run_doer" has incompatible type
#   "Callable[[ContextAdapter, DB, Event, str, str], Coroutine[Any, Any, None]]"; expected "DoerType"
# I'm adding "type: ignore" temporarily to run_doer cllas until solution is found.
class DoerType(Protocol):
    async def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        db: artemis.db.DB,
        cancel: threading.Event,
        *args: Any,
        **kwargs: Any
    ) -> Any: ...


class Actor(Protocol):
    def send(
        self,
        *args: Any,
        **kwargs: Any
    ) -> None: ...


class EventLoggerType(Protocol):
    def __call__(
        self,
        eventname: str,
        **more_details: Any
    ) -> None: ...


class ErrorEventLoggerType(Protocol):
    def __call__(
        self,
        result: Result[Any, Failure],
        message: str,
        **more_details: Any
    ) -> None: ...


class TaskLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, task_name: str) -> None:
        super(TaskLogger, self).__init__(logger, {
            'ctx_task_name': (30, task_name)
        })

    def begin(self) -> None:
        self.warning('beginning')

    def finished(self) -> None:
        self.warning('finished')

    def failed(self, failure: Failure) -> None:
        self.error('failed:\n{}'.format(stackprinter.format(failure.exception)))


_ = artemis.get_broker()


POOL_DRIVERS = {
    'openstack': artemis.drivers.openstack.OpenStackDriver,
    'aws': artemis.drivers.aws.AWSDriver,
    'beaker': artemis.drivers.beaker.BeakerDriver
}


def create_event_loggers(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    **default_details: Any
) -> Tuple[EventLoggerType, ErrorEventLoggerType]:
    def _log_event(
        eventname: str,
        **more_details: Any
    ) -> None:
        details = {
            **default_details,
            **more_details
        }

        log_guest_event(
            logger,
            session,
            guestname,
            eventname,
            **details
        )

    def _log_error_event(
        result: Result[Any, Failure],
        message: str,
        **more_details: Any
    ) -> None:
        details = {
            **default_details,
            **more_details
        }

        log_error_guest_event(
            logger,
            session,
            guestname,
            result.unwrap_error(),
            message,
            **details
        )

    return _log_event, _log_error_event


def actor_kwargs(actor_name: str) -> Dict[str, Any]:
    def _get(var_name: str, default: Any) -> Any:
        var_value = os.getenv(
            'ARTEMIS_ACTOR_{}_{}'.format(actor_name.upper(), var_name),
            default
        )
        # We don't bother about milliseconds in backoff values. For a sake of simplicity
        # variables stores value in seconds and here we convert it back to milliseconds
        if 'backoff' in var_name.lower():
            var_value = int(var_value) * 1000
        return var_value

    default_retries = os.getenv('ARTEMIS_ACTOR_DEFAULT_RETRIES', 5)

    return {
        'max_retries': int(_get('RETRIES', default_retries)),
        'min_backoff': int(_get('MIN_BACKOFF', DEFAULT_MIN_BACKOFF_SECONDS)),
        'max_backoff': int(_get('MAX_BACKOFF', DEFAULT_MAX_BACKOFF_SECONDS))
    }


def run_doer(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    fn: DoerType,
    *args: Any,
    **kwargs: Any
) -> Any:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        doer_task = loop.create_task(fn(logger, db, cancel, *args, **kwargs))

        loop.run_until_complete(doer_task)

    except dramatiq.middleware.Interrupt as exc:
        if isinstance(exc, dramatiq.middleware.TimeLimitExceeded):
            logger.error('time depleted')

        elif isinstance(exc, dramatiq.middleware.Shutdown):
            logger.error('killed')

        else:
            assert False, 'Unhandled interrupt exception'

        cancel.set()

        pending = asyncio.Task.all_tasks(loop)

        if not pending:
            return

        finish_future = asyncio.gather(*pending)

        loop.run_until_complete(finish_future)

        assert doer_task.done()

    return doer_task.result()


def task_core(
    doer: DoerType,
    logger_getter: Callable[[gluetool.log.ContextAdapter], TaskLogger],
    doer_args: Optional[Tuple[Any, ...]] = None,
    doer_kwargs: Optional[Dict[str, Any]] = None
) -> None:
    logger = logger_getter(root_logger)

    logger.begin()

    cancel = threading.Event()

    doer_args = doer_args or tuple()
    doer_kwargs = doer_kwargs or dict()

    try:
        run_doer(logger, db, cancel, doer, *doer_args, **doer_kwargs)

        logger.finished()
        return

    except Exception as exc:
        logger.failed(Failure.from_exc('task failed', exc))

    # To avoid chain of exceptions in the log - which we already logged above - raise a generic,
    # insignificant exception to notify our master about the failure.
    raise Exception('message processing failed')


def _dispatch_task(
    logger: gluetool.log.ContextAdapter,
    task: Actor,
    *args: Any,
    **kwargs: Any
) -> Result[None, Failure]:
    r = safe_call(task.send, *args, **kwargs)

    if r.is_ok:
        return Ok(None)

    exc_info = r.error.exc_info if r.error else None

    logger.error('failed to submit task {}'.format(task), exc_info=exc_info)

    return Error(Failure('failed to submit task {}'.format(task), exc_info=exc_info))


def _get_guest_by_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    state: artemis.guest.GuestState
) -> Optional[artemis.db.GuestRequest]:
    query = session \
            .query(GuestRequest) \
            .filter(GuestRequest.guestname == guestname) \
            .filter(GuestRequest.state == state.value)

    r_query = cast(
        Result[artemis.db.GuestRequest, Failure],
        safe_call(query.one)
    )

    if r_query.is_ok:
        return r_query.unwrap()

    failure = r_query.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(state.value))
        return None

    failure.reraise()


def _get_snapshot_by_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshotname: str,
    state: artemis.guest.GuestState
) -> Optional[artemis.db.SnapshotRequest]:
    query = session \
            .query(SnapshotRequest) \
            .filter(SnapshotRequest.snapshotname == snapshotname) \
            .filter(SnapshotRequest.state == state.value)

    r_query = cast(
        Result[artemis.db.SnapshotRequest, Failure],
        safe_call(query.one)
    )

    if r_query.is_ok:
        return r_query.unwrap()

    failure = r_query.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(state.value))
        return None

    failure.reraise()


def _update_guest_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    current_state: artemis.guest.GuestState,
    new_state: artemis.guest.GuestState,
    guest: Optional[artemis.guest.Guest] = None,
    set_values: Optional[Dict[str, Any]] = None,
    current_pool_data: Optional[str] = None,
    **details: Any
) -> bool:
    logger.warning('state switch: {} => {}'.format(current_state.value, new_state.value))

    details = details or {}

    if set_values:
        values = set_values
        values.update({
            'state': new_state.value
        })

    else:
        values = {
            'state': new_state.value
        }

    if current_pool_data:
        query = sqlalchemy \
            .update(GuestRequest.__table__) \
            .where(GuestRequest.guestname == guestname) \
            .where(GuestRequest.state == current_state.value) \
            .where(GuestRequest.pool_data == current_pool_data) \
            .values(**values)

    else:
        query = sqlalchemy \
            .update(GuestRequest.__table__) \
            .where(GuestRequest.guestname == guestname) \
            .where(GuestRequest.state == current_state.value) \
            .values(**values)

    r = safe_db_execute(logger, session, query)

    if r.is_ok:
        EVENT, ERROR_EVENT = create_event_loggers(
            logger,
            session,
            guestname,
            current_state=current_state.value,
            new_state=new_state.value,
            **details,
        )

        if r.value is True:
            logger.warning('state switch: {} => {}: succeeded'.format(current_state.value, new_state.value))

            EVENT('state-changed')

        else:
            logger.warning('state switch: {} => {}: failed'.format(current_state.value, new_state.value))

            ERROR_EVENT(r, 'failed to switch state')

        return r.unwrap()

    failure = r.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('state switch: {} => {}: no result found'.format(current_state.value, new_state.value))

        return False

    failure.reraise()


def _update_snapshot_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshotname: str,
    guestname: str,
    current_state: artemis.guest.GuestState,
    new_state: artemis.guest.GuestState,
    set_values: Optional[Dict[str, Any]] = None,
) -> bool:
    logger.warning('state switch: {} => {}'.format(current_state.value, new_state.value))

    if set_values:
        values = set_values
        values.update({
            'state': new_state.value
        })

    else:
        values = {
            'state': new_state.value
        }

    query = sqlalchemy \
        .update(SnapshotRequest.__table__) \
        .where(SnapshotRequest.snapshotname == snapshotname) \
        .where(SnapshotRequest.state == current_state.value) \
        .values(**values)

    r = safe_db_execute(logger, session, query)

    if r.is_ok:
        EVENT, ERROR_EVENT = create_event_loggers(
            logger,
            session,
            guestname,
            snapshotname=snapshotname,
            current_state=current_state.value,
            new_state=new_state.value
        )

        if r.value is True:
            logger.warning('state switch: {} => {}: succeeded'.format(current_state.value, new_state.value))

            EVENT('snapshot-state-changed')

        else:
            logger.warning('state switch: {} => {}: failed'.format(current_state.value, new_state.value))

            ERROR_EVENT(r, 'failed to switch snapshot state')

        return r.unwrap()

    failure = r.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('state switch: {} => {}: no result found'.format(current_state.value, new_state.value))

        return False

    failure.reraise()


def _get_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    poolname: str
) -> Result[artemis.drivers.PoolDriver, Failure]:
    try:
        pool_record = session \
                    .query(artemis.db.Pool) \
                    .filter(artemis.db.Pool.poolname == poolname) \
                    .one()

    except sqlalchemy.orm.exc.NoResultFound:
        raise Exception('no such pool "{}"'.format(poolname))

    pool_driver_class = POOL_DRIVERS[pool_record.driver]
    driver = pool_driver_class(logger, json.loads(pool_record.parameters))

    r_sanity = driver.sanity()

    if r_sanity.is_error:
        return Error(r_sanity.unwrap_error())

    return Ok(driver)


def get_pools(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> List[artemis.drivers.PoolDriver]:
    pools: List[artemis.drivers.PoolDriver] = []

    for pool_record in session.query(artemis.db.Pool).all():
        pool_driver_class = POOL_DRIVERS[pool_record.driver]

        pools += [
            pool_driver_class(logger, json.loads(pool_record.parameters), poolname=pool_record.poolname)
        ]

    return pools


def _get_ssh_key(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    ownername: str,
    keyname: str
) -> Result[artemis.db.SSHKey, Failure]:
    try:
        return Ok(
            cast(
                artemis.db.SSHKey,
                session.query(artemis.db.SSHKey).filter(
                    artemis.db.SSHKey.ownername == ownername,
                    artemis.db.SSHKey.keyname == keyname
                ).one()
            )
        )

    except sqlalchemy.orm.exc.NoResultFound:
        return Error(Failure('no key {}:{}'.format(ownername, keyname)))


def _get_master_key(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Result[artemis.db.SSHKey, Failure]:
    return _get_ssh_key(logger, session, 'artemis', 'master-key')


async def do_release_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str
) -> None:
    with db.get_session() as session:
        EVENT, ERROR_EVENT = create_event_loggers(logger, session, guestname)

        def _undo_guest_in_releasing() -> None:
            if _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.RELEASING,
                artemis.guest.GuestState.CONDEMNED
            ):
                return

            assert False, 'unreachable'

        gr = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.CONDEMNED)
        if not gr:
            return

        if cancel.is_set():
            logger.debug('canceling task')
            return

        if not _update_guest_state(
            logger,
            session,
            guestname,
            artemis.guest.GuestState.CONDEMNED,
            artemis.guest.GuestState.RELEASING
        ):
            return

        if gr.poolname:
            common_failure_details = {
                'guestname': guestname,
                'poolname': gr.poolname
            }

            r_pool = _get_pool(logger, session, gr.poolname)

            if r_pool.is_error:
                ERROR_EVENT(r_pool, 'pool sanity failed')
                return

            pool = r_pool.unwrap()

            if cancel.is_set():
                logger.info('canceling task')
                _undo_guest_in_releasing()
                return

            r_guest_sshkey = _get_ssh_key(
                logger,
                session,
                gr.ownername,
                gr.ssh_keyname
            )

            if r_guest_sshkey.is_error:
                ERROR_EVENT(r_guest_sshkey, 'failed to get SSH key')
                _undo_guest_in_releasing()
                return

            guest_sshkey = r_guest_sshkey.unwrap()
            r_guest = pool.guest_factory(gr, ssh_key=guest_sshkey)

            # If we cancelled the guest early, no provisioned guest is available
            if r_guest.is_error:
                failure = r_guest.unwrap_error()
                failure.details.update(common_failure_details)
                ERROR_EVENT(r_guest, 'failed to load guest', sentry=True)

            # This can happen if somebody removed the instance outside of Artemis
            else:
                r_release = pool.release_guest(r_guest.unwrap())

                if r_release.is_error:
                    failure = r_guest.unwrap_error()
                    failure.details.update(common_failure_details)
                    ERROR_EVENT(r_release, 'failed to release guest', sentry=True)

        query = sqlalchemy \
            .delete(GuestRequest.__table__) \
            .where(GuestRequest.guestname == guestname) \
            .where(GuestRequest.state == artemis.guest.GuestState.RELEASING.value)

        r_condemn = safe_db_execute(logger, session, query)

        if r_condemn.is_ok:
            EVENT('released')
            return

        failure = r_condemn.unwrap_error()

        if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
            logger.warning('not in RELEASING state anymore')
            return

        failure.reraise()


@dramatiq.actor(**actor_kwargs('RELEASE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def release_guest_request(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_release_guest_request,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.guest.GuestLogger(root_logger, guestname),
            'release'
        ),
        doer_args=(guestname,)
    )


async def do_update_guest(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str
) -> None:
    with db.get_session() as session:
        def _undo_guest_update(guest: artemis.guest.Guest) -> None:
            r = pool.release_guest(guest)

            if r.is_ok:
                return

            raise Exception(r.error)

        gr = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.PROMISED)
        if not gr:
            return

        assert gr.poolname is not None

        _, ERROR_EVENT = create_event_loggers(logger, session, guestname)

        current_pool_data = gr.pool_data

        r_pool = _get_pool(logger, session, gr.poolname)

        if r_pool.is_error:
            ERROR_EVENT(r_pool, 'pool sanity failed')
            return

        pool = r_pool.unwrap()

        if cancel.is_set():
            return

        r_guest_sshkey = _get_ssh_key(
            logger,
            session,
            gr.ownername,
            gr.ssh_keyname
        )

        if r_guest_sshkey.is_error:
            ERROR_EVENT(r_pool, 'failed to get SSH key')
            return

        r_guest = pool.guest_factory(gr, ssh_key=r_guest_sshkey.unwrap())

        if r_guest.is_error:
            ERROR_EVENT(r_pool, 'failed to load guest')
            return

        r_update = pool.update_guest(r_guest.unwrap())

        if r_update.is_error:
            ERROR_EVENT(r_update, 'failed to update guest')
            return

        guest = r_update.unwrap()

        if guest.is_promised:
            if _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.PROMISED,
                artemis.guest.GuestState.PROMISED,
                guest=guest,
                set_values={
                    'pool_data': guest.pool_data_to_db()
                },
                current_pool_data=current_pool_data
            ):
                r_promise = _dispatch_task(logger, update_guest, guestname)

                if r_promise.is_ok:
                    logger.info('scheduled update')
                    return

        else:
            if _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.PROMISED,
                artemis.guest.GuestState.READY,
                guest=guest,
                set_values={
                    'address': guest.address,
                    'pool_data': guest.pool_data_to_db()
                },
                current_pool_data=current_pool_data,
            ):
                logger.info('successfully acquired')
                return

        # Failed to change the state means somebody else already did the update. We have a guest on our hands,
        # which points to resources that are now wasted because there is another instance of this guest
        # already updated or finished. We can safely ask driver to release resources of this particular
        # guest instance - this is not going to affect the instance whose changes were commited to the database
        # before ours.
        _undo_guest_update(guest)


@dramatiq.actor(**actor_kwargs('UPDATE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def update_guest(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_update_guest,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.guest.GuestLogger(root_logger, guestname),
            'update'
        ),
        doer_args=(guestname,)
    )


async def do_acquire_guest(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str,
    poolname: str
) -> None:

    common_failure_details = {
        'guestname': guestname,
        'poolname': poolname
    }

    with db.get_session() as session:
        def _undo_guest_acquire(guest: artemis.guest.Guest) -> None:
            r = pool.release_guest(guest)

            if r.is_ok:
                return

            raise Exception(r.error)

        gr = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.PROVISIONING)
        if not gr:
            return

        _, ERROR_EVENT = create_event_loggers(logger, session, guestname)

        r_pool = _get_pool(logger, session, poolname)

        if r_pool.is_error:
            ERROR_EVENT(r_pool, 'pool sanity failed')
            return

        pool = r_pool.unwrap()

        r_master_key = _get_master_key(logger, session)
        if r_master_key.is_error:
            ERROR_EVENT(r_master_key, 'failed to get SSH key')

        master_key = r_master_key.unwrap()
        environment = artemis.environment.Environment.unserialize_from_json(json.loads(gr.environment))

        if cancel.is_set():
            return

        result = pool.acquire_guest(logger, gr, environment, master_key)

        if result.is_ok:
            guest = result.unwrap()

            if cancel.is_set():
                _undo_guest_acquire(guest)
                return

            # TODO: instead of switching to READY, we need to switch into transient state instead,
            # and upload the requested key to the guest (using our master key).

            # We have a guest, we can move the guest record to the next state. The guest may be unfinished,
            # in that case we should schedule a task for driver's update_guest method. Otherwise, we must
            # save guest's address. In both cases, we must be sure nobody else did any changes before us.
            if guest.is_promised:
                if _update_guest_state(
                    logger,
                    session,
                    guestname,
                    artemis.guest.GuestState.PROVISIONING,
                    artemis.guest.GuestState.PROMISED,
                    guest=guest,
                    set_values={
                        'pool_data': guest.pool_data_to_db()
                    }
                ):
                    r_promise = _dispatch_task(logger, update_guest, guestname)

                    if r_promise.is_ok:
                        logger.info('scheduled update')
                        return

            else:
                pool_data_to_db = guest.pool_data_to_db()

                if _update_guest_state(
                    logger,
                    session,
                    guestname,
                    artemis.guest.GuestState.PROVISIONING,
                    artemis.guest.GuestState.READY,
                    guest=guest,
                    set_values={
                        'address': guest.address,
                        'pool_data': pool_data_to_db
                    },
                    address=guest.address,
                    pool=gr.poolname,
                    pool_data=json.loads(pool_data_to_db)
                ):
                    logger.info('successfully acquired')
                    return

            # Failed to change the state means somebody else already did the provisioning. Or even canceled the request.
            # Again, we must undo and forget about the guest request.
            _undo_guest_acquire(guest)
            return

    # Code execution could only end up here if provisioning failed
    failure = result.unwrap_error()
    failure.details.update(common_failure_details)

    with db.get_session() as session:
        _, ERROR_EVENT = create_event_loggers(logger, session, guestname)

        ERROR_EVENT(
            result,
            'failed to provision: {}'.format(failure.message),
            sentry=True
        )

    raise Exception(failure.message)


@dramatiq.actor(**actor_kwargs('ACQUIRE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def acquire_guest(guestname: str, poolname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_acquire_guest,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.guest.GuestLogger(root_logger, guestname),
            'acquire'
        ),
        doer_args=(guestname, poolname)
    )


async def do_route_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str
) -> None:
    with db.get_session() as session:
        def _undo_guest_in_provisioning() -> None:
            if _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.PROVISIONING,
                artemis.guest.GuestState.ROUTING
            ):
                return

            # We should never ever end up here, because:
            #
            # - undo worked => _update_guest_state returns True and we leave right above this comment
            # - undo failed because of unspecified exception -> the exception is reraised in _update_guest_state
            # - undo failed because there was no such record in db -> _update_guest_state returns False, which is not
            # possible...
            #
            # We are the only instance of this task that got this far. We were the only instance that managed to move
            # guest to PROVISIONING state, any other instance should see it alread has that state (or they fail to
            # change it), stopping their execution at that point. We should be the only instance that has anything to
            # undo.
            #
            # So, what changed the guest state if it haven't been any other instance of this task, and if we failed to
            # dispatch any provisioning task??
            assert False, 'unreachable'

        # First, pick up our assigned guest request. Make sure it hasn't been
        # processed yet.
        guest = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.ROUTING)

        if not guest:
            return

        if cancel.is_set():
            return

        # Do stuff, examine request, pick the provisioner, and send it a message.
        #
        # Be aware that while the request was free to take, it may be being processed by multiple instances of this
        # task at once - we didn't acquire any lock! We could either introduce locking, or we can continue and make
        # sure the request didn't change when we start commiting changes. And since asking or forgiveness is simpler
        # than asking for permission, let's continue but be prepared to clean up if someone else did the work instead
        # of us.

        logger.info('finding suitable provisioner')

        r_engine = artemis.script.hook_engine('ROUTE')

        if r_engine.is_error:
            raise Exception('Failed to load ROUTE hook: {}'.format(r_engine.unwrap_error().message))

        engine = r_engine.unwrap()

        r_pool = engine.run_hook(
            'ROUTE',
            logger=logger,
            guest_request=guest,
            pools=get_pools(logger, session)
        )

        # Route hook failed, request cannot be fulfilled ;(
        if r_pool.is_error:
            logger.error('route hook failed, releasing guest: {}'.format(r_pool.unwrap_error().message))

            _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.ROUTING,
                artemis.guest.GuestState.CONDEMNED,
            )

            return

        pool = r_pool.unwrap()

        # No suitable pool found
        if not pool:
            raise Exception('No suitable pools found, raising to retry routing')

        if cancel.is_set():
            return

        # Mark request as suitable for provisioning.
        if not _update_guest_state(
            logger,
            session,
            guestname,
            artemis.guest.GuestState.ROUTING,
            artemis.guest.GuestState.PROVISIONING,
            set_values={
                'poolname': pool.poolname
            },
            pool=pool.poolname
        ):
            # We failed to move guest to PROVISIONING state which means some other instance of this task changed
            # guest's state instead of us, which means we should throw everything away because our decisions no
            # longer matter.
            return

        if cancel.is_set():
            _undo_guest_in_provisioning()

            return

        # Fine, the query succeeded, which means we are the first instance of this task to move this far. For any other
        # instance, the state change will fail and they will bail while we move on and try to dispatch the provisioning
        # task.
        r = _dispatch_task(logger, acquire_guest, guestname, pool.poolname)

        if r.is_ok:
            return

        # We failed to dispatch the task, but we already marked the request as suitable for provisioning, which means
        # that any subsequent run of this task would not be able to evaluate it again since it's no longer in ROUTING
        # state. We should undo this change.
        #
        # On the other hand, we just cannot chain undos of undos indefinitely, so if this attempt fails, let's give up
        # and let humans solve the problems.
        _undo_guest_in_provisioning()


@dramatiq.actor(**actor_kwargs('ROUTE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def route_guest_request(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_route_guest_request,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.guest.GuestLogger(root_logger, guestname),
            'route'
        ),
        doer_args=(guestname,)
    )


async def do_release_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    snapshotname: str
) -> None:
    with db.get_session() as session:
        def _undo_snapshot_in_removing() -> None:
            if _update_guest_state(
                logger,
                session,
                snapshotname,
                artemis.guest.GuestState.RELEASING,
                artemis.guest.GuestState.CONDEMNED
            ):
                return

            assert False, 'unreachable'

        snapshot_request = _get_snapshot_by_state(logger, session, snapshotname, artemis.guest.GuestState.CONDEMNED)
        if not snapshot_request:
            return

        EVENT, ERROR_EVENT = create_event_loggers(
            logger,
            session,
            snapshot_request.guestname,
            snapshotname=snapshot_request.snapshotname
        )

        if not _update_snapshot_state(
            logger,
            session,
            snapshotname,
            snapshot_request.guestname,
            artemis.guest.GuestState.CONDEMNED,
            artemis.guest.GuestState.RELEASING
        ):
            return

        if snapshot_request.poolname:
            r_pool = _get_pool(logger, session, snapshot_request.poolname)

            if r_pool.is_error:
                ERROR_EVENT(r_pool, 'pool sanity failed')

                _undo_snapshot_in_removing()
                return

            pool = r_pool.unwrap()

            if cancel.is_set():
                _undo_snapshot_in_removing()
                return

            r_snapshot = pool.snapshot_factory(snapshot_request)
            if r_snapshot.is_error:
                ERROR_EVENT(r_snapshot, 'failed to load pool')

                _undo_snapshot_in_removing()
                return

            r_release = pool.remove_snapshot(r_snapshot.unwrap())

            if r_release.is_error:
                ERROR_EVENT(r_release, 'failed to remove snapshot')

                _undo_snapshot_in_removing()
                return

        query = sqlalchemy \
            .delete(SnapshotRequest.__table__) \
            .where(SnapshotRequest.snapshotname == snapshotname) \
            .where(SnapshotRequest.state == artemis.guest.GuestState.RELEASING.value)

        r_condemn = safe_db_execute(logger, session, query)

        if r_condemn.is_ok:
            EVENT('snapshot-released')
            return

        failure = r_condemn.unwrap_error()

        if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
            logger.warning('not in CONDEMNED state anymore')
            return

        failure.reraise()


@dramatiq.actor(**actor_kwargs('RELEASE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def release_snapshot_request(snapshotname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_release_snapshot_request,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.snapshot.SnapshotLogger(root_logger, snapshotname),
            'release'
        ),
        doer_args=(snapshotname,)
    )


async def do_update_snapshot(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    snapshotname: str
) -> None:
    with db.get_session() as session:
        def _undo_snapshot_update(snapshot: artemis.snapshot.Snapshot) -> None:
            r = pool.remove_snapshot(snapshot)

            if r.is_ok:
                return

            raise Exception(r.error)

        snapshot_request = _get_snapshot_by_state(logger, session, snapshotname, artemis.guest.GuestState.PROMISED)
        if not snapshot_request:
            return

        _, ERROR_EVENT = create_event_loggers(logger, session, snapshot_request.guestname, snapshotname=snapshotname)

        assert snapshot_request.poolname is not None

        guest_request = _get_guest_by_state(logger, session, snapshot_request.guestname, artemis.guest.GuestState.READY)

        if not guest_request:
            return

        r_pool = _get_pool(logger, session, snapshot_request.poolname)

        if r_pool.is_error:
            ERROR_EVENT(r_pool, 'pool sanity failed')
            return

        pool = r_pool.unwrap()

        r_guest_sshkey = _get_ssh_key(
            logger,
            session,
            guest_request.ownername,
            guest_request.ssh_keyname
        )

        if r_guest_sshkey.is_error:
            ERROR_EVENT(r_guest_sshkey, 'failed to get SSH key')
            return

        guest_sshkey = r_guest_sshkey.unwrap()

        r_guest = pool.guest_factory(guest_request, ssh_key=guest_sshkey)
        if r_guest.is_error:
            ERROR_EVENT(r_guest, 'failed to load pool')
            return

        guest = r_guest.unwrap()

        if cancel.is_set():
            return

        r_snapshot = pool.snapshot_factory(snapshot_request)

        if r_snapshot.is_error:
            ERROR_EVENT(r_snapshot, 'failed to load snapshot')
            return

        r_update = pool.update_snapshot(r_snapshot.unwrap(), guest, start_again=snapshot_request.start_again)

        if r_update.is_error:
            ERROR_EVENT(r_update, 'failed to update snapshot')
            return

        snapshot = r_update.unwrap()

        if snapshot.is_promised:
            if _update_snapshot_state(
                logger,
                session,
                snapshotname,
                snapshot_request.guestname,
                artemis.guest.GuestState.PROMISED,
                artemis.guest.GuestState.PROMISED,
            ):
                r_promise = _dispatch_task(logger, update_snapshot, snapshotname, guest_request.guestname)

                if r_promise.is_ok:
                    logger.info('scheduled update')
                    return

        else:
            if _update_snapshot_state(
                logger,
                session,
                snapshotname,
                snapshot_request.guestname,
                artemis.guest.GuestState.PROMISED,
                artemis.guest.GuestState.READY,
            ):
                logger.info('successfully created')
                return

        # Failed to change the state means somebody else already did the update. We have a snapshot on our hands,
        # which points to resources that are now wasted because there is another instance of this snapshot
        # already updated or finished. We can safely ask driver to release resources of this particular
        # snapshot instance - this is not going to affect the instance whose changes were commited to the database
        # before ours.
        _undo_snapshot_update(snapshot)


@dramatiq.actor(**actor_kwargs('UPDATE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def update_snapshot(snapshotname: str, guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_update_snapshot,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.snapshot.SnapshotLogger(artemis.guest.GuestLogger(root_logger, guestname), snapshotname),
            'update'
        ),
        doer_args=(snapshotname,)
    )


async def do_create_snapshot(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    snapshotname: str
) -> None:
    with db.get_session() as session:
        def _undo_snapshot_create(snapshot: artemis.snapshot.Snapshot) -> None:
            r = pool.remove_snapshot(snapshot)

            if r.is_ok:
                return

            raise Exception(r.error)

        snapshot_request = _get_snapshot_by_state(logger, session, snapshotname, artemis.guest.GuestState.CREATING)

        if not snapshot_request:
            return

        _, ERROR_EVENT = create_event_loggers(logger, session, snapshot_request.guestname, snapshotname=snapshotname)

        if cancel.is_set():
            return

        guest_request = _get_guest_by_state(logger, session, snapshot_request.guestname, artemis.guest.GuestState.READY)

        if not guest_request:
            return

        if not snapshot_request.poolname:
            return

        r_pool = _get_pool(logger, session, snapshot_request.poolname)

        if r_pool.is_error:
            ERROR_EVENT(r_pool, 'pool sanity failed')
            return

        pool = r_pool.unwrap()

        r_guest_sshkey = _get_ssh_key(
            logger,
            session,
            guest_request.ownername,
            guest_request.ssh_keyname
        )

        if r_guest_sshkey.is_error:
            ERROR_EVENT(r_guest_sshkey, 'failed to get SSH key')
            return

        guest_sshkey = r_guest_sshkey.unwrap()

        r_guest = pool.guest_factory(guest_request, ssh_key=guest_sshkey)
        if r_guest.is_error:
            ERROR_EVENT(r_guest, 'failed to load pool')
            return

        guest = r_guest.unwrap()

        if cancel.is_set():
            return

        r_create = pool.create_snapshot(snapshot_request, guest)

        if r_create.is_error:
            error = r_create.unwrap_error()

            ERROR_EVENT(
                r_create,
                'failed to create snapshot: {}'.format(error.message),
                environment=error.details.get('environment'),
                hook_error=error.details.get('hook_error')
            )

            raise Exception(error)

        snapshot = r_create.unwrap()

        if cancel.is_set():
            _undo_snapshot_create(snapshot)
            return

        # If snapshot was promised - schedule update task. Otherwise change state to ready
        if snapshot.is_promised:
            if _update_snapshot_state(
                logger,
                session,
                snapshotname,
                snapshot_request.guestname,
                artemis.guest.GuestState.CREATING,
                artemis.guest.GuestState.PROMISED
            ):
                r_promise = _dispatch_task(logger, update_snapshot, snapshotname, snapshot.guestname)

                if r_promise.is_ok:
                    logger.info('scheduled update')
                    return

        else:
            if _update_snapshot_state(
                logger,
                session,
                snapshotname,
                snapshot_request.guestname,
                artemis.guest.GuestState.CREATING,
                artemis.guest.GuestState.READY,
            ):
                logger.info('successfully created')
                return

        # Failed to change the state means somebody else already did the provisioning. Or even canceled the request.
        # Again, we must undo and forget about the guest request.
        _undo_snapshot_create(snapshot)


@dramatiq.actor(**actor_kwargs('CREATE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def create_snapshot(snapshotname: str, guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_create_snapshot,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.snapshot.SnapshotLogger(artemis.guest.GuestLogger(root_logger, guestname), snapshotname),
            'acquire'
        ),
        doer_args=(snapshotname,)
    )


async def do_route_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    snapshotname: str
) -> None:
    with db.get_session() as session:
        def _undo_snapshot_in_creating() -> None:
            if _update_guest_state(
                logger,
                session,
                snapshotname,
                artemis.guest.GuestState.PROVISIONING,
                artemis.guest.GuestState.ROUTING
            ):
                return

            # We should never ever end up here, because:
            #
            # - undo worked => _update_snapshot_state returns True and we leave right above this comment
            # - undo failed because of unspecified exception -> the exception is reraised in _update_snapshot_state
            # - undo failed because there was no such record in db -> _update_snapshot_state returns False, which is not
            # possible...
            #
            # We are the only instance of this task that got this far. We were the only instance that managed to move
            # snapshot to PROVISIONING state, any other instance should see it alread has that state (or they fail to
            # change it), stopping their execution at that point. We should be the only instance that has anything to
            # undo.
            #
            # So, what changed the snapshot state if it haven't been any other instance of this task, and if we failed
            # to dispatch any provisioning task??
            assert False, 'unreachable'

        # First, pick up our assigned snapshot request. Make sure it hasn't been
        # processed yet.
        snapshot = _get_snapshot_by_state(logger, session, snapshotname, artemis.guest.GuestState.ROUTING)

        if not snapshot:
            return

        if cancel.is_set():
            return

        # Do stuff, examine request and send it a message.
        #
        # Be aware that while the request was free to take, it may be being processed by multiple instances of this
        # task at once - we didn't acquire any lock! We could either introduce locking, or we can continue and make
        # sure the request didn't change when we start commiting changes. And since asking or forgiveness is simpler
        # than asking for permission, let's continue but be prepared to clean up if someone else did the work instead
        # of us.

        # We are expecting, that guest is READY and active
        guest_request = _get_guest_by_state(logger, session, snapshot.guestname, artemis.guest.GuestState.READY)

        if not guest_request:
            return

        if cancel.is_set():
            return

        # Mark request as suitable for provisioning.
        if not _update_snapshot_state(
            logger,
            session,
            snapshotname,
            snapshot.guestname,
            artemis.guest.GuestState.ROUTING,
            artemis.guest.GuestState.CREATING,
            set_values={
                'poolname': guest_request.poolname
            }
        ):
            # We failed to move snapshot to CREATING state which means some other instance of this task changed
            # snapshot's state instead of us, which means we should throw everything away because our decisions no
            # longer matter.
            return

        # Fine, the query succeeded, which means we are the first instance of this task to move this far. For any other
        # instance, the state change will fail and they will bail while we move on and try to dispatch the provisioning
        # task.
        r = _dispatch_task(logger, create_snapshot, snapshotname, snapshot.guestname)
        logger.info('task was dispatched')

        if r.is_ok:
            return

        # We failed to dispatch the task, but we already marked the request as suitable for provisioning, which means
        # that any subsequent run of this task would not be able to evaluate it again since it's no longer in ROUTING
        # state. We should undo this change.
        #
        # On the other hand, we just cannot chain undos of undos indefinitely, so if this attempt fails, let's give up
        # and let humans solve the problems.
        _undo_snapshot_in_creating()


@dramatiq.actor(**actor_kwargs('ROUTE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def route_snapshot_request(snapshotname: str) -> None:
    task_core(  # type: ignore # Argument 1 has incompatible type
        do_route_snapshot_request,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.snapshot.SnapshotLogger(root_logger, snapshotname),
            'route'
        ),
        doer_args=(snapshotname,)
    )


async def do_restore_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    snapshotname: str
) -> None:
    with db.get_session() as session:
        def _undo_snapshot_restore() -> None:
            if _update_guest_state(
                logger,
                session,
                snapshotname,
                artemis.guest.GuestState.PROCESSING,
                artemis.guest.GuestState.RESTORING
            ):
                return

            assert False, 'unreachable'

        snapshot_request = _get_snapshot_by_state(logger, session, snapshotname, artemis.guest.GuestState.RESTORING)

        if not snapshot_request:
            return

        _, ERROR_EVENT = create_event_loggers(logger, session, snapshot_request.guestname, snapshotname=snapshotname)

        if _update_snapshot_state(
            logger,
            session,
            snapshotname,
            snapshot_request.guestname,
            artemis.guest.GuestState.RESTORING,
            artemis.guest.GuestState.PROCESSING
        ):
            logger.info('state changed to processing')

        if cancel.is_set():
            _undo_snapshot_restore()
            return

        guest_request = _get_guest_by_state(logger, session, snapshot_request.guestname, artemis.guest.GuestState.READY)

        if not guest_request:
            _undo_snapshot_restore()
            return

        assert snapshot_request.poolname is not None

        r_pool = _get_pool(logger, session, snapshot_request.poolname)

        if r_pool.is_error:
            ERROR_EVENT(r_pool, 'pool sanity failed')

            _undo_snapshot_restore()
            return

        pool = r_pool.unwrap()

        r_guest_sshkey = _get_ssh_key(
            logger,
            session,
            guest_request.ownername,
            guest_request.ssh_keyname
        )

        if r_guest_sshkey.is_error:
            ERROR_EVENT(r_guest_sshkey, 'failed to get SSH key')

            _undo_snapshot_restore()
            return

        guest_sshkey = r_guest_sshkey.unwrap()

        r_guest = pool.guest_factory(guest_request, ssh_key=guest_sshkey)
        if r_guest.is_error:
            ERROR_EVENT(r_guest, 'failed to load guest')

            _undo_snapshot_restore()
            return

        guest = r_guest.unwrap()

        if cancel.is_set():
            _undo_snapshot_restore()
            return

        r_restore = pool.restore_snapshot(snapshot_request, guest)

        if r_restore.is_error:
            _undo_snapshot_restore()

            error = r_restore.unwrap_error()

            ERROR_EVENT(
                r_restore,
                'failed to restore snapshot: {}'.format(error.message),
                environment=error.details.get('environment'),
                hook_error=error.details.get('hook_error')
            )

            raise Exception(error)

        if _update_snapshot_state(
            logger,
            session,
            snapshotname,
            snapshot_request.guestname,
            artemis.guest.GuestState.PROCESSING,
            artemis.guest.GuestState.READY
        ):
            logger.info('restored sucessfully')
            return

        # Failed to change the state means somebody else already did the provisioning. Or even canceled the request.
        # Again, we must undo and forget about the guest request.
        _undo_snapshot_restore()


@dramatiq.actor(**actor_kwargs('RESTORE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def restore_snapshot_request(snapshotname: str) -> None:
    task_core(  # type: ignore # Argument 1 has incompatible type
        do_restore_snapshot_request,
        logger_getter=lambda root_logger: TaskLogger(
            artemis.snapshot.SnapshotLogger(root_logger, snapshotname),
            'restore'
        ),
        doer_args=(snapshotname,)
    )
