import concurrent.futures
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

from . import Failure, get_db, get_logger, get_broker, safe_call, safe_db_execute, log_guest_event, \
    log_error_guest_event
from . import handle_failure as main_handle_failure
from .db import DB, GuestRequest, Pool, SnapshotRequest, SSHKey, Query
from .drivers import PoolDriver
from .environment import Environment
from .guest import Guest, GuestLogger, GuestState, GuestPoolDataType
from .script import hook_engine
from .snapshot import Snapshot, SnapshotLogger

from .drivers import aws as aws_driver
from .drivers import beaker as beaker_driver
from .drivers import openstack as openstack_driver

from typing import cast, Any, Callable, Dict, List, Optional, Tuple, Union
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
# So, futures to the rescue! Let's cheat a bit. Thread A will spawn - with the help of futures - new thread, B, which
# will run the actual code of the task. In thread A we'll have the executor instance, which, when receiving the
# asynchronous exceptions, would set "cancel?" event which was passed to the task doer in thread B. After that,
# thread A would continue waiting for thread B to finish.
#
# Thread B started running the task doer, and will check "canceled?" event from time to time. Should the event become
# set, it can safely unroll & quit. Asynchronous exceptions are delivered to the thread A, no need to fear them in
# thread B. We don't need to *kill* thread B when asynchronous exception arrived to thread A, we just need to tell it
# to quit as soon as possible.
#
# When thread B finishes, successfully or by raising an exception, its "return value" is "picked up" by thread A,
# possibly raising the original exception raised in thread B, giving thread A a chance to react to them even more.

#
# TODO:
# - support queue name when sending messages - we want our tasks to use different queues.
# - allow retries modification and tweaking
# - "lazy actor" wrapper to avoid the necessity of initializing dramatiq at the import time


# Initialize our top-level objects, database and logger, shared by all threads and in *this* worker.
root_logger = get_logger()
db = get_db(root_logger)

# Initialize the broker instance - this call takes core of correct connection between broker and queue manager.
_ = get_broker()


POOL_DRIVERS = {
    'aws': aws_driver.AWSDriver,
    'beaker': beaker_driver.BeakerDriver,
    'openstack': openstack_driver.OpenStackDriver
}


# A class of unique "reschedule task" doer return value
#
# Note: we could use object() to create this value, but using custom class let's use limit allowed types returned
# by doer.
class _RescheduleType:
    pass


# Unique object representing "reschedule task" return value of doer.
Reschedule = _RescheduleType()

# Doer return value type.
DoerReturnType = Result[Union[None, _RescheduleType], Failure]

# Helpers for constructing return values.
SUCCESS: DoerReturnType = Ok(None)
RESCHEDULE: DoerReturnType = Ok(Reschedule)


def FAIL(result: Result[Any, Failure]) -> DoerReturnType:
    return Error(result.unwrap_error())


# Task doer type.
class DoerType(Protocol):
    def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        *args: Any,
        **kwargs: Any
    ) -> DoerReturnType: ...


# Task actor type.
class Actor(Protocol):
    actor_name: str

    def send(
        self,
        *args: Any
    ) -> None: ...

    def send_with_options(
        self,
        args: Optional[Tuple[Any, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        delay: Optional[int] = None,
        **options: Any
    ) -> None: ...


# Types of functions we use to handle success and failures.
class SuccessHandlerType(Protocol):
    def __call__(
        self,
        eventname: str
    ) -> None: ...


class FailureHandlerType(Protocol):
    def __call__(
        self,
        result: Result[Any, Failure],
        label: str,
        sentry: bool = True
    ) -> DoerReturnType: ...


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


def create_event_handlers(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: Optional[str] = None,
    task: Optional[str] = None,
    **default_details: Any
) -> Tuple[SuccessHandlerType, FailureHandlerType, Dict[str, Any]]:
    """
    Return helper functions that take care of handling success and failure situations in tasks. These handlers take
    care of reporting the event:

    * create a guest event,
    * in case of failures, log the failure and submit it to Sentry.

    Third returned value is a "spice" mapping - all key: value entries added to this mapping will be added
    as extra details to all logs and failures.
    """

    spice_details: Dict[str, Any] = {**default_details}

    if task:
        spice_details['task'] = task

    def handle_success(
        eventname: str
    ) -> None:
        if guestname:
            log_guest_event(
                logger,
                session,
                guestname,
                eventname,
                **spice_details
            )

    def handle_failure(
        result: Result[Any, Failure],
        label: str,
        sentry: bool = True
    ) -> DoerReturnType:
        failure = result.unwrap_error()

        main_handle_failure(logger, result, label, sentry=sentry, **spice_details)

        if guestname:
            log_error_guest_event(
                logger,
                session,
                guestname,
                label,
                failure
            )

        return Error(failure)

    return handle_success, handle_failure, spice_details


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
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    fn: DoerType,
    *args: Any,
    **kwargs: Any
) -> DoerReturnType:
    """
    Run a given function - "doer" - isolated in its own thread. This thread then serves as a landing
    spot for dramatiq control exceptions (e.g. Shutdown).

    Control exceptions are delivered to the thread that runs the task. We don't want to interrupt
    the actual task code, which is hidden in the doer, so we offload it to a separate thread, catch
    exceptions here, and notify doer via "cancel" event.
    """

    executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
    doer_future: Optional[concurrent.futures.Future[DoerReturnType]] = None

    def _wait(message: str) -> None:
        """
        Wait for doer future to complete.

        Serves as a helper, to provide unified logging.
        """

        assert doer_future is not None

        while True:
            # We could drop timeout parameter, but it seems that without timeout in play, control exceptions
            # are delivered when blocking wait() finishes, which is obviously *after* the doer competes its
            # job - and that's too late for canceling anything, so not using timeout makes cancellation impossible.
            #
            # This is connected to GIL and how an exception can be delivered to a thread. So, we use timeout,
            # to interrupt wait() regularly, so we get a chance to receive exceptions and signal cancellation
            # to doer thread. The actual timeout length is pretty much pointless.
            done_futures, undone_futures = concurrent.futures.wait({doer_future}, timeout=10.0)

            gluetool.log.log_dict(logger.debug, 'doer futures', [done_futures, undone_futures])

            if len(undone_futures) != 0:
                logger.debug('doer is still running')
                continue

            break

        logger.debug(message)

        assert len(done_futures) == 1
        assert len(undone_futures) == 0
        assert doer_future in done_futures

    try:
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=threading.current_thread().name
        )

        logger.debug('submitting task doer {}'.format(fn))

        doer_future = executor.submit(fn, logger, db, session, cancel, *args, **kwargs)

        _wait('doer finished in regular mode')

    except dramatiq.middleware.Interrupt as exc:
        if isinstance(exc, dramatiq.middleware.TimeLimitExceeded):
            logger.error('task time depleted')

        elif isinstance(exc, dramatiq.middleware.Shutdown):
            logger.error('worker shutdown requested')

        else:
            assert False, 'Unhandled interrupt exception'

        logger.debug('entering doer cancellation mode')

        cancel.set()

        logger.debug('waiting for doer to finish')

        _wait('doer finished in cancellation mode')

    assert doer_future is not None
    assert doer_future.done(), 'doer finished yet not marked as done'

    if executor:
        executor.shutdown()

    return doer_future.result()


def task_core(
    doer: DoerType,
    logger: TaskLogger,
    doer_args: Optional[Tuple[Any, ...]] = None,
    doer_kwargs: Optional[Dict[str, Any]] = None
) -> None:
    logger.begin()

    cancel = threading.Event()

    doer_args = doer_args or tuple()
    doer_kwargs = doer_kwargs or dict()

    doer_result: DoerReturnType = Error(Failure('undefined doer result'))

    try:
        with db.get_session() as session:
            doer_result = run_doer(logger, db, session, cancel, doer, *doer_args, **doer_kwargs)

    except Exception as exc:
        stackprinter.show_current_exception()
        failure = Failure.from_exc('unhandled doer exception', exc)
        failure.log(logger.error)

        doer_result = Error(failure)

    if doer_result.is_ok:
        result = doer_result.unwrap()

        logger.finished()

        if result is Reschedule:
            raise Exception('message processing requested reschedule')

        return

    # To avoid chain a of exceptions in the log - which we already logged above - raise a generic,
    # insignificant exception to notify scheduler that this task failed and needs to be retried.
    raise Exception('message processing failed: {}'.format(doer_result.unwrap_error().message))


def _cancel_task_if(
    logger: gluetool.log.ContextAdapter,
    cancel: threading.Event,
    undo: Optional[Callable[[], None]] = None
) -> bool:
    """
    Check given cancellation event, and if it's set, call given (optional) undo callback.

    Returns ``True`` if task is supposed to be cancelled, ``False`` otherwise.
    """

    if not cancel.is_set():
        logger.debug('cancellation not requested')
        return False

    logger.warning('cancellation requested')

    if undo:
        logger.debug('running undo step')

        undo()

    return True


def _dispatch_task(
    logger: gluetool.log.ContextAdapter,
    task: Actor,
    *args: Any,
    delay: Optional[int] = None
) -> Result[None, Failure]:
    if delay is None:
        r = safe_call(task.send, *args)

    else:
        r = safe_call(task.send_with_options, args=args, delay=delay)

    if r.is_ok:
        formatted_args = [
            str(arg) for arg in args
        ]

        if delay is not None:
            formatted_args += [
                'delay={}'.format(delay)
            ]

        logger.info('scheduled task {}({})'.format(
            task.actor_name,
            ', '.join(formatted_args)
        ))

        return Ok(None)

    return Error(Failure(
        'failed to dispatch task',
        caused_by=r.unwrap_error(),
        task_name=task.actor_name,
        task_args=args,
        task_delay=delay
    ))


def _get_guest_request(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str
) -> Result[Optional[GuestRequest], Failure]:
    query_proxy = Query.from_session(session, GuestRequest) \
        .filter(GuestRequest.guestname == guestname)

    r_query = cast(
        Result[GuestRequest, Failure],
        safe_call(query_proxy.one)
    )

    if r_query.is_ok:
        return Ok(r_query.unwrap())

    failure = r_query.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        return Ok(None)

    return Error(failure)


def _get_guest_by_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    state: GuestState
) -> Result[Optional[GuestRequest], Failure]:
    query_proxy = Query.from_session(session, GuestRequest) \
        .filter(GuestRequest.guestname == guestname) \
        .filter(GuestRequest.state == state.value)

    r_query = cast(
        Result[GuestRequest, Failure],
        safe_call(query_proxy.one)
    )

    if r_query.is_ok:
        return Ok(r_query.unwrap())

    failure = r_query.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(state.value))
        return Ok(None)

    return Error(failure)


def _get_snapshot_by_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshotname: str,
    state: GuestState
) -> Result[Optional[SnapshotRequest], Failure]:
    query_proxy = Query.from_session(session, SnapshotRequest) \
        .filter(SnapshotRequest.snapshotname == snapshotname) \
        .filter(SnapshotRequest.state == state.value)

    r_query = cast(
        Result[SnapshotRequest, Failure],
        safe_call(query_proxy.one)
    )

    if r_query.is_ok:
        return Ok(r_query.unwrap())

    failure = r_query.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(state.value))
        return Ok(None)

    return Error(failure)


def _update_guest_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    current_state: GuestState,
    new_state: GuestState,
    guest: Optional[Guest] = None,
    set_values: Optional[Dict[str, Any]] = None,
    current_pool_data: Optional[GuestPoolDataType] = None,
    **details: Any
) -> Result[bool, Failure]:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        current_state=current_state.value,
        new_state=new_state.value,
        **details
    )

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

    if current_pool_data:
        query = sqlalchemy \
            .update(GuestRequest.__table__) \
            .where(GuestRequest.guestname == guestname) \
            .where(GuestRequest.state == current_state.value) \
            .where(GuestRequest.pool_data == Guest.pool_data_to_db(current_pool_data)) \
            .values(**values)

    else:
        query = sqlalchemy \
            .update(GuestRequest.__table__) \
            .where(GuestRequest.guestname == guestname) \
            .where(GuestRequest.state == current_state.value) \
            .values(**values)

    r = safe_db_execute(logger, session, query)

    if r.is_ok:
        if r.value is True:
            logger.warning('state switch: {} => {}: succeeded'.format(current_state.value, new_state.value))

            handle_success('state-changed')

        else:
            logger.warning('state switch: {} => {}: failed'.format(current_state.value, new_state.value))

            handle_failure(
                Error(Failure('failed to switch guest state')),
                'failed to switch guest state'
            )

        return Ok(r.unwrap())

    failure = r.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('state switch: {} => {}: no result found'.format(current_state.value, new_state.value))

        return Ok(False)

    return Error(failure)


def _update_snapshot_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshotname: str,
    guestname: str,
    current_state: GuestState,
    new_state: GuestState,
    set_values: Optional[Dict[str, Any]] = None,
    **details: Any
) -> Result[bool, Failure]:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        snapshotname=snapshotname,
        current_state=current_state.value,
        new_state=new_state.value,
        **details
    )

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
        if r.value is True:
            logger.warning('state switch: {} => {}: succeeded'.format(current_state.value, new_state.value))

            handle_success('snapshot-state-changed')

        else:
            logger.warning('state switch: {} => {}: failed'.format(current_state.value, new_state.value))

            handle_failure(Error(Failure('failed to switch snapshot state')), 'failed to switch snapshot state')

        return Ok(r.unwrap())

    failure = r.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('state switch: {} => {}: no result found'.format(current_state.value, new_state.value))

        return Ok(False)

    return Error(failure)


def _get_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    poolname: str
) -> Result[PoolDriver, Failure]:
    try:
        pool_record = Query.from_session(session, Pool) \
            .filter(Pool.poolname == poolname) \
            .one()

    except sqlalchemy.orm.exc.NoResultFound:
        raise Exception('no such pool "{}"'.format(poolname))

    pool_driver_class = POOL_DRIVERS[pool_record.driver]
    driver = pool_driver_class(logger, poolname, json.loads(pool_record.parameters))

    r_sanity = driver.sanity()

    if r_sanity.is_error:
        return Error(r_sanity.unwrap_error())

    return Ok(driver)


def get_pools(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> List[PoolDriver]:
    pools: List[PoolDriver] = []

    for pool_record in Query.from_session(session, Pool).all():
        pool_driver_class = POOL_DRIVERS[pool_record.driver]

        pools += [
            pool_driver_class(logger, pool_record.poolname, json.loads(pool_record.parameters))
        ]

    return pools


def _get_ssh_key(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    ownername: str,
    keyname: str
) -> Result[SSHKey, Failure]:
    try:
        return Ok(
            Query.from_session(session, SSHKey)
            .filter(
                SSHKey.ownername == ownername,
                SSHKey.keyname == keyname
            )
            .one()
        )

    except sqlalchemy.orm.exc.NoResultFound:
        return Error(Failure('no key {}:{}'.format(ownername, keyname)))


def _get_master_key(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> Result[SSHKey, Failure]:
    return _get_ssh_key(logger, session, 'artemis', 'master-key')


def get_guest_logger(
    task_name: str,
    root_logger: gluetool.log.ContextAdapter,
    guestname: str
) -> TaskLogger:
    return TaskLogger(
        GuestLogger(root_logger, guestname),
        task_name
    )


def get_snapshot_logger(
    task_name: str,
    root_logger: gluetool.log.ContextAdapter,
    guestname: str,
    snapshotname: str
) -> TaskLogger:
    return TaskLogger(
        SnapshotLogger(
            GuestLogger(root_logger, guestname),
            snapshotname
        ),
        task_name
    )


class Workspace:
    """
    A workspace is a container for tools commonly used by task doers - a workdesk, a drawer with hammers and
    screwdrivers, ready for task to help with common operations, so they perform these operations in the same
    way.

    Workspace takes care of executing given operation, evaluating the returned promise, handling failure
    and so on. The biggest advatage is that this outcome is stored in the workspace, and any consecutive
    operation called will become no-op if any previous operation outcome wasn't a success.

    This allows for chaining of calls, checking the result once at the end:

    .. code::

       workspace.load_guest_request()
       workspace.load_ssh_key()
       workspace.load_gr_pool()

       if workspace.result:
           return workspace.result

    If ``load_guest_request`` failed, it'd set ``workspace.result`` to a proper ``FAIL`` instance, suitable
    for immediate return by a task doer, ``load_ssh_key`` and ``load_gr_pool`` wouldn't do *anything* - both
    would return immediately. So, no need to deal with the intermediate results and spaghetti code in each task.

    On top of that, ``workspace.result`` is compatible with doer return values, so it can be immediately returned,
    as each failure was already handled inside workspace.
    """

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        handle_failure: FailureHandlerType
    ) -> None:
        self.logger = logger
        self.session = session
        self.cancel = cancel
        self.handle_failure = handle_failure

        self.result: Optional[DoerReturnType] = None

        self.guestname: Optional[str] = None
        self.snapshotname: Optional[str] = None

        self.gr: Optional[GuestRequest] = None
        self.sr: Optional[SnapshotRequest] = None
        self.ssh_key: Optional[SSHKey] = None
        self.pool: Optional[PoolDriver] = None
        self.guest: Optional[Guest] = None
        self.snapshot: Optional[Snapshot] = None

    def load_guest_request(self, guestname: str, state: Optional[GuestState] = None) -> None:
        """
        Load a guest request from a database, as long as it is in a given state.

        **OUTCOMES:**

          * ``SUCCESS`` if guest doesn't exist or it isn't in a given state
          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``guestname``
          * ``gr``
        """

        if self.result:
            return

        self.guestname = guestname

        if state is None:
            r = _get_guest_request(self.logger, self.session, guestname)

        else:
            r = _get_guest_by_state(self.logger, self.session, guestname, state)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to load guest request')
            return

        gr = r.unwrap()

        if not gr:
            self.result = SUCCESS
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.gr = gr

    def load_snapshot_request(self, snapshotname: str, state: GuestState) -> None:
        """
        Load a snapshot request from a database, as long as it is in a given state.

        **OUTCOMES:**

          * ``SUCCESS`` if snapshot doesn't exist or it isn't in a given state
          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``snapshotname``
          * ``sr``
        """

        if self.result:
            return

        self.snapshotname = snapshotname

        r = _get_snapshot_by_state(self.logger, self.session, snapshotname, state)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to load snapshot request')
            return

        sr = r.unwrap()

        if not sr:
            self.result = SUCCESS
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.sr = sr

    def load_ssh_key(self) -> None:
        """
        Load a SSH key specified by a guest request from a database.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``ssh_key``
        """

        if self.result:
            return

        assert self.gr

        r = _get_ssh_key(
            self.logger,
            self.session,
            self.gr.ownername,
            self.gr.ssh_keyname
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to get SSH key')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.ssh_key = r.unwrap()

    def load_gr_pool(self) -> None:
        """
        Load a pool as specified by a guest request.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``pool``
        """

        if self.result:
            return

        assert self.gr
        assert self.gr.poolname is not None

        r = _get_pool(self.logger, self.session, self.gr.poolname)

        if r.is_error:
            self.result = self.handle_failure(r, 'pool sanity failed')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.pool = r.unwrap()

    def load_sr_pool(self) -> None:
        """
        Load a pool as specified by a snapshot request.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``pool``
        """

        if self.result:
            return

        assert self.sr
        assert self.sr.poolname is not None

        r = _get_pool(self.logger, self.session, self.sr.poolname)

        if r.is_error:
            self.result = self.handle_failure(r, 'pool sanity failed')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.pool = r.unwrap()

    def load_guest(self) -> None:
        """
        Load a guest described by a guest request.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``guest``
        """

        if self.result:
            return

        assert self.gr
        assert self.ssh_key
        assert self.pool

        r = self.pool.guest_factory(self.gr, ssh_key=self.ssh_key)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to load guest')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.guest = r.unwrap()

    def load_snapshot(self) -> None:
        """
        Load a snapshot described by a snapshot request.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``snapshot``
        """

        if self.result:
            return

        assert self.sr
        assert self.pool

        r = self.pool.snapshot_factory(self.sr)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to load snapshot')

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.snapshot = r.unwrap()

    def update_guest_state(self, *args: Any, **kwargs: Any) -> None:
        """
        Updates guest state with given values.

        **OUTCOMES:**

          * ``FAIL``
        """

        if self.result:
            return

        assert self.guestname

        r = _update_guest_state(
            self.logger,
            self.session,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to update guest request')
            return

        if not r.unwrap():
            self.result = self.handle_failure(Error(Failure('foo')), 'failed to update guest state')
            return

    def update_snapshot_state(self, *args: Any, **kwargs: Any) -> None:
        """
        Updates snapshot state with given values.

        **OUTCOMES:**

          * ``FAIL``
        """

        if self.result:
            return

        assert self.snapshotname
        assert self.guestname

        r = _update_snapshot_state(
            self.logger,
            self.session,
            self.snapshotname,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to update snapshot request')
            return

        if not r.unwrap():
            self.result = self.handle_failure(Error(Failure('foo')), 'failed to update guest state')
            return

    def grab_guest_request(self, *args: Any, **kwargs: Any) -> None:
        """
        "Grab" the guest for task by changing its state.

        **OUTCOMES:**

          * ``SUCCESS`` if the guest does not exist or is not in the given state.
          * ``FAIL``
        """

        if self.result:
            return

        assert self.guestname

        r = _update_guest_state(
            self.logger,
            self.session,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to grab guest request')
            return

        if not r.unwrap():
            self.result = SUCCESS
            return

    def grab_snapshot_request(self, *args: Any, **kwargs: Any) -> None:
        """
        "Grab" the snapshot for task by changing its state.

        **OUTCOMES:**

          * ``SUCCESS`` if the guest does not exist or is not in the given state.
          * ``FAIL``
        """

        if self.result:
            return

        assert self.snapshotname
        assert self.guestname

        r = _update_snapshot_state(
            self.logger,
            self.session,
            self.snapshotname,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to grab snapshot request')
            return

        if not r.unwrap():
            self.result = SUCCESS
            return

    def ungrab_guest_request(self, *args: Any, **kwargs: Any) -> None:
        assert self.guestname

        r = _update_guest_state(
            self.logger,
            self.session,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to ungrab guest request')
            return

        if r.unwrap():
            return

        assert False, 'unreachable'

    def ungrab_snapshot_request(self, *args: Any, **kwargs: Any) -> None:
        assert self.snapshotname
        assert self.guestname

        r = _update_snapshot_state(
            self.logger,
            self.session,
            self.snapshotname,
            self.guestname,
            *args,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to ungrab snapshot request')
            return

        if r.unwrap():
            return

        assert False, 'unreachable'

    def dispatch_task(self, task: Actor, *args: Any) -> None:
        if self.result:
            return

        r = _dispatch_task(self.logger, task, *args)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to dispatch update task')
            return

    def run_hook(self, hook_name: str, **kwargs: Any) -> Any:
        r_engine = hook_engine(hook_name)

        if r_engine.is_error:
            self.result = self.handle_failure(r_engine, 'failed to load {} hook'.format(hook_name))
            return

        engine = r_engine.unwrap()

        r = engine.run_hook(
            hook_name,
            logger=self.logger,
            **kwargs
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'hook failed')
            return

        return r.unwrap()


def do_release_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='release-guest'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.CONDEMNED)
    workspace.grab_guest_request(GuestState.CONDEMNED, GuestState.RELEASING)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    if workspace.gr.poolname:
        spice_details['poolname'] = workspace.gr.poolname

        workspace.load_gr_pool()
        workspace.load_ssh_key()

        if workspace.result:
            workspace.ungrab_guest_request(GuestState.RELEASING, GuestState.CONDEMNED)

            return workspace.result

        workspace.load_guest()

        # If we cancelled the guest early, no provisioned guest is available
        if workspace.result:
            pass

        # This can happen if somebody removed the instance outside of Artemis
        else:
            assert workspace.pool
            assert workspace.guest

            r_release = workspace.pool.release_guest(workspace.guest)

            if r_release.is_error:
                handle_failure(r_release, 'failed to release guest')

    query = sqlalchemy \
        .delete(GuestRequest.__table__) \
        .where(GuestRequest.guestname == guestname) \
        .where(GuestRequest.state == GuestState.RELEASING.value)

    r_delete = safe_db_execute(logger, session, query)

    if r_delete.is_ok:
        handle_success('released')

        return SUCCESS

    failure = r_delete.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in RELEASING state anymore')

        return SUCCESS

    workspace.ungrab_guest_request(GuestState.RELEASING, GuestState.CONDEMNED)

    return handle_failure(r_delete, 'failed to release guest')


@dramatiq.actor(**actor_kwargs('RELEASE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def release_guest_request(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_release_guest_request,
        logger=get_guest_logger('release', root_logger, guestname),
        doer_args=(guestname,)
    )


def do_update_guest(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='update-guest'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PROMISED)
    workspace.load_ssh_key()
    workspace.load_gr_pool()
    workspace.load_guest()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.pool
    assert workspace.ssh_key
    assert workspace.guest

    spice_details['poolname'] = workspace.gr.poolname
    current_pool_data = Guest.pool_data_from_db(workspace.gr)

    def _undo_guest_update(guest: Guest) -> None:
        assert workspace.pool

        r = workspace.pool.release_guest(guest)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo guest update')

    environment = Environment.unserialize_from_json(json.loads(workspace.gr.environment))

    r_update = workspace.pool.update_guest(workspace.gr, environment, workspace.ssh_key)

    if r_update.is_error:
        return handle_failure(r_update, 'failed to update guest')

    guest = r_update.unwrap()

    if guest.is_promised:
        workspace.update_guest_state(
            GuestState.PROMISED,
            GuestState.PROMISED,
            guest=guest,
            set_values={
                'pool_data': Guest.pool_data_to_db(guest.pool_data)
            },
            current_pool_data=current_pool_data
        )

        workspace.dispatch_task(update_guest, guestname)

        if workspace.result:
            _undo_guest_update(guest)

            return workspace.result

        logger.info('scheduled update')

        return SUCCESS

    workspace.update_guest_state(
        GuestState.PROMISED,
        GuestState.READY,
        guest=guest,
        set_values={
            'address': guest.address,
            'pool_data': Guest.pool_data_to_db(guest.pool_data)
        },
        current_pool_data=current_pool_data
    )

    if workspace.result:
        _undo_guest_update(guest)

        return workspace.result

    logger.info('successfully acquired')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('UPDATE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def update_guest(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_update_guest,
        logger=get_guest_logger('update', root_logger, guestname),
        doer_args=(guestname,)
    )


def do_acquire_guest(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    poolname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='acquire-guest',
        poolname=poolname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PROVISIONING)
    workspace.load_ssh_key()
    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.pool
    assert workspace.ssh_key

    environment = Environment.unserialize_from_json(json.loads(workspace.gr.environment))

    result = workspace.pool.acquire_guest(logger, workspace.gr, environment, workspace.ssh_key, cancelled=cancel)

    if result.is_error:
        return handle_failure(result, 'failed to provision')

    guest = result.unwrap()

    def _undo_guest_acquire() -> None:
        assert workspace.pool

        r = workspace.pool.release_guest(guest)

        if r.is_ok:
            return

        raise Exception(r.error)

    # TODO: instead of switching to READY, we need to switch into transient state instead,
    # and upload the requested key to the guest (using our master key).

    # We have a guest, we can move the guest record to the next state. The guest may be unfinished,
    # in that case we should schedule a task for driver's update_guest method. Otherwise, we must
    # save guest's address. In both cases, we must be sure nobody else did any changes before us.
    if guest.is_promised:
        workspace.update_guest_state(
            GuestState.PROVISIONING,
            GuestState.PROMISED,
            guest=guest,
            set_values={
                'pool_data': Guest.pool_data_to_db(guest.pool_data)
            }
        )

        workspace.dispatch_task(update_guest, guestname)

        if workspace.result:
            _undo_guest_acquire()

            return workspace.result

        logger.info('scheduled update')

        return SUCCESS

    workspace.update_guest_state(
        GuestState.PROVISIONING,
        GuestState.READY,
        guest=guest,
        set_values={
            'address': guest.address,
            'pool_data': Guest.pool_data_to_db(guest.pool_data)
        },
        address=guest.address,
        pool=workspace.gr.poolname,
        pool_data=guest.pool_data
    )

    if workspace.result:
        _undo_guest_acquire()

        return workspace.result

    logger.info('successfully acquired')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('ACQUIRE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def acquire_guest(guestname: str, poolname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_acquire_guest,
        logger=get_guest_logger('acquire', root_logger, guestname),
        doer_args=(guestname, poolname)
    )


def do_route_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='route-guest'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)

    # First, pick up our assigned guest request. Make sure it hasn't been
    # processed yet.
    workspace.load_guest_request(guestname, state=GuestState.ROUTING)

    if workspace.result:
        return workspace.result

    # Do stuff, examine request, pick the provisioner, and send it a message.
    #
    # Be aware that while the request was free to take, it may be being processed by multiple instances of this
    # task at once - we didn't acquire any lock! We could either introduce locking, or we can continue and make
    # sure the request didn't change when we start commiting changes. And since asking for forgiveness is simpler
    # than asking for permission, let's continue but be prepared to clean up if someone else did the work instead
    # of us.

    logger.info('finding suitable provisioner')

    pool = workspace.run_hook(
        'ROUTE',
        guest_request=workspace.gr,
        pools=get_pools(logger, session)
    )

    # Route hook failed, request cannot be fulfilled ;(
    if workspace.result:
        return workspace.result

    # No suitable pool found
    if not pool:
        return RESCHEDULE

    if _cancel_task_if(logger, cancel):
        return RESCHEDULE

    # Mark request as suitable for provisioning.
    workspace.update_guest_state(
        GuestState.ROUTING,
        GuestState.PROVISIONING,
        set_values={
            'poolname': pool.poolname
        },
        pool=pool.poolname
    )

    if workspace.result:
        # We failed to move guest to PROVISIONING state which means some other instance of this task changed
        # guest's state instead of us, which means we should throw everything away because our decisions no
        # longer matter.
        return SUCCESS

    # Fine, the query succeeded, which means we are the first instance of this task to move this far. For any other
    # instance, the state change will fail and they will bail while we move on and try to dispatch the provisioning
    # task.
    workspace.dispatch_task(acquire_guest, guestname, pool.poolname)

    if workspace.result:
        workspace.ungrab_guest_request(GuestState.PROVISIONING, GuestState.ROUTING)

        return workspace.result

    logger.info('scheduled provisioning')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('ROUTE_GUEST_REQUEST'))  # type: ignore  # Untyped decorator
def route_guest_request(guestname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_route_guest_request,
        logger=get_guest_logger('route', root_logger, guestname),
        doer_args=(guestname,)
    )


def do_release_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    snapshotname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='release-snapshot',
        snapshotname=snapshotname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname)
    workspace.load_snapshot_request(snapshotname, GuestState.CONDEMNED)
    workspace.grab_snapshot_request(GuestState.CONDEMNED, GuestState.RELEASING)

    if workspace.result:
        return workspace.result

    def _undo_grab() -> None:
        workspace.ungrab_snapshot_request(GuestState.RELEASING, GuestState.CONDEMNED)

    assert workspace.sr

    if workspace.sr.poolname:
        spice_details['poolname'] = workspace.sr.poolname

        workspace.load_sr_pool()
        workspace.load_snapshot()

        if workspace.result:
            _undo_grab()

            return workspace.result

    query = sqlalchemy \
        .delete(SnapshotRequest.__table__) \
        .where(SnapshotRequest.snapshotname == snapshotname) \
        .where(SnapshotRequest.state == GuestState.RELEASING.value)

    r_delete = safe_db_execute(logger, session, query)

    if r_delete.is_ok:
        handle_success('snapshot-released')

        return SUCCESS

    failure = r_delete.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in RELEASING state anymore')

        return SUCCESS

    _undo_grab()

    return handle_failure(r_delete, 'failed to release snapshot')


@dramatiq.actor(**actor_kwargs('RELEASE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def release_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_release_snapshot_request,
        logger=get_snapshot_logger('release-snapshot', root_logger, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_update_snapshot(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    snapshotname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='update-snapshot',
        snapshotname=snapshotname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.PROMISED)
    workspace.load_guest_request(guestname, state=GuestState.READY)
    workspace.load_sr_pool()
    workspace.load_ssh_key()
    workspace.load_guest()
    workspace.load_snapshot()

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.snapshot
    assert workspace.guest
    assert workspace.pool

    r_update = workspace.pool.update_snapshot(
        workspace.snapshot,
        workspace.guest,
        start_again=workspace.sr.start_again
    )

    if r_update.is_error:
        return handle_failure(r_update, 'failed to update snapshot')

    snapshot = r_update.unwrap()

    def _undo_snapshot_update(snapshot: Snapshot) -> None:
        assert workspace.pool

        r = workspace.pool.remove_snapshot(snapshot)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo guest update')

    if snapshot.is_promised:
        workspace.update_snapshot_state(
            GuestState.PROMISED,
            GuestState.PROMISED,
        )

        workspace.dispatch_task(update_snapshot, guestname, snapshotname)

        if workspace.result:
            _undo_snapshot_update(snapshot)

            return workspace.result

        logger.info('scheduled update')

        return SUCCESS

    workspace.update_snapshot_state(
        GuestState.PROMISED,
        GuestState.READY
    )

    if workspace.result:
        _undo_snapshot_update(snapshot)

        return workspace.result

    logger.info('successfully created')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('UPDATE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def update_snapshot(guestname: str, snapshotname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_update_snapshot,
        logger=get_snapshot_logger('update-snapshot', root_logger, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_create_snapshot(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    snapshotname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='create-snapshot',
        snapshotname=snapshotname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.CREATING)
    workspace.load_guest_request(guestname, state=GuestState.READY)

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.gr

    # When can this happen?
    if not workspace.sr.poolname:
        return RESCHEDULE

    workspace.load_sr_pool()
    workspace.load_ssh_key()
    workspace.load_guest()

    if workspace.result:
        return workspace.result

    assert workspace.pool
    assert workspace.ssh_key
    assert workspace.guest

    r_create = workspace.pool.create_snapshot(workspace.sr, workspace.guest)

    if r_create.is_error:
        return handle_failure(r_create, 'failed to create snapshot')

    snapshot = r_create.unwrap()

    def _undo_snapshot_create() -> None:
        assert workspace.pool

        r = workspace.pool.remove_snapshot(snapshot)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo snapshot create')

    if snapshot.is_promised:
        workspace.update_snapshot_state(
            GuestState.CREATING,
            GuestState.PROMISED,
        )

        workspace.dispatch_task(update_snapshot, guestname, snapshotname)

        if workspace.result:
            _undo_snapshot_create()

            return workspace.result

        logger.info('scheduled update')

        return SUCCESS

    workspace.update_snapshot_state(
        GuestState.CREATING,
        GuestState.READY
    )

    if workspace.result:
        _undo_snapshot_create()

        return workspace.result

    logger.info('successfully created')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('CREATE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def create_snapshot(guestname: str, snapshotname: str) -> None:
    task_core(  # type: ignore  # Argument 1 has incompatible type
        do_create_snapshot,
        logger=get_snapshot_logger('acquire-snapshot', root_logger, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_route_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    snapshotname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='route-snapshot',
        snapshotname=snapshotname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.ROUTING)
    workspace.load_guest_request(guestname, state=GuestState.READY)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    workspace.grab_snapshot_request(
        GuestState.ROUTING,
        GuestState.CREATING,
        set_values={
            'poolname': workspace.gr.poolname
        }
    )

    if workspace.result:
        return workspace.result

    workspace.dispatch_task(create_snapshot, guestname, snapshotname)

    if workspace.result:
        workspace.ungrab_guest_request(GuestState.CREATING, GuestState.ROUTING)

        return workspace.result

    logger.info('scheduled creation')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('ROUTE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def route_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(  # type: ignore # Argument 1 has incompatible type
        do_route_snapshot_request,
        logger=get_snapshot_logger('route-snapshot', root_logger, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_restore_snapshot_request(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    snapshotname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='restore-snapshot',
        snapshotname=snapshotname
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.RESTORING)
    workspace.load_guest_request(guestname, state=GuestState.READY)
    workspace.grab_snapshot_request(GuestState.RESTORING, GuestState.PROCESSING)

    if workspace.result:
        return workspace.result

    workspace.load_sr_pool()
    workspace.load_ssh_key()
    workspace.load_guest()

    if workspace.result:
        workspace.ungrab_snapshot_request(GuestState.PROCESSING, GuestState.RESTORING)

        return workspace.result

    assert workspace.sr
    assert workspace.pool
    assert workspace.guest

    r_restore = workspace.pool.restore_snapshot(workspace.sr, workspace.guest)

    if r_restore.is_error:
        workspace.ungrab_snapshot_request(GuestState.PROCESSING, GuestState.RESTORING)

        return FAIL(r_restore)

    workspace.update_snapshot_state(
        GuestState.PROCESSING,
        GuestState.READY
    )

    if workspace.result:
        workspace.ungrab_snapshot_request(GuestState.PROCESSING, GuestState.RESTORING)

        return workspace.result

    logger.info('restored sucessfully')

    return SUCCESS


@dramatiq.actor(**actor_kwargs('RESTORE_SNAPSHOT_REQUEST'))  # type: ignore  # Untyped decorator
def restore_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(  # type: ignore # Argument 1 has incompatible type
        do_restore_snapshot_request,
        logger=get_snapshot_logger('restore-snapshot', root_logger, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )
