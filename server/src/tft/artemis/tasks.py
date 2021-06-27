import concurrent.futures
import contextvars
import datetime
import enum
import json
import os
import random
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast

import dramatiq
import gluetool.log
import periodiq
import sqlalchemy
import sqlalchemy.dialects.postgresql
import sqlalchemy.orm.exc
import sqlalchemy.orm.session
import stackprinter
from gluetool.result import Error, Ok, Result
from typing_extensions import Protocol

from . import KNOB_POOL_ENABLED, Failure, Knob, get_broker, get_db, get_logger, log_error_guest_event, \
    log_guest_event, metrics, safe_call, safe_db_change
from .context import DATABASE, LOGGER, SESSION, with_context
from .db import DB, GuestEvent, GuestLog, GuestLogContentType, GuestLogState, GuestRequest, Pool, SafeQuery, \
    SnapshotRequest, SSHKey, upsert
from .drivers import PoolData, PoolDriver, PoolLogger, ProvisioningState
from .drivers import aws as aws_driver
from .drivers import azure as azure_driver
from .drivers import beaker as beaker_driver
from .drivers import openstack as openstack_driver
from .guest import GuestLogger, GuestState, SnapshotLogger
from .routing_policies import PolicyRuling
from .script import hook_engine

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

# Initialize our top-level objects, database and logger, shared by all threads and in *this* worker.
_ROOT_LOGGER = get_logger()

_ROOT_DB: Optional[DB] = None


def get_root_db(logger: Optional[gluetool.log.ContextAdapter] = None) -> DB:
    global _ROOT_DB

    logger = logger or _ROOT_LOGGER

    if _ROOT_DB is None:
        _ROOT_DB = get_db(logger, application_name='artemis-worker')

    return _ROOT_DB


# Initialize the broker instance - this call takes core of correct connection between broker and queue manager.
BROKER = get_broker()


class TaskPriority(enum.Enum):
    """
    Task priorities.

    "The lower the numeric value, the higher priority!"
    """

    LOW = 300
    DEFAULT = 200
    HIGH = 100


class TaskQueue(enum.Enum):
    """
    Task queues.
    """

    DEFAULT = 'default'
    PERIODIC = 'periodic'
    POOL_DATA_REFRESH = 'pool-data-refresh'


def cast_priority(raw_value: str) -> int:
    # First, try to find corresponding `TaskPriority` member.
    try:
        return cast(int, TaskPriority[raw_value.upper()].value)

    except KeyError:
        pass

    # If we failed, the priority might be just an integer, a priority itself.
    try:
        return int(raw_value)

    except ValueError:
        pass

    # None of the above: report issue, but proceed with the default priority instead.
    Failure('unknown task priority', priority=raw_value).handle(_ROOT_LOGGER)

    return TaskPriority.DEFAULT.value


def cast_queue(raw_value: str) -> str:
    # First, try to match the given value with a defined queue.
    try:
        return cast(str, TaskQueue[raw_value.upper()].value)

    except KeyError:
        pass

    # Yep, not in our list, but that doesn't meen it's forbidden to use it. Keep the input.
    return raw_value


KNOB_ACTOR_DEFAULT_RETRIES_COUNT: Knob[int] = Knob(
    'actor.default-retries-count',
    'A number of time a failing task get retried. Serves as a default value for tasks without custom setting.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_RETRIES',
    cast_from_str=int,
    default=5
)

KNOB_ACTOR_DEFAULT_MIN_BACKOFF: Knob[int] = Knob(
    'actor.default-min-backoff',
    'The lowest possible delay, in seconds, before the next attempt to run a failed task.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_MIN_BACKOFF',
    cast_from_str=int,
    default=15
)

KNOB_ACTOR_DEFAULT_MAX_BACKOFF: Knob[int] = Knob(
    'actor.default-max-backoff',
    'The biggest possible delay, in seconds, before the next attempt to run a failed task.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_MAX_BACKOFF',
    cast_from_str=int,
    default=60
)

KNOB_ACTOR_DEFAULT_PRIORITY: Knob[int] = Knob(
    'actor.default-priority',
    'Task priority ("HIGH", "DEFAULT", "LOW" or any positive integer).',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_PRIORITY',
    cast_from_str=cast_priority,
    default=TaskPriority.DEFAULT.value
)

KNOB_ACTOR_DEFAULT_QUEUE: Knob[str] = Knob(
    'actor.default-queue',
    'Task queue ("default", "periodic", "pool-data-refresh" or any other string).',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_QUEUE',
    cast_from_str=cast_queue,
    default=TaskQueue.DEFAULT.value
)

KNOB_CLOSE_AFTER_DISPATCH: Knob[bool] = Knob(
    'broker.close-after-dispatch',
    'When enabled, broker connection will be forcefully closed after every message dispatch.',
    has_db=False,
    envvar='ARTEMIS_CLOSE_AFTER_DISPATCH',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_DISPATCH_PREPARE_DELAY: Knob[int] = Knob(
    'actor.dispatch-preparing.delay',
    """
    A delay, in second, between successful acquire of a cloud instance
    and dispatching of post-acquire preparation tasks.
    """,
    has_db=False,
    envvar='ARTEMIS_ACTOR_DISPATCH_PREPARE_DELAY',
    cast_from_str=int,
    default=60
)

KNOB_DELAY_UNIFORM_SPREAD: Knob[int] = Knob(
    'actor.delay-uniform-spread',
    'A range, in seconds, by which can a task delay be modified before use.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DELAY_UNIFORM_SPREAD',
    cast_from_str=int,
    default=5
)

KNOB_REFRESH_POOL_RESOURCES_METRICS_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-resources-metrics.schedule',
    'When to run pool image info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_RESOURCES_METRICS_SCHEDULE',
    cast_from_str=str,
    default='* * * * *'
)


KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-image-info.schedule',
    'When to run pool image info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_IMAGE_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *'
)


KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'actor.verify-ssh.connect-timeout',
    'Prepare stage SSH timeout.',
    per_pool=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15
)


KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-flavor-info.schedule',
    'When to run OpenStack flavor info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_FLAVOR_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *'
)

#: A delay, in second, between successful acquire of a cloud instance and dispatching of post-acquire preparation tasks.
KNOB_UPDATE_GUEST_LOG_DELAY: Knob[int] = Knob(
    'actor.dispatch-preparing.delay',
    'How often to run guest log update',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DISPATCH_PREPARE_DELAY',
    cast_from_str=int,
    default=60
)


KNOB_GC_EVENTS_SCHEDULE: Knob[str] = Knob(
    'gc.events.schedule',
    'When to run garbage collection task for guest request events.',
    has_db=False,
    envvar='ARTEMIS_GC_EVENTS_SCHEDULE',
    cast_from_str=str,
    default='15 */4 * * *'
)


KNOB_GC_EVENTS_THRESHOLD: Knob[int] = Knob(
    'gc.events.threshold',
    'How old must the guest events be to be removed, in seconds.',
    has_db=False,
    envvar='ARTEMIS_GC_EVENTS_THRESHOLD',
    cast_from_str=int,
    default=86400 * 30  # 30 days
)


POOL_DRIVERS = {
    'aws': aws_driver.AWSDriver,
    'beaker': beaker_driver.BeakerDriver,
    'openstack': openstack_driver.OpenStackDriver,
    'azure': azure_driver.AzureDriver,
}


POST_INSTALL_SCRIPT_REMOTE_FILEPATH = '/tmp/artemis-post-install-script.sh'


# A class of unique "reschedule task" doer return value
#
# Note: we could use object() to create this value, but using custom class let's use limit allowed types returned
# by doer.
class _RescheduleType:
    pass


# A class of unique "failed but ignore" doer return value
class _IgnoreType:
    def __init__(self, failure: Failure) -> None:
        self.failure = failure


# Unique object representing "reschedule task" return value of doer.
Reschedule = _RescheduleType()

# Doer return value type.
DoerReturnType = Result[Union[None, _RescheduleType, _IgnoreType], Failure]

# Helpers for constructing return values.
SUCCESS: DoerReturnType = Ok(None)
RESCHEDULE: DoerReturnType = Ok(Reschedule)


def is_ignore_result(result: DoerReturnType) -> bool:
    return result.is_ok and isinstance(result.unwrap(), _IgnoreType)


def IGNORE(result: Result[Any, Failure]) -> DoerReturnType:
    return Ok(_IgnoreType(result.unwrap_error()))


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
    ) -> DoerReturnType:
        ...


# Task actor type *before* applying `@dramatiq.actor` decorator, which is hidden in our `@task` decorator.
BareActorType = Callable[..., None]


# Task actor type.
class Actor(Protocol):
    actor_name: str
    fn: BareActorType
    options: Dict[str, Any]

    def send(
        self,
        *args: Any
    ) -> None:
        ...

    def send_with_options(
        self,
        args: Optional[Tuple[Any, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        delay: Optional[int] = None,
        **options: Any
    ) -> None:
        ...

    def message(
        self,
        *args: Any
    ) -> dramatiq.Message:
        ...


class DispatchTaskType(Protocol):
    def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        task: Actor,
        *args: Any,
        delay: Optional[int] = None
    ) -> Result[None, Failure]:
        ...


# Types of functions we use to handle success and failures.
class SuccessHandlerType(Protocol):
    def __call__(
        self,
        eventname: str,
        return_value: DoerReturnType = SUCCESS
    ) -> DoerReturnType:
        ...


class FailureHandlerType(Protocol):
    def __call__(
        self,
        result: Result[Any, Failure],
        label: str,
        sentry: bool = True
    ) -> DoerReturnType:
        ...


class TaskLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, task_name: str) -> None:
        super(TaskLogger, self).__init__(logger, {
            'ctx_task_name': (30, task_name)
        })

    def begin(self) -> None:
        self.info('beginning')

    def finished(self) -> None:
        self.info('finished')

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
        eventname: str,
        return_value: DoerReturnType = SUCCESS
    ) -> DoerReturnType:
        if guestname:
            log_guest_event(
                logger,
                session,
                guestname,
                eventname,
                **spice_details
            )

        return return_value

    def handle_failure(
        result: Result[Any, Failure],
        label: str,
        sentry: bool = True
    ) -> DoerReturnType:
        failure = result.unwrap_error()

        failure.handle(logger, label=label, sentry=sentry, guestname=guestname, **spice_details)

        if guestname:
            log_error_guest_event(
                logger,
                session,
                guestname,
                label,
                failure
            )

        if failure.recoverable is True:
            return Error(failure)

        return IGNORE(result)

    return handle_success, handle_failure, spice_details


def actor_control_value(actor_name: str, var_name: str, default: Any) -> Any:
    var_value = os.getenv(
        'ARTEMIS_ACTOR_{}_{}'.format(actor_name.upper(), var_name),
        default
    )

    # We don't bother about milliseconds in backoff values. For a sake of simplicity
    # variables stores value in seconds and here we convert it back to milliseconds
    if 'backoff' in var_name.lower() or 'tick' in var_name.lower():
        var_value = int(var_value) * 1000

    return var_value


def actor_kwargs(
    actor_name: str,
    priority: TaskPriority = TaskPriority.DEFAULT,
    queue_name: TaskQueue = TaskQueue.DEFAULT,
    periodic: Optional[periodiq.CronSpec] = None
) -> Dict[str, Any]:
    # We need to preserve the special queues requested by tasks, but still giving maintainers a chance
    # to change that. Therefore we accept the priority and queue name as parameters, and use them as
    # defaults when checking knobs. That way, if maintainer uses envvar to specify queue, it'd be used,
    # otherwise the one specified in the source source would be used.

    # Here we keep the actual priority and queue as understood by dramatiq. In our code, we use enums,
    # to avoid magic values here and there, but we have to translate those for dramatiq.
    priority_actual = cast(int, priority.value)
    queue_actual = cast(str, queue_name.value)

    # We want to support two ways how to specify priority: using names of our predefined priorities ("high"),
    # or by a number, for tweaks needed by maintainers ("101"). We get the maintainers' input, and try to
    # translate it to either enum member, or an integer.
    priority_input: str = actor_control_value(
        actor_name,
        'PRIORITY',
        priority.name
    )

    # Queues are easier: we have a list of predefined queues, but just like priorities, maintainers can specify
    # their own ones. There's no second-level test though, calling `str()` on queue name makes no sense since it's
    # already a string, and pretty much any string can be a queue name. We use `int()` on given priority because
    # priorities can be only integers.
    queue_input: str = actor_control_value(
        actor_name,
        'QUEUE',
        queue_name.name
    )

    try:
        priority_actual = TaskPriority[priority_input.upper()].value

    except KeyError:
        try:
            priority_actual = int(priority_input)

        except ValueError:
            Failure('unknown task priority', priority=priority_input).handle(_ROOT_LOGGER)

            priority_actual = TaskPriority.DEFAULT.value

    try:
        queue_actual = TaskQueue[queue_input.upper()].value

    except KeyError:
        # Yep, not in our list, but that doesn't meen it's forbidden to use it. Keep the input.
        pass

    kwargs = {
        'priority': priority_actual,
        'queue_name': queue_actual,
        'max_retries': int(actor_control_value(actor_name, 'RETRIES', KNOB_ACTOR_DEFAULT_RETRIES_COUNT.value)),
        'min_backoff': int(actor_control_value(actor_name, 'MIN_BACKOFF', KNOB_ACTOR_DEFAULT_MIN_BACKOFF.value)),
        'max_backoff': int(actor_control_value(actor_name, 'MAX_BACKOFF', KNOB_ACTOR_DEFAULT_MAX_BACKOFF.value))
    }

    if periodic is not None:
        kwargs['periodic'] = periodic

    return kwargs


# Implementing the decorator as a class on purpose - it plays nicely with type annotations when used without
# any arguments.
class task:
    def __init__(
        self,
        priority: TaskPriority = TaskPriority.DEFAULT,
        queue_name: TaskQueue = TaskQueue.DEFAULT,
        periodic: Optional[periodiq.CronSpec] = None
    ) -> None:
        self.priority = priority
        self.queue_name = queue_name
        self.periodic = periodic

    def __call__(self, fn: BareActorType) -> Actor:
        actor_name_uppersized = fn.__name__.upper()

        dramatiq_kwargs = actor_kwargs(
            actor_name_uppersized,
            periodic=self.periodic,
            priority=self.priority,
            queue_name=self.queue_name
        )

        return cast(Actor, dramatiq.actor(fn, **dramatiq_kwargs))


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

        # We need to propagate our current context to newly spawned thread. To do that, we need to copy our context,
        # and then use its `run()` method instead of the function we'd run in our new thread. `run()` would then
        # do its setup and call our function when context is set properly.
        thread_context = contextvars.copy_context()

        doer_future = executor.submit(
            thread_context.run,
            fn,
            logger,
            db,
            session,
            cancel,
            *args,
            **kwargs
        )

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
    db: Optional[DB] = None,
    session: Optional[sqlalchemy.orm.session.Session] = None,
    cancel: Optional[threading.Event] = None,
    doer_args: Optional[Tuple[Any, ...]] = None,
    doer_kwargs: Optional[Dict[str, Any]] = None
) -> None:
    logger.begin()

    db = db or get_root_db()
    cancel = cancel or threading.Event()

    doer_args = doer_args or tuple()
    doer_kwargs = doer_kwargs or dict()

    doer_result: DoerReturnType = Error(Failure('undefined doer result'))

    # Updating context - this function is the entry point into Artemis code, therefore context
    # is probably left empty or with absolutely wrong objects.

    # TODO: once we get nicer method, set context explicitly here
    LOGGER.set(logger)
    DATABASE.set(db)

    # Small helper so we can keep all session-related stuff inside one block, and avoid repetition or more than
    # one `get_session()` call.
    def _run_doer(session: sqlalchemy.orm.session.Session) -> DoerReturnType:
        SESSION.set(session)

        assert db is not None
        assert cancel is not None
        assert doer_args is not None
        assert doer_kwargs is not None

        doer_result = run_doer(logger, db, session, cancel, doer, *doer_args, **doer_kwargs)

        # "Ignored" failures - failures the tasks don't wish to repeat by running the task again - need
        # special handling: we have to mark the guest request as failed. Without this step, client will
        # spin endlessly until it finally gives up.

        if not is_ignore_result(doer_result):
            return doer_result

        failure = cast(_IgnoreType, doer_result.unwrap()).failure

        # Not all failures influence their parent guest request.
        if failure.recoverable is not False or failure.fail_guest_request is not True:
            return doer_result

        # Also, not all failures relate to guests. Such failures are easy to deal with, there's nothing to update.
        if 'guestname' not in failure.details:
            return doer_result

        guestname = failure.details['guestname']

        r_state_change = _update_guest_state(
            logger,
            session,
            guestname,
            GuestState.ERROR
        )

        # If the change failed, we're left with a loose end: the task marked the failure as something that will not
        # get better over time, but here we failed to mark the request as failed because of issue that may be
        # transient. If that's the case, we should probably try again. Otherwise, we log the error that killed the
        # state change, and move on.
        if r_state_change.is_error:
            # Describes the problem encountered when changing the guest request state.
            state_change_failure = r_state_change.unwrap_error()

            # Describes *when* this change was needed, i.e. what we attempted to do. Brings more context for humans.
            failure = Failure.from_failure(
                'failed to mark guest request as failed',
                state_change_failure
            )

            # State change failed because of recoverable failure => use it as an excuse to try again. We can expect the
            # task to fail, but we will get another chance to mark the guest as failed. This effectively drops the
            # original `IGNORE` result, replacing it with an error.
            if state_change_failure.recoverable is True:
                return Error(failure)

            # State change failed because of irrecoverable failure => no point to try again. Probably not very common,
            # but still possible, in theory. At least try to log the situation before proceeding with the original
            # `IGNORE`.
            failure.handle(logger)

        if r_state_change.unwrap() is not True:
            failure = Failure('failed to mark guest request as failed')

            # State change failed because the expected record might be missing or changed in some way => use it as an
            # excuse to try again. We can expect the task to *not* perform its work because it's higly likely its
            # initial attempt to "grab" the guest request would fail. Imagine acquire-guest-request to fail
            # irrecoverably, and before we can get to mark the request as failed, user removes it. The state change fail
            # is then quite expected, and the next iteration of acquire-guest-request will not even try to provision (
            # and fail irrecoverable again) because the guest request would be gone, resulting in successfull no-op.
            return Error(failure)

        # State change succeeded, and changed exactly the request we're working with. There is nothing left to do,
        # we proceed by propagating the original "ignore" result, closing the chapter.
        return doer_result

    try:
        if session is None:
            with db.get_session() as session:
                doer_result = _run_doer(session)

        else:
            doer_result = _run_doer(session)

    except Exception as exc:
        failure = Failure.from_exc('unhandled doer exception', exc)
        failure.handle(logger)

        doer_result = Error(failure)

    if doer_result.is_ok:
        result = doer_result.unwrap()

        if is_ignore_result(doer_result):
            logger.warning('message processing encountered error and requests waiver')

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


def _randomize_delay(delay: int) -> int:
    """
    Modify a given delay by a randomized value withing spread specified by :py:const:`KNOB_DELAY_UNIFORM_SPREAD`.
    """

    # Use `max()` to always return positive delay - if `delay == 0`, then the randomized delay could
    # fall bellow zero, and that does not seem to be a good practice.
    return max(0, delay + int(random.uniform(-KNOB_DELAY_UNIFORM_SPREAD.value, KNOB_DELAY_UNIFORM_SPREAD.value)))


def dispatch_task(
    logger: gluetool.log.ContextAdapter,
    task: Actor,
    *args: Any,
    delay: Optional[int] = None
) -> Result[None, Failure]:
    """
    Dispatch a given task.

    :param logger: logger to use for logging.
    :param task: callable, a Dramatiq task, to dispatch.
    :param args: positional parameters to pass to the task.
    :param delay: if set, the task will be delayed by this many seconds.
    """

    if delay is None:
        r = safe_call(task.send, *args)

    else:
        delay = _randomize_delay(delay)

        # The underlying Dramatiq code treats delay as miliseconds, hence the multiplication.
        r = safe_call(task.send_with_options, args=args, delay=delay * 1000)

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

        if KNOB_CLOSE_AFTER_DISPATCH.value:
            logger.debug('closing broker connection as requested')

            BROKER.connection.close()

        return Ok(None)

    return Error(Failure.from_failure(
        'failed to dispatch task',
        r.unwrap_error(),
        task_name=task.actor_name,
        task_args=args,
        task_delay=delay
    ))


def dispatch_group(
    logger: gluetool.log.ContextAdapter,
    tasks: List[Actor],
    *args: Any,
    on_complete: Optional[Actor] = None,
    delay: Optional[int] = None
) -> Result[None, Failure]:
    """
    Dispatch given tasks as a group.

    :param logger: logger to use for logging.
    :param tasks: list of callables, Dramatiq tasks, to dispatch.
    :param args: positional parameters to pass to all tasks.
    :param on_complete: a task to dispatch when group tasks complete.
    :param delay: if set, the task will be delayed by this many seconds.
    """

    try:
        group = dramatiq.group([
            task.message(*args)
            for task in tasks
        ])

        if on_complete:
            group.add_completion_callback(on_complete.message(*args))

        if delay is None:
            group.run()

        else:
            delay = _randomize_delay(delay)

            group.run(delay=delay * 1000)

        formatted_args = [
            str(arg) for arg in args
        ]

        if delay is not None:
            formatted_args += [
                'delay={}'.format(delay)
            ]

        logger.info('scheduled group ({})({})'.format(
            ' | '.join([task.actor_name for task in tasks]),
            ', '.join(formatted_args)
        ))

    except Exception as exc:
        return Error(Failure.from_exc(
            'failed to dispatch group',
            exc,
            group_tasks=[task.actor_name for task in tasks],
            group_args=args
        ))

    return Ok(None)


def _update_guest_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    new_state: GuestState,
    current_state: Optional[GuestState] = None,
    set_values: Optional[Dict[str, Union[str, int, None, datetime.datetime]]] = None,
    current_pool_data: Optional[str] = None,
    **details: Any
) -> Result[bool, Failure]:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        current_state=current_state.value if current_state is not None else None,
        new_state=new_state.value,
        **details
    )

    current_state_label = current_state.value if current_state is not None else '<ignored>'

    logger.warning('state switch: {} => {}'.format(current_state_label, new_state.value))

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
        .update(GuestRequest.__table__) \
        .where(GuestRequest.guestname == guestname)

    if current_state is not None:
        query = query.where(GuestRequest.state == current_state.value)

    if current_pool_data:
        query = query.where(GuestRequest.pool_data == current_pool_data)

    query = query.values(**values)

    r = safe_db_change(logger, session, query)

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to switch guest state',
            r.unwrap_error(),
            current_state=current_state_label,
            new_state=new_state.value
        ))

    if r.value is False:
        logger.warning('state switch: {} => {}: failed'.format(current_state_label, new_state.value))

        return Error(Failure(
            'did not switch guest state',
            current_state=current_state_label,
            new_state=new_state.value
        ))

    logger.warning('state switch: {} => {}: succeeded'.format(current_state_label, new_state.value))

    handle_success('state-changed')

    return Ok(True)


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

    r = safe_db_change(logger, session, query)

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to switch snapshot state',
            r.unwrap_error(),
            current_state=current_state.value,
            new_state=new_state.value
        ))

    if r.value is False:
        logger.warning('state switch: {} => {}: failed'.format(current_state.value, new_state.value))

        return Error(Failure(
            'did not switch snapshot state',
            current_state=current_state.value,
            new_state=new_state.value
        ))

    logger.warning('state switch: {} => {}: succeeded'.format(current_state.value, new_state.value))

    handle_success('snapshot-state-changed')

    return Ok(True)


def _get_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    poolname: str
) -> Result[PoolDriver, Failure]:
    r_pool = SafeQuery.from_session(session, Pool) \
        .filter(Pool.poolname == poolname) \
        .one_or_none()

    if r_pool.is_error:
        return Error(r_pool.unwrap_error())

    pool_record = r_pool.unwrap()

    if pool_record is None:
        return Error(Failure(
            'no such pool',
            poolname=poolname
        ))

    pool_driver_class = POOL_DRIVERS[pool_record.driver]
    driver = pool_driver_class(logger, poolname, json.loads(pool_record.parameters))

    r_sanity = driver.sanity()

    if r_sanity.is_error:
        return Error(r_sanity.unwrap_error())

    return Ok(driver)


def get_pools(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    enabled_only: bool = True
) -> Result[List[PoolDriver], Failure]:
    r_pools = SafeQuery.from_session(session, Pool).all()

    if r_pools.is_error:
        return Error(r_pools.unwrap_error())

    pools: List[PoolDriver] = []

    for pool_record in r_pools.unwrap():
        pool_driver_class = POOL_DRIVERS[pool_record.driver]

        if enabled_only is True:
            r_enabled = KNOB_POOL_ENABLED.get_value(session=session, poolname=pool_record.poolname)

            if r_enabled.is_error:
                return Error(r_enabled.unwrap_error())

            if r_enabled.unwrap() is not True:
                continue

        pools += [
            pool_driver_class(logger, pool_record.poolname, json.loads(pool_record.parameters))
        ]

    # NOTE(ivasilev) Currently Azure driver can't guarantee proper authentication in case of more than one Azure
    # pools, so need to warn the user about this.
    if len([d for d in pools if isinstance(d, azure_driver.AzureDriver)]) > 1:
        logger.warning('Multiple Azure pools are not supported at the moment, authentication may fail.')

    return Ok(pools)


@with_context
def _get_ssh_key(
    ownername: str,
    keyname: str,
    session: sqlalchemy.orm.session.Session
) -> Result[Optional[SSHKey], Failure]:
    return SafeQuery.from_session(session, SSHKey) \
        .filter(SSHKey.ownername == ownername) \
        .filter(SSHKey.keyname == keyname) \
        .one_or_none()


def _get_master_key() -> Result[SSHKey, Failure]:
    r_master_key = _get_ssh_key('artemis', 'master-key')

    if r_master_key.is_error:
        return Error(r_master_key.unwrap_error())

    master_key = r_master_key.unwrap()

    if master_key is None:
        return Error(Failure('failed to find master key'))

    return Ok(master_key)


def get_pool_logger(
    task_name: str,
    logger: gluetool.log.ContextAdapter,
    poolname: str
) -> TaskLogger:
    return TaskLogger(
        PoolLogger(logger, poolname),
        task_name
    )


def get_guest_logger(
    task_name: str,
    logger: gluetool.log.ContextAdapter,
    guestname: str
) -> TaskLogger:
    return TaskLogger(
        GuestLogger(logger, guestname),
        task_name
    )


def get_snapshot_logger(
    task_name: str,
    logger: gluetool.log.ContextAdapter,
    guestname: str,
    snapshotname: str
) -> TaskLogger:
    return TaskLogger(
        SnapshotLogger(
            GuestLogger(logger, guestname),
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
    and so on. The biggest advantage is that this outcome is stored in the workspace, and any consecutive
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
        self.guest_events: Optional[List[GuestEvent]] = None

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
            r = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.guestname == guestname) \
                .one_or_none()

        else:
            r = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.guestname == guestname) \
                .filter(GuestRequest.state == state.value) \
                .one_or_none()

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

        r = SafeQuery.from_session(self.session, SnapshotRequest) \
            .filter(SnapshotRequest.snapshotname == snapshotname) \
            .filter(SnapshotRequest.state == state.value) \
            .one_or_none()

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

        r = _get_ssh_key(self.gr.ownername, self.gr.ssh_keyname)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to get SSH key')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.ssh_key = r.unwrap()

        if self.ssh_key is None:
            self.result = self.handle_failure(
                Error(Failure(
                    'no such SSH key',
                    ownername=self.gr.ownername,
                    keyname=self.gr.ssh_keyname
                )),
                'failed to find SSH key'
            )

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

    def load_guest_events(self, eventname: Optional[str] = None) -> None:
        """
        Load guest events according to set guestname.

        **OUTCOMES:**

          * ``RESCHEDULE`` if cancel was requested
          * ``FAIL`` otherwise

        **SETS:**

          * ``guest_events``
        """

        if self.result:
            return

        assert self.guestname

        r_events = GuestEvent.fetch(
            self.session,
            eventname=eventname,
            guestname=self.guestname
        )

        if r_events.is_error:
            self.result = self.handle_failure(r_events, 'failed to fetch events')
            return

        if _cancel_task_if(self.logger, self.cancel):
            self.result = RESCHEDULE
            return

        self.guest_events = r_events.unwrap()

    def update_guest_state(
        self,
        new_state: GuestState,
        current_state: Optional[GuestState] = None,
        set_values: Optional[Dict[str, Union[str, int, None, datetime.datetime]]] = None,
        current_pool_data: Optional[str] = None,
        **details: Any
    ) -> None:
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
            new_state,
            current_state=current_state,
            set_values=set_values,
            current_pool_data=current_pool_data,
            **details
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to update guest request')
            return

        if not r.unwrap():
            self.result = self.handle_failure(Error(Failure('foo')), 'failed to update guest state')
            return

    def update_snapshot_state(
        self,
        current_state: GuestState,
        new_state: GuestState,
        set_values: Optional[Dict[str, Any]] = None,
        **details: Any
    ) -> None:
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
            current_state,
            new_state,
            set_values=set_values,
            **details
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to update snapshot request')
            return

        if not r.unwrap():
            self.result = self.handle_failure(Error(Failure('foo')), 'failed to update guest state')
            return

    def grab_snapshot_request(
        self,
        current_state: GuestState,
        new_state: GuestState,
        set_values: Optional[Dict[str, Any]] = None,
        **details: Any
    ) -> None:
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
            current_state,
            new_state,
            set_values=set_values,
            **details
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to grab snapshot request')
            return

        if not r.unwrap():
            self.result = SUCCESS
            return

    def ungrab_guest_request(self, current_state: GuestState, new_state: GuestState) -> None:
        assert self.guestname

        r = _update_guest_state(
            self.logger,
            self.session,
            self.guestname,
            new_state,
            current_state=current_state
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to ungrab guest request')
            return

        if r.unwrap():
            return

        assert False, 'unreachable'

    def ungrab_snapshot_request(
        self,
        current_state: GuestState,
        new_state: GuestState,
        set_values: Optional[Dict[str, Any]] = None,
        **details: Any
    ) -> None:
        assert self.snapshotname
        assert self.guestname

        r = _update_snapshot_state(
            self.logger,
            self.session,
            self.snapshotname,
            self.guestname,
            current_state,
            new_state,
            set_values=set_values,
            **details
        )

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to ungrab snapshot request')
            return

        if r.unwrap():
            return

        assert False, 'unreachable'

    def dispatch_task(self, task: Actor, *args: Any, delay: Optional[int] = None) -> None:
        if self.result:
            return

        r = dispatch_task(self.logger, task, *args, delay=delay)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to dispatch update task')
            return

    def dispatch_group(
        self,
        tasks: List[Actor],
        *args: Any,
        on_complete: Optional[Actor] = None,
        delay: Optional[int] = None
    ) -> None:
        if self.result:
            return

        r = dispatch_group(self.logger, tasks, *args, on_complete=on_complete, delay=delay)

        if r.is_error:
            self.result = self.handle_failure(r, 'failed to dispatch group')
            return

    def run_hook(self, hook_name: str, **kwargs: Any) -> Any:
        r_engine = hook_engine(hook_name)

        if r_engine.is_error:
            self.result = self.handle_failure(r_engine, 'failed to load {} hook'.format(hook_name))
            return

        engine = r_engine.unwrap()

        try:
            r = engine.run_hook(
                hook_name,
                logger=self.logger,
                **kwargs
            )

        except Exception as exc:
            r = Error(Failure.from_exc('unhandled hook error', exc))

        if r.is_error:
            self.result = self.handle_failure(r, 'hook failed')
            return

        return r.unwrap()


def _handle_successful_failover(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    workspace: Workspace
) -> None:
    # load events to workspace, sorted by date
    workspace.load_guest_events(eventname='error')
    assert workspace.guest_events is not None

    # If the list of events is empty, it means the provisioning did not run into any error at all.
    # Which means, we are not dealing with a failover.
    if not workspace.guest_events:
        return

    # detect and log successful first failover
    previous_poolname: Optional[str] = None

    for event in workspace.guest_events:
        if not event.details:
            continue

        details = json.loads(event.details)

        if 'failure' not in details or 'poolname' not in details['failure']:
            continue

        previous_poolname = details['failure']['poolname']

        break

    assert workspace.gr
    assert workspace.gr.poolname

    poolname = workspace.gr.poolname

    if previous_poolname and previous_poolname != poolname:
        logger.warning('successful failover - from pool {} to {}'.format(previous_poolname, poolname))
        metrics.ProvisioningMetrics.inc_failover_success(previous_poolname, poolname)


def do_release_pool_resources(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    poolname: str,
    serialized_resource_ids: str,
    guestname: Optional[str]
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='release-pool-resources'
    )

    handle_success('entered-task')

    r_pool = _get_pool(logger, session, poolname)

    if r_pool.is_error:
        return handle_failure(r_pool, 'pool sanity failed')

    pool = r_pool.unwrap()

    r_release = pool.release_pool_resources(logger, serialized_resource_ids)

    if r_release.is_error:
        return handle_failure(r_release, 'failed to release pool resources')

    return handle_success('finished-task')


@task()
def release_pool_resources(poolname: str, resource_ids: str, guestname: Optional[str]) -> None:
    if guestname:
        logger = get_guest_logger('release-pool-resources', _ROOT_LOGGER, guestname)

    else:
        logger = TaskLogger(_ROOT_LOGGER, 'release-pool-resources')

    task_core(
        cast(DoerType, do_release_pool_resources),
        logger=logger,
        doer_args=(poolname, resource_ids, guestname)
    )


def is_provisioning_tail_task(actor: Actor) -> bool:
    """
    Returns ``True`` if the given task is considered to be part of the provisioning "tail",
    i.e. tasks that take care of provisioning and follow up tasks.
    """

    return actor.actor_name in (
        guest_request_prepare_finalize_pre_connect.actor_name,
        guest_request_prepare_finalize_post_connect.actor_name,
        prepare_verify_ssh.actor_name,
        acquire_guest_request.actor_name,
        update_guest_request.actor_name,
        route_guest_request.actor_name
    )


def is_logging_tail_task(actor: Actor) -> bool:
    return actor.actor_name in (
        update_guest_log.actor_name,
    )


def do_handle_provisioning_chain_tail(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    current_state: GuestState,
    new_state: GuestState = GuestState.ROUTING
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='provisioning-tail'
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=current_state)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    if workspace.gr.poolname and not PoolData.is_empty(workspace.gr):
        spice_details['poolname'] = workspace.gr.poolname

        workspace.load_gr_pool()

        if workspace.result:
            return workspace.result

        assert workspace.pool

        r_release = workspace.pool.release_guest(logger, workspace.gr)

        if r_release.is_error:
            handle_failure(r_release, 'failed to release guest resources')

            return RESCHEDULE

    workspace.update_guest_state(
        new_state,
        current_state=current_state,
        set_values={
            'poolname': None,
            'pool_data': json.dumps({}),
            'address': None
        },
        current_pool_data=workspace.gr.pool_data
    )

    if new_state == GuestState.ROUTING:
        workspace.dispatch_task(route_guest_request, guestname)

    if workspace.result:
        return workspace.result

    logger.info('reverted to {}'.format(new_state.value))

    return handle_success('finished-task')


def handle_provisioning_chain_tail(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    actor: Actor
) -> bool:
    cancel = threading.Event()

    # for acquire_guest, move from PROVISIONING back to ROUTING
    if actor.actor_name == acquire_guest_request.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PROVISIONING,
            GuestState.ROUTING
        )

    # for do_update_guest, move from PROMISED back to ROUTING
    elif actor.actor_name == update_guest_request.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PROMISED,
            GuestState.ROUTING
        )

    # for route_guest_request, stay in ROUTING
    elif actor.actor_name == route_guest_request.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.ROUTING,
            GuestState.ERROR
        )

    # for post-acquire prepare chain final task, revert to ROUTING
    elif actor.actor_name == guest_request_prepare_finalize_pre_connect.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PREPARING,
            GuestState.ROUTING
        )

    # for post-acquire prepare chain final task, revert to ROUTING
    elif actor.actor_name == guest_request_prepare_finalize_post_connect.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PREPARING,
            GuestState.ROUTING
        )

    # for post-acquire verify chain tasks, revert to ROUTING
    elif actor.actor_name == prepare_verify_ssh.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PREPARING,
            GuestState.ROUTING
        )

    # for post-acquire verify chain tasks, revert to ROUTING
    elif actor.actor_name == prepare_post_install_script.actor_name:
        r = do_handle_provisioning_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            GuestState.PREPARING,
            GuestState.ROUTING
        )

    else:
        Failure(
            'actor not covered by provisioning chain tail',
            guestname=guestname,
            actor_name=actor.actor_name
        ).handle(logger)

        return False

    if r.is_ok:
        if r is SUCCESS:
            return True

        if r is RESCHEDULE:
            return False

        Failure(
            'unexpected result of provisioning chain tail',
            guestname=guestname,
            actor_name=actor.actor_name
        ).handle(logger)

        return False

    # Failures were already handled by this point
    return False


def do_handle_logging_chain_tail(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    logname: str,
    contenttype: GuestLogContentType
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='provisioning-tail'
    )

    handle_success('entered-task')

    query = sqlalchemy \
        .update(GuestLog.__table__) \
        .where(GuestLog.guestname == guestname) \
        .where(GuestLog.logname == logname) \
        .where(GuestLog.contenttype == contenttype) \
        .values(
            updated=datetime.datetime.utcnow(),
            state=GuestLogState.ERROR
        )

    r_store = safe_db_change(logger, session, query)

    if r_store.is_error:
        return handle_failure(r_store, 'failed to update the log')

    if r_store.unwrap() is not True:
        return handle_success('finished-task', return_value=RESCHEDULE)

    return handle_success('finished-task')


def handle_logging_chain_tail(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    logname: str,
    contenttype: GuestLogContentType,
    actor: Actor
) -> bool:
    cancel = threading.Event()

    # for update_guest_log, drop the log record to ERROR state
    if actor.actor_name == update_guest_log.actor_name:
        r = do_handle_logging_chain_tail(
            logger,
            db,
            session,
            cancel,
            guestname,
            logname,
            contenttype
        )

    else:
        Failure(
            'actor not covered by logging chain tail',
            guestname=guestname,
            actor_name=actor.actor_name
        ).handle(logger)

        return False

    if r.is_ok:
        if r is SUCCESS:
            return True

        if r is RESCHEDULE:
            return False

        Failure(
            'unexpected result of logging chain tail',
            guestname=guestname,
            logname=logname,
            contenttype=contenttype.value,
            actor_name=actor.actor_name
        ).handle(logger)

        return False

    # Failures were already handled by this point
    return False


def do_update_guest_log(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str,
    logname: str,
    contenttype: GuestLogContentType
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='update-guest-log'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    r_guest_log = SafeQuery.from_session(session, GuestLog) \
        .filter(GuestLog.guestname == workspace.gr.guestname) \
        .filter(GuestLog.logname == logname) \
        .filter(GuestLog.contenttype == contenttype) \
        .one_or_none()

    if r_guest_log.is_error:
        return handle_failure(r_guest_log, 'failed to fetch the log')

    guest_log = r_guest_log.unwrap()

    if guest_log is None:
        # We're the first: create the record, and reschedule. We *could* proceed and try to fetch the data, too,
        # let's try with another task run first.

        r_upsert = upsert(
            logger,
            session,
            GuestLog,
            primary_keys={
                GuestLog.guestname: guestname,
                GuestLog.logname: logname,
                GuestLog.contenttype: contenttype
            },
            insert_data={
                GuestLog.state: GuestLogState.PENDING
            }
        )

        if r_upsert.is_error:
            return handle_failure(r_upsert, 'failed to create log record')

        return handle_success('finished-task', return_value=RESCHEDULE)

    logger.warning(f'guest-log: {guest_log.logname} {guest_log.contenttype} {guest_log.state}')

    if guest_log.state == GuestLogState.ERROR:
        # TODO logs: there is a corner case: log crashes because of flapping API, the guest is reprovisioned
        # to different pool, and here the could succeed - but it's never going to be tried again since it's
        # in ERROR state and there's no way to "reset" the state - possibly do that in API via POST.
        return handle_success('finished-task')

    # TODO logs: it'd be nice to change logs' state to something final
    if workspace.gr.state in (GuestState.CONDEMNED.value, GuestState.ERROR.value):
        logger.warning('guest can no longer provide any useful logs')

        return handle_success('finished-task')

    if workspace.gr.pool is None:
        logger.warning('guest request has no pool at this moment, reschedule')

        return handle_success('finished-task', return_value=RESCHEDULE)

    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.pool

    if guest_log.state == GuestLogState.COMPLETE:
        if not guest_log.is_expired:
            return handle_success('finished-task')

        r_update = workspace.pool.update_guest_log(
            workspace.gr,
            guest_log
        )

    elif guest_log.state == GuestLogState.PENDING:
        r_update = workspace.pool.update_guest_log(
            workspace.gr,
            guest_log
        )

    elif guest_log.state == GuestLogState.IN_PROGRESS:
        r_update = workspace.pool.update_guest_log(
            workspace.gr,
            guest_log
        )

    if r_update.is_error:
        return handle_failure(r_update, 'failed to update the log')

    update_progress = r_update.unwrap()

    logger.warning(f'update-progress: {update_progress}')

    query = sqlalchemy \
        .update(GuestLog.__table__) \
        .where(GuestLog.guestname == workspace.gr.guestname) \
        .where(GuestLog.logname == logname) \
        .where(GuestLog.state == guest_log.state) \
        .where(GuestLog.contenttype == contenttype) \
        .where(GuestLog.updated == guest_log.updated) \
        .where(GuestLog.url == guest_log.url) \
        .where(GuestLog.blob == guest_log.blob) \
        .values(
            url=update_progress.url,
            blob=update_progress.blob,
            updated=datetime.datetime.utcnow(),
            state=update_progress.state,
            expires=update_progress.expires
        )

    r_store = safe_db_change(logger, session, query)

    if r_store.is_error:
        return handle_failure(r_store, 'failed to update the log')

    if r_store.unwrap() is not True:
        return handle_success('finished-task', return_value=RESCHEDULE)

    if update_progress.state == GuestLogState.COMPLETE:
        return handle_success('finished-task')

    if update_progress.state == GuestLogState.ERROR:
        return handle_success('finished-task')

    # PENDING or IN_PROGRESS proceed the same way
    workspace.dispatch_task(
        update_guest_log,
        guestname,
        logname,
        contenttype.value,
        delay=update_progress.delay_update or KNOB_UPDATE_GUEST_LOG_DELAY.value
    )

    if workspace.result:
        return workspace.result

    return handle_success('finished-task')


@dramatiq.actor(**actor_kwargs('UPDATE_GUEST_LOG'))  # type: ignore  # Untyped decorator
def update_guest_log(guestname: str, logname: str, contenttype: str) -> None:
    task_core(
        cast(DoerType, do_update_guest_log),
        logger=get_guest_logger('update-guest-log', _ROOT_LOGGER, guestname),
        doer_args=(guestname, logname, GuestLogContentType(contenttype))
    )


def do_prepare_verify_ssh(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str
) -> DoerReturnType:
    # Avoid circular imports
    from .drivers import run_remote

    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='prepare-verify-ssh'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PREPARING)
    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.gr.address
    assert workspace.pool

    r_master_key = _get_master_key()

    if r_master_key.is_error:
        return handle_failure(r_master_key, 'failed to fetch master key')

    r_ssh_timeout = KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value(session=session, pool=workspace.pool)

    if r_ssh_timeout.is_error:
        return handle_failure(r_ssh_timeout, 'failed to obtain ssh timeout value')

    r_ssh = run_remote(
        logger,
        workspace.gr,
        ['bash', '-c', 'echo ping'],
        key=r_master_key.unwrap(),
        ssh_timeout=r_ssh_timeout.unwrap()
    )

    if r_ssh.is_error:
        return handle_failure(r_ssh, 'failed to verify SSH')

    ssh_output = r_ssh.unwrap()

    if ssh_output.stdout.strip() != 'ping':
        failure = Failure(
            'did not receive expected response',
            command_output=ssh_output.process_output
        )

        return handle_failure(Error(failure), 'failed to verify SSH')

    return handle_success('finished-task')


@task()
def prepare_verify_ssh(guestname: str) -> None:
    task_core(
        cast(DoerType, do_prepare_verify_ssh),
        logger=get_guest_logger('prepare-verify-ssh', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def do_prepare_post_install_script(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    guestname: str
) -> DoerReturnType:
    # Avoid circular imports
    from .drivers import copy_to_remote, create_tempfile, run_remote

    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        guestname=guestname,
        task='prepare-post-install-script'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PREPARING)
    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.gr.address
    assert workspace.pool

    r_master_key = _get_master_key()

    if r_master_key.is_error:
        return handle_failure(r_master_key, 'failed to fetch master key')

    r_ssh_timeout = KNOB_PREPARE_VERIFY_SSH_CONNECT_TIMEOUT.get_value(session=session, pool=workspace.pool)

    if r_ssh_timeout.is_error:
        return handle_failure(r_ssh_timeout, 'failed to obtain ssh timeout value')

    with create_tempfile(file_contents=workspace.gr.post_install_script) as post_install_filepath:
        r_upload = copy_to_remote(
            logger,
            workspace.gr,
            post_install_filepath,
            POST_INSTALL_SCRIPT_REMOTE_FILEPATH,
            key=r_master_key.unwrap(),
            ssh_timeout=r_ssh_timeout.unwrap()
        )

    if r_upload.is_error:
        return handle_failure(r_upload, 'failed to upload post-install script')

    r_ssh = run_remote(
        logger,
        workspace.gr,
        ['/bin/sh', POST_INSTALL_SCRIPT_REMOTE_FILEPATH],
        key=r_master_key.unwrap(),
        ssh_timeout=r_ssh_timeout.unwrap()
    )

    if r_ssh.is_error:
        return handle_failure(r_ssh, 'failed to execute post-install script successfully')

    return handle_success('finished-task')


@task()
def prepare_post_install_script(guestname: str) -> None:
    task_core(
        cast(DoerType, do_prepare_post_install_script),
        logger=get_guest_logger('prepare-post-install-script', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def do_guest_request_prepare_finalize_pre_connect(
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
        task='prepare-finalize-pre-connect'
    )

    handle_success('enter-task')

    logger.info('pre-connect preparation steps complete')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PREPARING)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    tasks: List[Actor] = []

    # Running post-install script is optional - the driver might have done it already.
    if workspace.gr.post_install_script:
        workspace.load_gr_pool()

        if workspace.result:
            return workspace.result

        assert workspace.pool

        r_capabilities = workspace.pool.capabilities()

        if r_capabilities.is_error:
            return handle_failure(r_capabilities, 'failed to fetch pool capabilities')

        if r_capabilities.unwrap().supports_native_post_install_script is False:
            tasks += [prepare_post_install_script]

    if tasks:
        workspace.dispatch_group(
            tasks,
            workspace.guestname,
            on_complete=guest_request_prepare_finalize_post_connect
        )

    else:
        workspace.dispatch_task(guest_request_prepare_finalize_post_connect, workspace.guestname)

    if workspace.result:
        return workspace.result

    return handle_success('finished-task')


@task()
def guest_request_prepare_finalize_pre_connect(guestname: str) -> None:
    task_core(
        cast(DoerType, do_guest_request_prepare_finalize_pre_connect),
        logger=get_guest_logger('guest-request-prepare-finalize-pre-connect', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def do_guest_request_prepare_finalize_post_connect(
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
        task='prepare-finalize-post-connect'
    )

    handle_success('enter-task')

    logger.info('post-connect preparation steps complete')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PREPARING)

    workspace.update_guest_state(
        GuestState.READY,
        current_state=GuestState.PREPARING
    )

    if workspace.result:
        return workspace.result

    logger.info('successfully provisioned')

    # calculate provisioning duration time
    assert workspace.gr is not None
    provisioning_duration = (datetime.datetime.utcnow() - workspace.gr.ctime).total_seconds()
    logger.info("provisioning duration: {}s".format(provisioning_duration))

    # update provisioning duration metrics
    metrics.ProvisioningMetrics.inc_provisioning_durations(provisioning_duration)

    # check if this was a failover and mark it in metrics
    _handle_successful_failover(logger, session, workspace)

    # update metrics counter for successfully provisioned guest requests
    assert workspace.gr
    assert workspace.gr.poolname is not None

    metrics.ProvisioningMetrics.inc_success(workspace.gr.poolname)

    return handle_success('finished-task')


@task()
def guest_request_prepare_finalize_post_connect(guestname: str) -> None:
    task_core(
        cast(DoerType, do_guest_request_prepare_finalize_post_connect),
        logger=get_guest_logger('guest-request-prepare-finalize-post-connect', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def dispatch_preparing_pre_connect(
    logger: gluetool.log.ContextAdapter,
    workspace: Workspace,
) -> None:
    """
    Helper for dispatching post-acquire chain of tasks.

    Tier 1: verify the basic accessibility of the guest.
    """

    workspace.dispatch_group(
        [
            prepare_verify_ssh
        ],
        workspace.guestname,
        on_complete=guest_request_prepare_finalize_pre_connect,
        delay=KNOB_DISPATCH_PREPARE_DELAY.value
    )


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
        task='release-guest-request'
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.CONDEMNED)

    if workspace.result:
        return workspace.result

    assert workspace.gr

    if workspace.gr.poolname and not PoolData.is_empty(workspace.gr):
        spice_details['poolname'] = workspace.gr.poolname

        workspace.load_gr_pool()
        workspace.load_ssh_key()

        if workspace.result:
            return workspace.result

        assert workspace.pool

        r_release = workspace.pool.release_guest(logger, workspace.gr)

        if r_release.is_error:
            return handle_failure(r_release, 'failed to release guest')

    query = sqlalchemy \
        .delete(GuestRequest.__table__) \
        .where(GuestRequest.guestname == guestname) \
        .where(GuestRequest.state == GuestState.CONDEMNED.value)

    r_delete = safe_db_change(logger, session, query)

    if r_delete.is_error:
        return handle_failure(r_delete, 'failed to remove guest request record')

    # We ignore the actual return value: the query was executed, but we either removed exactly one record,
    # which is good, or we removed 0 records, which is also acceptable, as somebody already did that for us.
    # We did schedule the release of resources successfully, which means we left no loose ends.
    handle_success('released')

    return handle_success('finished-task')


@task()
def release_guest_request(guestname: str) -> None:
    task_core(
        cast(DoerType, do_release_guest_request),
        logger=get_guest_logger('release-guest-request', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def do_update_guest_request(
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
        task='update-guest-request'
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PROMISED)
    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.pool

    spice_details['poolname'] = workspace.gr.poolname
    current_pool_data = workspace.gr.pool_data

    def _undo_guest_update() -> None:
        assert workspace.gr
        assert workspace.pool

        r = workspace.pool.release_guest(logger, workspace.gr)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo guest update')

    r_update = workspace.pool.update_guest(
        logger,
        session,
        workspace.gr
    )

    if r_update.is_error:
        return handle_failure(r_update, 'failed to update guest')

    provisioning_progress = r_update.unwrap()

    # not returning here - pool was able to recover and proceed
    for failure in provisioning_progress.pool_failures:
        handle_failure(Error(failure), 'pool encountered failure during update')

    if provisioning_progress.state == ProvisioningState.PENDING:
        workspace.update_guest_state(
            GuestState.PROMISED,
            current_state=GuestState.PROMISED,
            set_values={
                'pool_data': provisioning_progress.pool_data.serialize()
            },
            current_pool_data=current_pool_data
        )

        workspace.dispatch_task(update_guest_request, guestname, delay=provisioning_progress.delay_update)

        if workspace.result:
            _undo_guest_update()

            return workspace.result

        logger.info('scheduled update')

        return handle_success('finished-task')

    elif provisioning_progress.state == ProvisioningState.CANCEL:
        logger.info('provisioning cancelled')

        workspace.pool.release_guest(logger, workspace.gr)

        if workspace.result:
            return workspace.result

        if handle_provisioning_chain_tail(logger, db, session, workspace.gr.guestname, update_guest_request):
            return handle_success('finished-task')

        return RESCHEDULE

    assert provisioning_progress.address

    workspace.update_guest_state(
        GuestState.PREPARING,
        current_state=GuestState.PROMISED,
        set_values={
            'address': provisioning_progress.address,
            'pool_data': provisioning_progress.pool_data.serialize()
        },
        current_pool_data=current_pool_data
    )

    if workspace.result:
        _undo_guest_update()

        return workspace.result

    logger.info('successfully acquired')

    dispatch_preparing_pre_connect(logger, workspace)

    if workspace.result:
        _undo_guest_update()

        return workspace.result

    return handle_success('finished-task')


@task()
def update_guest_request(guestname: str) -> None:
    task_core(
        cast(DoerType, do_update_guest_request),
        logger=get_guest_logger('update-guest-request', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


def do_acquire_guest_request(
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
        task='acquire-guest-request',
        poolname=poolname
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname, state=GuestState.PROVISIONING)
    workspace.load_gr_pool()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.pool

    result = workspace.pool.acquire_guest(
        logger,
        session,
        workspace.gr,
        cancelled=cancel
    )

    if result.is_error:
        return handle_failure(result, 'failed to provision')

    provisioning_progress = result.unwrap()

    # not returning here - pool was able to recover and proceed
    for failure in provisioning_progress.pool_failures:
        handle_failure(Error(failure), 'pool encountered failure during acquisition')

    def _undo_guest_acquire() -> None:
        assert workspace.gr
        assert workspace.pool

        r = workspace.pool.release_guest(logger, workspace.gr)

        if r.is_ok:
            return

        raise Exception(r.error)

    # We have a guest, we can move the guest record to the next state. The guest may be unfinished,
    # in that case we should schedule a task for driver's update_guest method. Otherwise, we must
    # save guest's address. In both cases, we must be sure nobody else did any changes before us.
    if provisioning_progress.state == ProvisioningState.PENDING:
        workspace.update_guest_state(
            GuestState.PROMISED,
            current_state=GuestState.PROVISIONING,
            set_values={
                'pool_data': provisioning_progress.pool_data.serialize()
            }
        )

        workspace.dispatch_task(update_guest_request, guestname, delay=provisioning_progress.delay_update)

        if workspace.result:
            _undo_guest_acquire()

            return workspace.result

        logger.info('scheduled update')

        return handle_success('finished-task')

    elif provisioning_progress.state == ProvisioningState.CANCEL:
        logger.info('provisioning cancelled')

        workspace.pool.release_guest(logger, workspace.gr)

        if workspace.result:
            return workspace.result

        if handle_provisioning_chain_tail(logger, db, session, workspace.gr.guestname, acquire_guest_request):
            return handle_success('finished-task')

        return RESCHEDULE

    assert provisioning_progress.address

    workspace.update_guest_state(
        GuestState.PREPARING,
        current_state=GuestState.PROVISIONING,
        set_values={
            'address': provisioning_progress.address,
            'pool_data': provisioning_progress.pool_data.serialize()
        },
        address=provisioning_progress.address,
        pool=workspace.gr.poolname,
        pool_data=provisioning_progress.pool_data.serialize()
    )

    if workspace.result:
        _undo_guest_acquire()

        return workspace.result

    logger.info('successfully acquired')

    dispatch_preparing_pre_connect(logger, workspace)

    if workspace.result:
        _undo_guest_acquire()

        return workspace.result

    return handle_success('finished-task')


@task()
def acquire_guest_request(guestname: str, poolname: str) -> None:
    task_core(
        cast(DoerType, do_acquire_guest_request),
        logger=get_guest_logger('acquire-guest-request', _ROOT_LOGGER, guestname),
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
        task='route-guest-request'
    )

    handle_success('entered-task')

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

    r_pools = get_pools(logger, session)

    if r_pools.is_error:
        return handle_failure(r_pools, 'failed to fetch pools')

    ruling = cast(
        PolicyRuling,
        workspace.run_hook(
            'ROUTE',
            session=session,
            guest_request=workspace.gr,
            pools=r_pools.unwrap()
        )
    )

    # Route hook failed, request cannot be fulfilled ;(
    if workspace.result:
        return workspace.result

    if ruling.cancel:
        handle_success('routing-cancelled')

        workspace.update_guest_state(
            GuestState.ERROR,
            current_state=GuestState.ROUTING
        )

        if workspace.result:
            return workspace.result

        return handle_success('finished-task')

    # If no suitable pools found
    if not ruling.allowed_pools:
        return RESCHEDULE

    # At this point, all pools are equally worthy: we may very well use the first one.
    pool = ruling.allowed_pools[0]

    assert workspace.gr
    new_pool = pool.poolname
    current_pool = workspace.gr.poolname

    if _cancel_task_if(logger, cancel):
        return RESCHEDULE

    # Mark request as suitable for provisioning.
    workspace.update_guest_state(
        GuestState.PROVISIONING,
        current_state=GuestState.ROUTING,
        set_values={
            'poolname': pool.poolname
        },
        pool=pool.poolname
    )

    if workspace.result:
        # We failed to move guest to PROVISIONING state which means some other instance of this task changed
        # guest's state instead of us, which means we should throw everything away because our decisions no
        # longer matter.
        return handle_success('finished-task')

    # Fine, the query succeeded, which means we are the first instance of this task to move this far. For any other
    # instance, the state change will fail and they will bail while we move on and try to dispatch the provisioning
    # task.
    workspace.dispatch_task(acquire_guest_request, guestname, pool.poolname)

    if workspace.result:
        workspace.ungrab_guest_request(GuestState.PROVISIONING, GuestState.ROUTING)

        return workspace.result

    logger.info('scheduled provisioning')

    # New pool was chosen - log failover
    if workspace.gr and current_pool and new_pool != current_pool:
        logger.warning('failover - trying {} pool instead of {}'.format(new_pool, current_pool))
        metrics.ProvisioningMetrics.inc_failover(current_pool, new_pool)

    return handle_success('finished-task')


@task()
def route_guest_request(guestname: str) -> None:
    task_core(
        cast(DoerType, do_route_guest_request),
        logger=get_guest_logger('route-guest-request', _ROOT_LOGGER, guestname),
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

    handle_success('entered-task')

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

        if workspace.result:
            _undo_grab()

            return workspace.result

    query = sqlalchemy \
        .delete(SnapshotRequest.__table__) \
        .where(SnapshotRequest.snapshotname == snapshotname) \
        .where(SnapshotRequest.state == GuestState.RELEASING.value)

    r_delete = safe_db_change(logger, session, query)

    if r_delete.is_ok:
        handle_success('snapshot-released')

        return handle_success('finished-task')

    failure = r_delete.unwrap_error()

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in RELEASING state anymore')

        return handle_success('finished-task')

    _undo_grab()

    return handle_failure(r_delete, 'failed to release snapshot')


@task()
def release_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_release_snapshot_request),
        logger=get_snapshot_logger('release-snapshot', _ROOT_LOGGER, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_create_snapshot_start_guest(
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
        task='create-snapshot-stop-guest',
        snapshotname=snapshotname
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.READY)
    workspace.load_guest_request(guestname, state=GuestState.STARTING)

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.gr

    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        return workspace.result

    assert workspace.pool
    assert workspace.ssh_key

    r_started = workspace.pool.is_guest_running(workspace.gr)

    if r_started.is_error:
        return handle_failure(r_started, 'failed to check if guest is started')

    started = r_started.unwrap()

    if not started:
        workspace.dispatch_task(create_snapshot_start_guest, guestname, snapshotname)

        if workspace.result:
            return workspace.result

        return handle_success('finished-task')

    workspace.update_guest_state(
        GuestState.READY,
        current_state=GuestState.STARTING
    )

    if workspace.result:
        return workspace.result

    logger.info('successfully started')

    return handle_success('finished-task')


@task()
def create_snapshot_start_guest(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_create_snapshot_start_guest),
        logger=get_snapshot_logger('create-snapshot-start-guest', _ROOT_LOGGER, guestname, snapshotname),
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

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.PROMISED)
    workspace.load_guest_request(guestname, state=GuestState.STOPPED)
    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        return workspace.result

    assert workspace.gr
    assert workspace.sr
    assert workspace.pool

    r_update = workspace.pool.update_snapshot(
        workspace.gr,
        workspace.sr,
        start_again=workspace.sr.start_again
    )

    if r_update.is_error:
        return handle_failure(r_update, 'failed to update snapshot')

    provisioning_progress = r_update.unwrap()

    def _undo_snapshot_update() -> None:
        assert workspace.sr
        assert workspace.pool

        r = workspace.pool.remove_snapshot(workspace.sr)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo guest update')

    if provisioning_progress.state == ProvisioningState.PENDING:
        workspace.update_snapshot_state(
            GuestState.PROMISED,
            GuestState.PROMISED,
        )

        workspace.dispatch_task(update_snapshot, guestname, snapshotname)

        if workspace.result:
            _undo_snapshot_update()

            return workspace.result

        logger.info('scheduled update')

        return handle_success('finished-task')

    workspace.update_snapshot_state(
        GuestState.PROMISED,
        GuestState.READY
    )

    if workspace.result:
        return workspace.result

    if not workspace.sr.start_again:
        return handle_success('finished-task')

    r_start = workspace.pool.start_guest(logger, workspace.gr)

    if r_start.is_error:
        return handle_failure(r_start, 'failed to start guest')

    workspace.update_guest_state(
        GuestState.STARTING,
        current_state=GuestState.STOPPED
    )

    if workspace.result:
        _undo_snapshot_update()

        return workspace.result

    workspace.dispatch_task(create_snapshot_start_guest, guestname, snapshotname)

    if workspace.result:
        _undo_snapshot_update()

        return workspace.result

    return handle_success('finished-task')


@task()
def update_snapshot(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_update_snapshot),
        logger=get_snapshot_logger('update-snapshot', _ROOT_LOGGER, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_create_snapshot_create(
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
        task='create-snapshot-create',
        snapshotname=snapshotname
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.CREATING)
    workspace.load_guest_request(guestname, state=GuestState.STOPPED)

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.gr

    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        return workspace.result

    assert workspace.pool
    assert workspace.ssh_key

    r_create = workspace.pool.create_snapshot(workspace.gr, workspace.sr)

    if r_create.is_error:
        return handle_failure(r_create, 'failed to create snapshot')

    provisioning_progress = r_create.unwrap()

    def _undo_snapshot_create() -> None:
        assert workspace.sr
        assert workspace.pool

        r = workspace.pool.remove_snapshot(workspace.sr)

        if r.is_ok:
            return

        handle_failure(r, 'failed to undo snapshot create')

    if provisioning_progress.state == ProvisioningState.PENDING:
        workspace.update_snapshot_state(
            GuestState.CREATING,
            GuestState.PROMISED,
        )

        workspace.dispatch_task(update_snapshot, guestname, snapshotname)

        if workspace.result:
            _undo_snapshot_create()

            return workspace.result

        logger.info('scheduled update')

        return handle_success('finished-task')

    workspace.update_snapshot_state(
        GuestState.CREATING,
        GuestState.READY
    )

    if workspace.result:
        return workspace.result

    if not workspace.sr.start_again:
        return handle_success('finished-task')

    r_start = workspace.pool.start_guest(logger, workspace.gr)

    if r_start.is_error:
        return handle_failure(r_start, 'failed to start guest')

    workspace.update_guest_state(
        GuestState.STARTING,
        current_state=GuestState.STOPPED
    )

    if workspace.result:
        _undo_snapshot_create()

        return workspace.result

    workspace.dispatch_task(create_snapshot_start_guest, guestname, snapshotname)

    if workspace.result:
        _undo_snapshot_create()

        return workspace.result

    logger.info('successfully created')

    return handle_success('finished-task')


@task()
def create_snapshot_create(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_create_snapshot_create),
        logger=get_snapshot_logger('create-snapshot-create', _ROOT_LOGGER, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_create_snapshot_stop_guest(
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
        task='create-snapshot-stop-guest',
        snapshotname=snapshotname
    )

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.CREATING)
    workspace.load_guest_request(guestname, state=GuestState.STOPPING)

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.gr

    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        return workspace.result

    assert workspace.pool
    assert workspace.ssh_key

    r_stopped = workspace.pool.is_guest_stopped(workspace.gr)

    if r_stopped.is_error:
        return handle_failure(r_stopped, 'failed to check if guest is stopped')

    stopped = r_stopped.unwrap()

    if not stopped:
        workspace.dispatch_task(create_snapshot_stop_guest, guestname, snapshotname)

        if workspace.result:
            return workspace.result

        logger.info('scheduled create-snapshot-stop-guest')

        return handle_success('finished-task')

    workspace.update_guest_state(
        GuestState.STOPPED,
        current_state=GuestState.STOPPING
    )

    if workspace.result:
        return workspace.result

    workspace.dispatch_task(create_snapshot_create, guestname, snapshotname)

    if workspace.result:
        return workspace.result

    logger.info('scheduled create-snapshot-create-snapshot')

    return handle_success('finished-task')


@task()
def create_snapshot_stop_guest(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_create_snapshot_stop_guest),
        logger=get_snapshot_logger('create-snapshot-stop-guest', _ROOT_LOGGER, guestname, snapshotname),
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

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.CREATING)
    workspace.load_guest_request(guestname, state=GuestState.READY)

    if workspace.result:
        return workspace.result

    assert workspace.sr
    assert workspace.gr

    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        return workspace.result

    assert workspace.pool
    assert workspace.ssh_key

    r_stop = workspace.pool.stop_guest(logger, workspace.gr)

    if r_stop.is_error:
        return handle_failure(r_stop, 'failed to stop guest')

    def _undo_snapshot_create() -> None:
        assert workspace.pool
        assert workspace.gr

        r = workspace.pool.start_guest(logger, workspace.gr)

        if r.is_ok:
            return

        workspace.update_guest_state(
            GuestState.STARTING,
            current_state=GuestState.STOPPING
        )

        workspace.dispatch_task(create_snapshot_start_guest, guestname, snapshotname)

        handle_failure(r, 'failed to undo snapshot create')

    workspace.update_guest_state(
        GuestState.STOPPING,
        current_state=GuestState.READY
    )

    if workspace.result:
        return workspace.result

    workspace.dispatch_task(create_snapshot_stop_guest, guestname, snapshotname)

    if workspace.result:
        _undo_snapshot_create()

        return workspace.result

    logger.info('scheduled create-snapshot-stop-guest')

    return handle_success('finished-task')


@task()
def create_snapshot(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_create_snapshot),
        logger=get_snapshot_logger('create-snapshot', _ROOT_LOGGER, guestname, snapshotname),
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

    handle_success('entered-task')

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

    return handle_success('finished-task')


@task()
def route_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_route_snapshot_request),
        logger=get_snapshot_logger('route-snapshot', _ROOT_LOGGER, guestname, snapshotname),
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

    handle_success('entered-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_snapshot_request(snapshotname, GuestState.RESTORING)
    workspace.load_guest_request(guestname, state=GuestState.READY)
    workspace.grab_snapshot_request(GuestState.RESTORING, GuestState.PROCESSING)

    if workspace.result:
        return workspace.result

    workspace.load_sr_pool()
    workspace.load_ssh_key()

    if workspace.result:
        workspace.ungrab_snapshot_request(GuestState.PROCESSING, GuestState.RESTORING)

        return workspace.result

    assert workspace.gr
    assert workspace.sr
    assert workspace.pool

    r_restore = workspace.pool.restore_snapshot(workspace.gr, workspace.sr)

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

    return handle_success('finished-task')


@task()
def restore_snapshot_request(guestname: str, snapshotname: str) -> None:
    task_core(
        cast(DoerType, do_restore_snapshot_request),
        logger=get_snapshot_logger('restore-snapshot', _ROOT_LOGGER, guestname, snapshotname),
        doer_args=(guestname, snapshotname)
    )


def do_refresh_pool_resources_metrics(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    poolname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        task='refresh-pool-metrics'
    )

    handle_success('entered-task')

    # Handling errors is slightly different in this task. While we fully use `handle_failure()`,
    # we do not return `RESCHEDULE` or `Error()` from this doer. This particular task is being
    # rescheduled regularly anyway, and we probably do not want exponential delays, because
    # they would make metrics less accurate when we'd finally succeed talking to the pool.
    #
    # On the other hand, we schedule next iteration of this task here, and it seems to make sense
    # to retry if we fail to schedule it - without this, the "it will run once again anyway" concept
    # breaks down.
    r_pool = _get_pool(logger, session, poolname)

    if r_pool.is_error:
        handle_failure(r_pool, 'failed to load pool')

    else:
        pool = r_pool.unwrap()

        r_refresh = pool.refresh_pool_resources_metrics(logger, session)

        if r_refresh.is_error:
            handle_failure(r_refresh, 'failed to refresh pool resources metrics')

    return handle_success('finished-task')


def do_acquire_guest_console_url(
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
        task='acquire-guest-console-url'
    )

    handle_success('enter-task')

    workspace = Workspace(logger, session, cancel, handle_failure)
    workspace.load_guest_request(guestname)
    workspace.load_gr_pool()
    assert workspace.pool
    assert workspace.gr
    r_console = workspace.pool.acquire_console_url(logger, workspace.gr)
    if r_console.is_error:
        handle_failure(r_console, 'failed to get guest console')
        return RESCHEDULE

    console_url_data = r_console.unwrap()
    workspace.update_guest_state(
        GuestState(workspace.gr.state),
        set_values={
            'console_url': console_url_data.url,
            'console_url_expires': console_url_data.expires,
        },
        current_pool_data=workspace.gr.pool_data
    )

    if workspace.result:
        return workspace.result

    return handle_success('finished-task')


@task()
def acquire_guest_console_url(guestname: str) -> None:
    task_core(
        cast(DoerType, do_acquire_guest_console_url),
        logger=get_guest_logger('acquire-guest-console-url', _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )


@task(
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.POOL_DATA_REFRESH
)
def refresh_pool_resources_metrics(poolname: str) -> None:
    task_core(
        cast(DoerType, do_refresh_pool_resources_metrics),
        logger=get_pool_logger('refresh-pool-resources-metrics', _ROOT_LOGGER, poolname),
        doer_args=(poolname,)
    )


def do_refresh_pool_resources_metrics_dispatcher(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event
) -> DoerReturnType:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        task='refresh-pool-metrics-dispatcher'
    )

    handle_success('entered-task')

    logger.info('scheduling pool metrics refresh')

    r_pools = get_pools(_ROOT_LOGGER, session)

    if r_pools.is_error:
        handle_failure(r_pools, 'failed to fetch pools')

        return handle_success('finished-task')

    for pool in r_pools.unwrap():
        dispatch_task(
            get_pool_logger('refresh-pool-resources-metrics-dispatcher', _ROOT_LOGGER, pool.poolname),
            refresh_pool_resources_metrics,
            pool.poolname
        )

    return handle_success('finished-task')


@task(
    periodic=periodiq.cron(KNOB_REFRESH_POOL_RESOURCES_METRICS_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC
)
def refresh_pool_resources_metrics_dispatcher() -> None:
    """
    Dispatcher-like task for pool resources metrics refresh. It is being scheduled periodically (by Periodiq),
    and it refreshes nothing on its own - instead, it gets a list of pools, and dispatches the actual refresh
    task for each pool.

    This way, we can use Periodiq (or similar package), which makes it much simpler to run tasks in
    a cron-like fashion, to schedule the task. It does not support this kind of scheduling with different
    parameters, so we have this task that picks parameters for its kids.

    We don't care about rescheduling or retries - this task would be executed again very soon, exponential
    retries would make the metrics more outdated.
    """

    task_core(
        cast(DoerType, do_refresh_pool_resources_metrics_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, 'refresh-pool-resources-dispatcher')
    )


def do_refresh_pool_image_info(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    poolname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        task='refresh-pool-image-info'
    )

    handle_success('entered-task')

    # Handling errors is slightly different in this task. While we fully use `handle_failure()`,
    # we do not return `RESCHEDULE` or `Error()` from this doer. This particular task is being
    # rescheduled regularly anyway, and we probably do not want exponential delays, because
    # they wouldn't make data any fresher when we'd finally succeed talking to the pool.
    #
    # On the other hand, we schedule next iteration of this task here, and it seems to make sense
    # to retry if we fail to schedule it - without this, the "it will run once again anyway" concept
    # breaks down.
    r_pool = _get_pool(logger, session, poolname)

    if r_pool.is_error:
        handle_failure(r_pool, 'failed to load pool')

    else:
        pool = r_pool.unwrap()

        r_refresh = pool.refresh_cached_pool_image_info()

        if r_refresh.is_error:
            handle_failure(r_refresh, 'failed to refresh pool image info')

    return handle_success('finished-task')


@task(
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.POOL_DATA_REFRESH
)
def refresh_pool_image_info(poolname: str) -> None:
    task_core(
        cast(DoerType, do_refresh_pool_image_info),
        logger=get_pool_logger('refresh-pool-image-info', _ROOT_LOGGER, poolname),
        doer_args=(poolname,)
    )


def do_refresh_pool_image_info_dispatcher(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event
) -> DoerReturnType:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        task='refresh-pool-image-info-dispatcher'
    )

    handle_success('entered-task')

    logger.info('scheduling pool image info refresh')

    r_pools = get_pools(_ROOT_LOGGER, session)

    if r_pools.is_error:
        handle_failure(r_pools, 'failed to fetch pools')

        return handle_success('finished-task')

    for pool in r_pools.unwrap():
        dispatch_task(
            get_pool_logger('refresh-pool-image-info-dispatcher', _ROOT_LOGGER, pool.poolname),
            refresh_pool_image_info,
            pool.poolname
        )

    return handle_success('finished-task')


@task(
    periodic=periodiq.cron(KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC
)
def refresh_pool_image_info_dispatcher() -> None:
    """
    Dispatcher-like task for pool image info refresh. It is being scheduled periodically (by Periodiq),
    and it refreshes nothing on its own - instead, it gets a list of pools, and dispatches the actual refresh
    task for each pool.

    This way, we can use Periodiq (or similar package), which makes it much simpler to run tasks in
    a cron-like fashion, to schedule the task. It does not support this kind of scheduling with different
    parameters, so we have this task that picks parameters for its kids.

    We don't care about rescheduling or retries - this task would be executed again very soon, exponential
    retries would make the metrics more outdated.
    """

    task_core(
        cast(DoerType, do_refresh_pool_image_info_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, 'refresh-pool-image-info-dispatcher')
    )


def do_refresh_pool_flavor_info(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event,
    poolname: str
) -> DoerReturnType:
    handle_success, handle_failure, spice_details = create_event_handlers(
        logger,
        session,
        task='refresh-pool-flavor-info'
    )

    handle_success('entered-task')

    # Handling errors is slightly different in this task. While we fully use `handle_failure()`,
    # we do not return `RESCHEDULE` or `Error()` from this doer. This particular task is being
    # rescheduled regularly anyway, and we probably do not want exponential delays, because
    # they wouldn't make data any fresher when we'd finally succeed talking to the pool.
    #
    # On the other hand, we schedule next iteration of this task here, and it seems to make sense
    # to retry if we fail to schedule it - without this, the "it will run once again anyway" concept
    # breaks down.
    r_pool = _get_pool(logger, session, poolname)

    if r_pool.is_error:
        handle_failure(r_pool, 'failed to load pool')

    else:
        pool = r_pool.unwrap()

        r_refresh = pool.refresh_cached_pool_flavor_info()

        if r_refresh.is_error:
            handle_failure(r_refresh, 'failed to refresh pool flavor info')

    return handle_success('finished-task')


@task(priority=TaskPriority.HIGH, queue_name=TaskQueue.POOL_DATA_REFRESH)
def refresh_pool_flavor_info(poolname: str) -> None:
    task_core(
        cast(DoerType, do_refresh_pool_flavor_info),
        logger=get_pool_logger('refresh-pool-flavor-info', _ROOT_LOGGER, poolname),
        doer_args=(poolname,)
    )


def do_refresh_pool_flavor_info_dispatcher(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event
) -> DoerReturnType:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        task='refresh-pool-flavor-info-dispatcher'
    )

    handle_success('entered-task')

    logger.info('scheduling pool flavor info refresh')

    r_pools = get_pools(logger, session)

    if r_pools.is_error:
        handle_failure(r_pools, 'failed to fetch pools')

        return handle_success('finished-task')

    for pool in r_pools.unwrap():
        dispatch_task(
            get_pool_logger('refresh-pool-flavor-info-dispatcher', logger, pool.poolname),
            refresh_pool_flavor_info,
            pool.poolname
        )

    return handle_success('finished-task')


@task(
    periodic=periodiq.cron(KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE.value),
    priority=TaskPriority.HIGH,
    queue_name=TaskQueue.PERIODIC
)
def refresh_pool_flavor_info_dispatcher() -> None:
    """
    Dispatcher-like task for pool flavor info refresh. It is being scheduled periodically (by Periodiq),
    and it refreshes nothing on its own - instead, it gets a list of pools, and dispatches the actual refresh
    task for each pool.

    This way, we can use Periodiq (or similar package), which makes it much simpler to run tasks in
    a cron-like fashion, to schedule the task. It does not support this kind of scheduling with different
    parameters, so we have this task that picks parameters for its kids.

    We don't care about rescheduling or retries - this task would be executed again very soon, exponential
    retries would make the metrics more outdated.
    """

    task_core(
        cast(DoerType, do_refresh_pool_flavor_info_dispatcher),
        logger=TaskLogger(_ROOT_LOGGER, 'refresh-pool-flavor-info-dispatcher')
    )


def do_gc_events(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    cancel: threading.Event
) -> DoerReturnType:
    handle_success, handle_failure, _ = create_event_handlers(
        logger,
        session,
        task='gc-events'
    )

    handle_success('entered-task')

    deadline = datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value)

    logger.info(f'removing events older than {deadline}')

    # TODO: INTERVAL is PostgreSQL-specific. We don't plan to use another DB, but, if we chose to, this would have
    # to be rewritten.
    guest_count_subquery = session.query(  # type: ignore # untyped function "query"
        GuestRequest.guestname
    ).subquery('t')

    query = sqlalchemy \
        .delete(
            GuestEvent.__table__    # type: ignore  # GuestRequest *has* __table__
        ) \
        .where(GuestEvent.guestname.notin_(guest_count_subquery)) \
        .where(sqlalchemy.func.age(GuestEvent.updated) >= sqlalchemy.func.cast(
            '{} SECONDS'.format(KNOB_GC_EVENTS_THRESHOLD.value),
            sqlalchemy.dialects.postgresql.INTERVAL
        ))

    r_execute = safe_call(session.execute, query)

    if r_execute.is_error:
        return handle_failure(r_execute, 'failed to select')

    query_result = cast(
        sqlalchemy.engine.ResultProxy,
        r_execute.unwrap()
    )

    logger.info(f'removed {query_result.rowcount} events')

    return handle_success('finished-task')


@task(
    periodic=periodiq.cron(KNOB_GC_EVENTS_SCHEDULE.value),
    priority=TaskPriority.LOW,
    queue_name=TaskQueue.PERIODIC
)
def gc_events() -> None:
    task_core(
        cast(DoerType, do_gc_events),
        logger=TaskLogger(_ROOT_LOGGER, 'gc-events')
    )
