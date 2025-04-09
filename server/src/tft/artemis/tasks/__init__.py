# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import contextlib
import contextvars
import dataclasses
import datetime
import enum
import functools
import inspect
import os
import random
import threading
from typing import Any, Callable, Dict, Generator, List, Literal, Optional, Tuple, TypeVar, Union, cast

import dramatiq
import dramatiq.broker
import dramatiq.common
import dramatiq.errors
import gluetool.log
import gluetool.utils
import periodiq
import sqlalchemy
import sqlalchemy.dialects.postgresql
import sqlalchemy.orm.exc
import sqlalchemy.orm.session
import stackprinter
from gluetool.result import Error, Ok, Result
from typing_extensions import Protocol, TypedDict

from .. import (
    Failure,
    RSSWatcher,
    Sentry,
    SerializableContainer,
    TracingOp,
    get_broker,
    get_db,
    get_logger,
    get_worker_name,
    log_dict_yaml,
    metrics,
    safe_call,
)
from ..context import CURRENT_MESSAGE, CURRENT_TASK, DATABASE, LOGGER, SESSION, with_context
from ..db import (
    DB,
    DMLResult,
    GuestEvent,
    GuestLog,
    GuestLogContentType,
    GuestLogState,
    GuestRequest,
    GuestShelf,
    SafeQuery,
    SerializedPoolDataMapping,
    SnapshotRequest,
    SSHKey,
    TaskRequest,
    TaskSequenceRequest,
    TransactionResult,
    execute_dml,
    transaction,
)
from ..drivers import (
    PoolDriver,
    PoolLogger,
    aws as aws_driver,
    azure as azure_driver,
    beaker as beaker_driver,
    gcp as gcp_driver,
    ibmcloudpower as ibmcloud_power_driver,
    ibmcloudvpc as ibmcloud_vpc_driver,
    localhost as localhost_driver,
    openstack as openstack_driver,
    rest as rest_driver,
)
from ..guest import GuestLogger, GuestState, ShelfLogger, SnapshotLogger
from ..knobs import Knob
from ..profile import Profiler
from ..script import hook_engine

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
# 2024-11-01: it turns out we can simplify. After recent changes to how transactions are used, and the fact that
# the cancellation event was pretty much unused, offloading task code into its own thread no longer looks necessary.
# Plus, there seem to be some problem with thread A getting stuck when thread B gets spawned while interpreter is
# quitting. Hard to investigate. Therefore we're dropping the cancellation event, and adding an alternative
# implementation that can be enabled to run task code directly in thread A.


# Initialize our top-level objects, database and logger, shared by all threads and in *this* worker.
_ROOT_LOGGER = get_logger()

_ROOT_DB: Optional[DB] = None


def get_root_db(logger: Optional[gluetool.log.ContextAdapter] = None) -> DB:
    global _ROOT_DB

    logger = logger or _ROOT_LOGGER

    if _ROOT_DB is None:
        _ROOT_DB = get_db(logger, application_name=f'worker: {get_worker_name()}')

    return _ROOT_DB


# Initialize the broker instance - this call takes core of correct connection between broker and queue manager.
BROKER = get_broker(_ROOT_LOGGER, application_name=f'worker: {get_worker_name()}')


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
        return TaskPriority[raw_value.upper()].value

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
        return TaskQueue[raw_value.upper()].value

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

KNOB_ACTOR_DEFAULT_SINGLETON_DEADLINE: Knob[int] = Knob(
    'actor.default-singleton-deadline',
    'The biggest possible deadline for a singleton task, in seconds.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_SINGLETON_DEADLINE',
    cast_from_str=int,
    default=300
)

KNOB_ACTOR_DEFAULT_PRIORITY: Knob[int] = Knob(
    'actor.default-priority',
    'Task priority ("HIGH", "DEFAULT", "LOW" or any positive integer).',
    has_db=False,
    envvar='ARTEMIS_ACTOR_DEFAULT_PRIORITY',
    cast_from_str=cast_priority,
    default=TaskPriority.DEFAULT.value,
    default_label='DEFAULT'
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

KNOB_OFFLOAD_TASKS: Knob[bool] = Knob(
    'actor.offload-tasks',
    'When enabled, tasks will run in their own threads.',
    has_db=False,
    envvar='ARTEMIS_OFFLOAD_TASKS',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_TRACE_TASKS_AS_EVENTS: Knob[bool] = Knob(
    'actor.trace-tasks-as-events',
    'When enabled, each task will emit "entered/finished task" event.',
    has_db=False,
    envvar='ARTEMIS_TRACE_TASKS_AS_EVENTS',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

POOL_DRIVERS = {
    'aws': aws_driver.AWSDriver,
    'beaker': beaker_driver.BeakerDriver,
    'localhost': localhost_driver.LocalhostDriver,
    'openstack': openstack_driver.OpenStackDriver,
    'rest': rest_driver.RestDriver,
    'azure': azure_driver.AzureDriver,
    'ibmcloud-vpc': ibmcloud_vpc_driver.IBMCloudVPCDriver,
    'ibmcloud-power': ibmcloud_power_driver.IBMCloudPowerDriver,
    'gcp': gcp_driver.GCPDriver,
}


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


def IGNORE(result: Result[Any, Failure]) -> DoerReturnType:  # noqa: N802
    return Ok(_IgnoreType(result.unwrap_error()))


def FAIL(result: Result[Any, Failure]) -> DoerReturnType:  # noqa: N802
    return Error(result.unwrap_error())


# Task actor type *before* applying `@dramatiq.actor` decorator, which is hidden in our `@task` decorator.
BareActorType = Callable[..., None]

#: A type of a single task argument.
ActorArgumentType = Union[None, str, enum.Enum]

#: A type of name/value container with actor arguments.
NamedActorArgumentsType = Dict[str, ActorArgumentType]


# Task doer type.
class DoerType(Protocol):
    __name__: str

    def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        *args: ActorArgumentType,
        **kwargs: ActorArgumentType
    ) -> DoerReturnType:
        ...


# Task actor type.
class ActorOptions(TypedDict):
    # Retries middleware
    max_retries: Optional[int]
    min_backoff: Optional[int]
    max_backoff: Optional[int]
    retries: Optional[int]
    # TODO: possibly a callable, need to check Dramatiq docs
    retry_when: Any
    throws: Optional[Exception]
    tail_handler: Optional['TailHandler']

    # Singleton middleware
    singleton: bool
    singleton_deadline: int
    singleton_no_retry_on_lock_fail: bool

    # Middleware notes
    artemis_notes: Optional[Dict[str, str]]


class Actor(Protocol):
    actor_name: str
    fn: BareActorType
    queue_name: str
    options: ActorOptions

    def __call__(self, *args: ActorArgumentType) -> None:
        ...

    def send(
        self,
        *args: ActorArgumentType
    ) -> None:
        ...

    def send_with_options(
        self,
        args: Optional[Tuple[ActorArgumentType, ...]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
        delay: Optional[int] = None,
        **options: Any
    ) -> None:
        ...

    def message(
        self,
        *args: ActorArgumentType
    ) -> dramatiq.Message:
        ...

    def message_with_options(
        self,
        args: Optional[Tuple[ActorArgumentType, ...]] = None,
        delay: Optional[int] = None,
        pipe_ignore: bool = False,
        **options: Any
    ) -> dramatiq.Message:
        ...


@dataclasses.dataclass(repr=False)
class TaskCall(SerializableContainer):
    """
    A class bundling together information Artemis has about a particular *executed* task call.
    """

    #: A task callable that has been executed.
    actor: Actor
    #: Arguments given to the task.
    args: Tuple[ActorArgumentType, ...]

    #: Argument names, listed in the same order as arguments in :py:attr:`args`.
    arg_names: Tuple[str, ...]

    delay: Optional[int] = None

    # For tracking messages through logs
    broker_message: Optional[dramatiq.Message] = None
    task_request_id: Optional[int] = None
    task_sequence_request_id: Optional[int] = None

    _named_args: Optional[NamedActorArgumentsType] = None
    _tail_handler: Optional['TailHandler'] = None

    def __repr__(self) -> str:
        formatted_args = [
            str(arg) for arg in self.args
        ]

        if self.delay is not None:
            formatted_args.append(f'delay={self.delay}')

        return f'{self.actor.actor_name}({", ".join(formatted_args)})'

    @property
    def named_args(self) -> NamedActorArgumentsType:
        """
        Returns a mapping between argument names and their values.
        """

        if self._named_args is None:
            self._named_args = {
                name: arg
                for name, arg in zip(self.arg_names, self.args)
            }

        return self._named_args

    def has_args(self, *names: str) -> bool:
        """
        Verifies all given argument names are indeed available in this instance.

        :param names: argument names to verify.
        """

        return all([name in self.named_args for name in names])

    def extract_args(self, *names: str) -> List[ActorArgumentType]:
        """
        Extract all arguments specified by their names.
        """

        return [self.named_args[name] for name in names]

    def logger(
        self,
        logger: gluetool.log.ContextAdapter,
        failure_details: Optional[Dict[str, Any]] = None
    ) -> gluetool.log.ContextAdapter:
        logger = TaskLogger(logger, self.actor.actor_name.replace('_', '-'), message=self.broker_message)

        if self.has_args('guestname'):
            guestname = self.named_args['guestname']

            assert isinstance(guestname, str)

            logger = GuestLogger(logger, guestname)

            if failure_details is not None:
                failure_details['guestname'] = guestname

        if self.has_args('poolname'):
            poolname = self.named_args['poolname']

            assert isinstance(poolname, str)

            logger = PoolLogger(logger, poolname)

            if failure_details is not None:
                failure_details['poolname'] = poolname

        return logger

    @property
    def broker_message_id(self) -> Optional[str]:
        return self.broker_message.message_id if self.broker_message is not None else None

    @property
    def tail_handler(self) -> Optional['TailHandler']:
        return self.actor.options['tail_handler']

    @property
    def has_tail_handler(self) -> bool:
        return self.tail_handler is not None

    @property
    def age(self) -> Optional[float]:
        if self.broker_message is None:
            return None

        return cast(int, dramatiq.common.current_millis() - self.broker_message.message_timestamp) / 1000.0

    @classmethod
    def _construct(
        cls,
        actor: Actor,
        *args: ActorArgumentType,
        delay: Optional[int] = None,
        broker_message: Optional[dramatiq.Message] = None,
        task_request_id: Optional[int] = None,
        task_sequence_request_id: Optional[int] = None
    ) -> 'TaskCall':
        signature = inspect.signature(actor.fn)
        arg_names = tuple(name for name in signature.parameters)

        assert len(signature.parameters) == len(args), 'actor signature parameters does not match message content'

        return TaskCall(
            actor=actor,
            args=args,
            arg_names=arg_names,
            delay=delay,
            broker_message=broker_message,
            task_request_id=task_request_id,
            task_sequence_request_id=task_sequence_request_id
        )

    @classmethod
    def from_message(
        cls,
        broker: dramatiq.broker.Broker,
        broker_message: dramatiq.Message,
        delay: Optional[int] = None,
        task_request_id: Optional[int] = None,
        task_sequence_request_id: Optional[int] = None
    ) -> 'TaskCall':
        return cls._construct(
            cast('Actor', broker.get_actor(broker_message.actor_name)),
            *broker_message.args,
            delay=delay,
            broker_message=broker_message,
            task_request_id=task_request_id,
            task_sequence_request_id=task_sequence_request_id
        )

    @classmethod
    def from_call(
        cls,
        actor: Actor,
        *args: ActorArgumentType,
        delay: Optional[int] = None,
        task_request_id: Optional[int] = None,
        task_sequence_request_id: Optional[int] = None
    ) -> 'TaskCall':
        return cls._construct(
            actor,
            *args,
            delay=delay,
            task_request_id=task_request_id,
            task_sequence_request_id=task_sequence_request_id
        )

    @classmethod
    def from_task_request(
        cls,
        request: TaskRequest
    ) -> Result['TaskCall', Failure]:
        r_actor = resolve_actor(request.taskname)

        if r_actor.is_error:
            return Error(r_actor.unwrap_error())

        return Ok(cls._construct(
            r_actor.unwrap(),
            *request.arguments,
            delay=request.delay,
            task_request_id=request.id,
            task_sequence_request_id=request.task_sequence_request_id
        ))

    def serialize(self) -> Dict[str, Any]:
        return {
            'actor': self.actor.actor_name,
            'args': self.named_args,
            'delay': self.delay,
            'message': {
                'id': self.broker_message_id,
                'age': self.age,
                'queue': self.broker_message.queue_name if self.broker_message else None,
                'options': self.broker_message.options if self.broker_message else {}
            },
            'task-request': {
                'id': self.task_request_id,
                'sequence-id': self.task_sequence_request_id
            }
        }

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'TaskCall':
        raise NotImplementedError


class DispatchTaskType(Protocol):
    def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        task: Actor,
        *args: ActorArgumentType,
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


class MessageLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, message: dramatiq.Message) -> None:
        super().__init__(logger, {
            'ctx_message_id': (5, message.message_id)
        })

    @property
    def message_id(self) -> str:
        return cast(str, self._contexts['message_id'][1])


class TaskLogger(gluetool.log.ContextAdapter):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        task_name: str,
        message: Optional[dramatiq.Message] = None
    ) -> None:
        if not message:
            message_proxy = CURRENT_MESSAGE.get(None)
            message = message_proxy._message if message_proxy is not None else None

        if message:
            logger = MessageLogger(logger, message)

        super().__init__(logger, {
            'ctx_task_name': (30, task_name)
        })

    @property
    def taskname(self) -> str:
        return cast(str, self._contexts['task_name'][1])

    def begin(self, actor_args: Optional[Tuple[ActorArgumentType, ...]] = None) -> None:
        if actor_args is not None:
            self.info(f'beginning: ({", ".join(str(arg) for arg in actor_args)})')

        else:
            self.info('beginning')

    def finished(self) -> None:
        self.info('finished')

    def failed(self, failure: Failure) -> None:
        self.error(f'failed:\n{stackprinter.format(failure.exception)}')


def actor_control_value(actor_name: str, var_name: str, default: Any) -> Any:
    var_value = os.getenv(
        f'ARTEMIS_ACTOR_{actor_name.upper()}_{var_name}',
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
    priority_actual = priority.value
    queue_actual = queue_name.value

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

    # Yep,if it's not in our list, it doesn't meen it's forbidden to use it. Keep the input.
    with contextlib.suppress(KeyError):
        queue_actual = TaskQueue[queue_input.upper()].value

    kwargs = {
        'priority': priority_actual,
        'queue_name': queue_actual,
        'max_retries': int(actor_control_value(actor_name, 'RETRIES', KNOB_ACTOR_DEFAULT_RETRIES_COUNT.value)),
        'min_backoff': int(actor_control_value(actor_name, 'MIN_BACKOFF', KNOB_ACTOR_DEFAULT_MIN_BACKOFF.value)),
        'max_backoff': int(actor_control_value(actor_name, 'MAX_BACKOFF', KNOB_ACTOR_DEFAULT_MAX_BACKOFF.value)),
        'singleton_deadline': int(
            actor_control_value(actor_name, 'SINGLETON_DEADLINE', KNOB_ACTOR_DEFAULT_SINGLETON_DEADLINE.value)
        )
    }

    if periodic is not None:
        kwargs['periodic'] = periodic

    return kwargs


def resolve_actor(actorname: str) -> Result[Actor, Failure]:
    # Some tasks may seem to be unused, but they *must* be imported and known to broker
    # for transactional outbox to work correctly.
    from . import acquire_guest_request  # noqa: F401, isort:skip
    from . import gc_guest_events  # noqa: F401, isort:skip
    from . import guest_request_watchdog  # noqa: F401, isort:skip
    from . import guest_shelf_lookup  # noqa: F401, isort:skip
    from . import prepare_finalize_post_connect  # noqa: F401, isort:skip
    from . import prepare_finalize_pre_connect  # noqa: F401, isort:skip
    from . import prepare_kickstart  # noqa: F401, isort:skip
    from . import prepare_kickstart_wait  # noqa: F401, isort:skip
    from . import prepare_post_install_script  # noqa: F401, isort:skip
    from . import prepare_verify_ssh  # noqa: F401, isort:skip
    from . import preprovision  # noqa: F401, isort:skip
    from . import refresh_pool_avoid_groups_hostnames_dispatcher  # noqa: F401, isort:skip
    from . import refresh_pool_avoid_groups_hostnames  # noqa: F401, isort:skip
    from . import refresh_pool_flavor_info_dispatcher  # noqa: F401, isort:skip
    from . import refresh_pool_flavor_info  # noqa: F401, isort:skip
    from . import refresh_pool_image_info_dispatcher  # noqa: F401, isort:skip
    from . import refresh_pool_image_info  # noqa: F401, isort:skip
    from . import refresh_pool_resources_metrics_dispatcher  # noqa: F401, isort:skip
    from . import refresh_pool_resources_metrics  # noqa: F401, isort:skip
    from . import release_guest_request  # noqa: F401, isort:skip
    from . import release_pool_resources  # noqa: F401, isort:skip
    from . import remove_shelf  # noqa: F401, isort:skip
    from . import return_guest_to_shelf  # noqa: F401, isort:skip
    from . import route_guest_request  # noqa: F401, isort:skip
    from . import shelved_guest_watchdog  # noqa: F401, isort:skip
    from . import trigger_guest_reboot  # noqa: F401, isort:skip
    from . import update_guest_log  # noqa: F401, isort:skip
    from . import update_guest_request  # noqa: F401, isort:skip
    from . import worker_ping  # noqa: F401, isort:skip

    try:
        actor = BROKER.get_actor(actorname)

    except dramatiq.errors.ActorNotFound as exc:
        return Error(Failure.from_exc('failed to find task', exc))

    return Ok(actor)


GuestFieldStates = Dict[
    str,
    Union[str, int, None, datetime.datetime, GuestState, SerializedPoolDataMapping]
]


#: Type variable representing :py:class:_Workspace and its child classes.
WorkspaceBound = TypeVar('WorkspaceBound', bound='Workspace')


def step(fn: Callable[[WorkspaceBound], None]) -> Callable[[WorkspaceBound], WorkspaceBound]:
    """
    Mark a function as a "task step".

    A task step accepts only the workspace and returns nothing. Wrapper provided by the decorator
    would test workspaces ``result`` property, and would not call the decorated function if ``result``
    is no longer ``None``.

    After calling the decorated function, wrapper returns the workspace itself. Together with the ``result``
    test, this allows for chaining of steps since once ``result`` is set, no following steps would be executed.

    .. code-block:: python

       @step
       def foo(workspace: Workspace) -> None:
           workspace.bar()

    :param fn: callable.
    """

    @functools.wraps(fn)
    def wrapper(workspace: WorkspaceBound) -> WorkspaceBound:
        """
        Wrapper for the decorated function.

        :param self: workspace to pass to the decorated function.
        """

        if workspace.result:
            return workspace

        fn(workspace)

        return workspace

    return wrapper


# Implementing the decorator as a class on purpose - it plays nicely with type annotations when used without
# any arguments.
class task:  # noqa: N801
    def __init__(
        self,
        priority: TaskPriority = TaskPriority.DEFAULT,
        queue_name: TaskQueue = TaskQueue.DEFAULT,
        periodic: Optional[periodiq.CronSpec] = None,
        tail_handler: Optional['TailHandler'] = None,
        singleton: bool = False,
        singleton_no_retry_on_lock_fail: bool = False
    ) -> None:
        self.priority = priority
        self.queue_name = queue_name
        self.periodic = periodic

        self.tail_handler = tail_handler

        self.singleton = singleton
        self.singleton_no_retry_on_lock_fail = singleton_no_retry_on_lock_fail

    def __call__(self, fn: BareActorType) -> Actor:
        actor_name_uppersized = fn.__name__.upper()

        dramatiq_kwargs = actor_kwargs(
            actor_name_uppersized,
            periodic=self.periodic,
            priority=self.priority,
            queue_name=self.queue_name
        )

        dramatiq_actor = dramatiq.actor(
            fn,
            tail_handler=self.tail_handler,
            singleton=self.singleton,
            singleton_no_retry_on_lock_fail=self.singleton_no_retry_on_lock_fail,
            **dramatiq_kwargs
        )

        return cast(Actor, dramatiq_actor)


def run_doer_multithread(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    fn: DoerType,
    actor_name: str,
    *args: ActorArgumentType,
    **kwargs: Any
) -> DoerReturnType:
    """
    Run a given function - "doer" - isolated in its own thread. This thread then serves as a landing
    spot for dramatiq control exceptions (e.g. Shutdown).

    Control exceptions are delivered to the thread that runs the task. We don't want to interrupt
    the actual task code, which is hidden in the doer, so we offload it to a separate thread, and catch
    exceptions here.
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

        logger.debug(f'submitting task doer {fn.__name__}')

        # We need to propagate our current context to newly spawned thread. To do that, we need to copy our context,
        # and then use its `run()` method instead of the function we'd run in our new thread. `run()` would then
        # do its setup and call our function when context is set properly.
        thread_context = contextvars.copy_context()

        def _thread_trampoline() -> DoerReturnType:
            profile_actor = gluetool.utils.normalize_bool_option(actor_control_value(actor_name, 'PROFILE', False))
            verbose_profile = gluetool.utils.normalize_bool_option(
                actor_control_value(actor_name, 'VERBOSE_PROFILE', False)
            )

            if profile_actor:
                profiler = Profiler(verbose=verbose_profile)
                profiler.start()

            try:
                return thread_context.run(fn, logger, db, session, *args, **kwargs)

            finally:
                if profile_actor:
                    profiler.stop()
                    profiler.log(logger, 'profiling report (inner)')

        doer_future = executor.submit(_thread_trampoline)

        _wait('doer finished in regular mode')

    except dramatiq.middleware.Interrupt as exc:
        if isinstance(exc, dramatiq.middleware.TimeLimitExceeded):
            logger.error('task time depleted')

        elif isinstance(exc, dramatiq.middleware.Shutdown):
            logger.error('worker shutdown requested')

        else:
            assert False, 'Unhandled interrupt exception'

        logger.debug('waiting for doer to finish')

        _wait('doer finished in cancellation mode')

    assert doer_future is not None
    assert doer_future.done(), 'doer finished yet not marked as done'

    if executor:
        executor.shutdown()

    return doer_future.result()


def run_doer_singlethread(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
    fn: DoerType,
    actor_name: str,
    *args: ActorArgumentType,
    **kwargs: Any
) -> DoerReturnType:
    """
    Run a given function - "doer" - in the current thread.

    Unlike the multithreaded variant, we are using a single thread which needs to take care of
    catching and handling exceptions as well as doing the work. Control exceptions are delivered to
    this thread.
    """

    logger.debug(f'starting {fn.__name__} doer')

    profile_actor = gluetool.utils.normalize_bool_option(actor_control_value(actor_name, 'PROFILE', False))
    verbose_profile = gluetool.utils.normalize_bool_option(actor_control_value(actor_name, 'VERBOSE_PROFILE', False))

    try:
        logger.debug(f'submitting task doer {fn.__name__}')

        if profile_actor:
            profiler = Profiler(verbose=verbose_profile)
            profiler.start()

        with Sentry.start_span(
            TracingOp.FUNCTION,
            description='run_doer',
            tags={
                'taskname': fn.__name__
            }
        ):
            result = fn(logger, db, session, *args, **kwargs)

    except dramatiq.middleware.Interrupt as exc:
        logger.debug('doer interrupted')

        if profile_actor:
            profiler.stop()
            profiler.log(logger, 'profiling report (inner)')

        if isinstance(exc, dramatiq.middleware.TimeLimitExceeded):
            failure = Failure.from_exc(
                'task time depleted',
                exc
            )

        elif isinstance(exc, dramatiq.middleware.Shutdown):
            failure = Failure.from_exc(
                'worker shutdown requested',
                exc
            )

        else:
            failure = Failure('unhandled interrupt exception')

        failure.handle(logger)

        return Error(failure)

    else:
        logger.debug(f'doer finished with {result}')

        if profile_actor:
            profiler.stop()
            profiler.log(logger, 'profiling report (inner)')

        return result


run_doer = run_doer_multithread if KNOB_OFFLOAD_TASKS.value else run_doer_singlethread


def _task_core(
    doer: DoerType,
    logger: TaskLogger,
    db: Optional[DB] = None,
    session: Optional[sqlalchemy.orm.session.Session] = None,
    doer_args: Optional[Tuple[ActorArgumentType, ...]] = None,
    doer_kwargs: Optional[Dict[str, Any]] = None,
    session_isolation: bool = True,
    session_read_only: bool = False
) -> None:
    rss = RSSWatcher()

    logger.begin(actor_args=doer_args)

    logger.info(f'[{os.getpid()}] {rss.format()}')  # noqa: FS002

    # TODO: implement a proper decorator, or merge this into @task decorator - but @task seems to be flawed,
    # which requires a fix, therefore merge this into @task once it gets fixed.
    caller_frame = inspect.stack()[2]

    actor_name = caller_frame.frame.f_code.co_name

    profile_actor = gluetool.utils.normalize_bool_option(actor_control_value(actor_name, 'PROFILE', False))
    verbose_profile = gluetool.utils.normalize_bool_option(actor_control_value(actor_name, 'VERBOSE_PROFILE', False))

    if profile_actor:
        profiler = Profiler(verbose=verbose_profile)
        profiler.start()

    db = db or get_root_db()

    doer_args = doer_args or tuple()
    doer_kwargs = doer_kwargs or dict()

    doer_result: DoerReturnType = Error(Failure('undefined doer result'))

    # Updating context - this function is the entry point into Artemis code, therefore context
    # is probably left empty or with absolutely wrong objects.

    LOGGER.set(logger)
    DATABASE.set(db)

    # Small helper so we can keep all session-related stuff inside one block, and avoid repetition or more than
    # one `get_session()` call.
    def _run_doer(session: sqlalchemy.orm.session.Session) -> DoerReturnType:
        SESSION.set(session)

        assert db is not None
        assert doer_args is not None
        assert doer_kwargs is not None

        doer_result = run_doer(
            logger,
            db,
            session,
            doer,
            actor_name,
            *doer_args,
            **doer_kwargs
        )

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
            # TODO: poolname=?
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

        # State change succeeded, and changed exactly the request we're working with. There is nothing left to do,
        # we proceed by propagating the original "ignore" result, closing the chapter.
        return doer_result

    try:
        if session is None:
            with db.get_session(logger, read_only=session_read_only) as session:
                doer_result = _run_doer(session)

        else:
            doer_result = _run_doer(session)

    except Exception as exc:
        failure = Failure.from_exc('unhandled doer exception', exc)
        failure.handle(logger)

        doer_result = Error(failure)

    if profile_actor:
        profiler.stop()
        profiler.log(logger, 'profiling report (outer)')

    CURRENT_TASK.set(None)

    if doer_result.is_ok:
        result = doer_result.unwrap()

        if is_ignore_result(doer_result):
            logger.warning('message processing encountered error and requests waiver')

        rss.snapshot()
        logger.info(f'[{os.getpid()}] {rss.format()}')  # noqa: FS002

        logger.finished()

        if result is Reschedule:
            raise Exception('message processing requested reschedule')

        return

    rss.snapshot()
    logger.info(f'[{os.getpid()}] {rss.format()}')  # noqa: FS002

    # To avoid chain a of exceptions in the log - which we already logged above - raise a generic,
    # insignificant exception to notify scheduler that this task failed and needs to be retried.
    raise Exception(f'message processing failed: {doer_result.unwrap_error().message}')


def task_core(
    doer: DoerType,
    logger: TaskLogger,
    db: Optional[DB] = None,
    session: Optional[sqlalchemy.orm.session.Session] = None,
    doer_args: Optional[Tuple[ActorArgumentType, ...]] = None,
    doer_kwargs: Optional[Dict[str, Any]] = None,
    session_isolation: bool = True,
    session_read_only: bool = False
) -> None:
    task_call = TaskCall.from_message(BROKER, CURRENT_MESSAGE.get())

    CURRENT_TASK.set(task_call)

    with Sentry.start_transaction(
        TracingOp.QUEUE_TASK,
        'task',
        tags={
            'taskname': task_call.actor.actor_name
        },
        data={
            'task_call': task_call.serialize()
        }
    ) as tracing_transaction:
        if 'poolname' in task_call.named_args:
            tracing_transaction.set_tag('poolname', task_call.named_args['poolname'])

        with Sentry.start_span(
            TracingOp.FUNCTION,
            description='run_task',
            tags={
                'taskname': task_call.actor.actor_name
            },
            data={
                'task_call': task_call.serialize()
            }
        ) as tracing_span:
            if 'poolname' in task_call.named_args:
                tracing_span.set_tag('poolname', task_call.named_args['poolname'])

            _task_core(
                doer,
                logger,
                db,
                session=session,
                doer_args=doer_args,
                doer_kwargs=doer_kwargs,
                session_isolation=session_isolation,
                session_read_only=session_read_only
            )


def _randomize_delay(delay: int) -> int:
    """
    Modify a given delay by a randomized value withing spread specified by :py:const:`KNOB_DELAY_UNIFORM_SPREAD`.
    """

    # Use `max()` to always return positive delay - if `delay == 0`, then the randomized delay could
    # fall bellow zero, and that does not seem to be a good practice.
    return max(0, delay + int(random.uniform(-KNOB_DELAY_UNIFORM_SPREAD.value, KNOB_DELAY_UNIFORM_SPREAD.value)))


def serialize_task_invocation(
    task: TaskCall
) -> Dict[str, Any]:
    return {
        'tasks': task.serialize()
    }


def serialize_task_group_invocation(
    tasks: List[TaskCall],
    on_complete: Optional[TaskCall] = None
) -> Dict[str, Any]:
    return {
        'group': [task_call.serialize() for task_call in tasks],
        'on-complete': on_complete.serialize() if on_complete is not None else None
    }


def serialize_task_sequence_invocation(
    tasks: List[TaskCall],
    on_complete: Optional[TaskCall] = None
) -> Dict[str, Any]:
    return {
        'sequence': [task_call.serialize() for task_call in tasks],
        'on-complete': on_complete.serialize() if on_complete is not None else None
    }


def dispatch_task(
    logger: gluetool.log.ContextAdapter,
    task: Actor,
    *args: ActorArgumentType,
    delay: Optional[int] = None,
    task_request_id: Optional[int] = None
) -> Result[None, Failure]:
    """
    Dispatch a given task.

    :param logger: logger to use for logging.
    :param task: callable, a Dramatiq task, to dispatch.
    :param args: positional parameters to pass to the task.
    :param delay: if set, the task will be delayed by this many seconds.
    """

    message = task.message(*args)

    # The underlying Dramatiq code treats delay as miliseconds, hence the multiplication.
    actual_delay = _randomize_delay(delay) * 1000 if delay is not None else None

    task_call = TaskCall.from_message(BROKER, message, delay=delay, task_request_id=task_request_id)

    with Sentry.start_span(
        TracingOp.QUEUE_SUBMIT,
        description='dispatch_task',
        tags={
            'taskname': task_call.actor.actor_name
        },
        data={
            'task_call': task_call.serialize()
        }
    ):
        r = safe_call(BROKER.enqueue, message, delay=actual_delay)

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to dispatch task',
            r.unwrap_error(),
            task_call=task_call
        ))

    log_dict_yaml(logger.info, 'scheduled task', serialize_task_invocation(task_call))

    if KNOB_CLOSE_AFTER_DISPATCH.value:
        logger.debug('closing broker connection as requested')

        BROKER.connection.close()

    return Ok(None)


def dispatch_group(
    logger: gluetool.log.ContextAdapter,
    tasks: List[Actor],
    *args: ActorArgumentType,
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

    # The underlying Dramatiq code treats delay as miliseconds, hence the multiplication.
    actual_delay = _randomize_delay(delay) * 1000 if delay is not None else None

    try:
        messages = [
            task.message(*args)
            for task in tasks
        ]

        task_calls: List[TaskCall] = [
            TaskCall.from_message(BROKER, message, delay=delay)
            for message in messages
        ]

        on_complete_task_call: Optional[TaskCall] = None

        group = dramatiq.group(messages)

        if on_complete:
            on_complete_message = on_complete.message(*args)
            on_complete_task_call = TaskCall.from_message(BROKER, on_complete_message)

            group.add_completion_callback(on_complete_message)

        group.run(delay=actual_delay)

        log_dict_yaml(
            logger.info,
            'scheduled group',
            serialize_task_group_invocation(task_calls, on_complete=on_complete_task_call)
        )

        if KNOB_CLOSE_AFTER_DISPATCH.value:
            logger.debug('closing broker connection as requested')

            BROKER.connection.close()

    except Exception as exc:
        return Error(Failure.from_exc(
            'failed to dispatch group',
            exc,
            group_tasks=task_calls,
            group_on_complete=on_complete_task_call
        ))

    return Ok(None)


def dispatch_sequence(
    logger: gluetool.log.ContextAdapter,
    tasks: List[Tuple[Optional[int], Actor, Tuple[ActorArgumentType, ...]]],
    on_complete: Optional[Tuple[Actor, Tuple[ActorArgumentType, ...]]] = None,
    delay: Optional[int] = None,
    task_sequence_request_id: Optional[int] = None
) -> Result[None, Failure]:
    """
    Dispatch given tasks as a pipeline.

    Based on Dramatiq's :py:class:`dramatiq.pipeline` implementation, but since we are
    not interested in task results, "sequence" is more fitting.

    :param logger: logger to use for logging.
    :param tasks: list of callables, Dramatiq tasks, to dispatch, with their arguments.
    :param on_complete: a task to dispatch when the last task completes.
    :param delay: if set, the task will be delayed by this many seconds.
    """

    # The underlying Dramatiq code treats delay as miliseconds, hence the multiplication.
    actual_delay = _randomize_delay(delay) * 1000 if delay is not None else None

    # Add `pipe_ignore` to disable result propagation. We ignore task results.
    messages = [
        task.message_with_options(args=args, pipe_ignore=True)
        for _, task, args in tasks
    ]

    task_calls: List[TaskCall] = [
        TaskCall.from_message(
            BROKER,
            message,
            task_request_id=task_request_id,
            task_sequence_request_id=task_sequence_request_id
        )
        for (task_request_id, _, _), message in zip(tasks, messages)
    ]

    on_complete_task_call: Optional[TaskCall] = None

    pipeline = dramatiq.pipeline(messages)

    if on_complete:
        on_complete_message = on_complete[0].message_with_options(args=on_complete[1], pipe_ignore=True)
        on_complete_task_call = TaskCall.from_message(BROKER, on_complete_message)

        pipeline = pipeline | on_complete_message

    with Sentry.start_span(
        TracingOp.QUEUE_SUBMIT,
        description='dispatch_sequence',
        data={
            'task_calls': serialize_task_sequence_invocation(task_calls, on_complete_task_call)
        }
    ):
        r = safe_call(pipeline.run, delay=actual_delay)

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to dispatch task sequence',
            r.unwrap_error(),
            task_calls=serialize_task_sequence_invocation(task_calls, on_complete_task_call)
        ))

    log_dict_yaml(
        logger.info,
        'scheduled sequence',
        serialize_task_sequence_invocation(task_calls, on_complete=on_complete_task_call)
    )

    if KNOB_CLOSE_AFTER_DISPATCH.value:
        logger.debug('closing broker connection as requested')

        BROKER.connection.close()

    return Ok(None)


def _request_task(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    task: Actor,
    *task_arguments: ActorArgumentType,
    delay: Optional[int] = None,
    task_sequence_request_id: Optional[int] = None
) -> Result[None, Failure]:
    r = TaskRequest.create(
        logger,
        session,
        task,
        *task_arguments,
        delay=delay,
        task_sequence_request_id=task_sequence_request_id
    )

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to add task request',
            r.unwrap_error(),
            task_name=task.actor_name,
            task_args=task_arguments,
            task_sequence_request_id=task_sequence_request_id
        ))

    task_request_id = r.unwrap()

    if task_sequence_request_id is None:
        log_dict_yaml(
            logger.info,
            f'requested task #{task_request_id}',
            TaskCall.from_call(task, *task_arguments, delay=delay, task_request_id=task_request_id).serialize()
        )

    else:
        log_dict_yaml(
            logger.info,
            f'requested task #{task_sequence_request_id}/#{task_request_id}',
            TaskCall.from_call(task, *task_arguments, delay=delay, task_request_id=task_request_id).serialize()
        )

    return Ok(None)


def _request_task_sequence(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    tasks: List[Tuple[Actor, Tuple[ActorArgumentType, ...]]],
    delay: Optional[int] = None
) -> Result[None, Failure]:
    r = TaskSequenceRequest.create(logger, session)

    if r.is_error:
        return Error(Failure.from_failure(
            'failed to add task sequence request',
            r.unwrap_error()
        ))

    task_sequence_request_id = r.unwrap()

    logger.info(f'requested task sequence #{task_sequence_request_id}')

    for i, (task, task_arguments) in enumerate(tasks):
        if i == 0:
            r_task = _request_task(
                logger,
                session,
                task,
                *task_arguments,
                delay=delay,
                task_sequence_request_id=task_sequence_request_id
            )

        else:
            r_task = _request_task(
                logger,
                session,
                task,
                *task_arguments,
                task_sequence_request_id=task_sequence_request_id
            )

        if r_task.is_error:
            return Error(Failure.from_failure(
                'failed to add task request',
                r_task.unwrap_error()
            ))

    return Ok(None)


def _guest_state_update_query(
    guestname: str,
    new_state: GuestState,
    current_state: Optional[GuestState] = None,
    set_values: Optional[GuestFieldStates] = None,
    current_pool_data: Optional[SerializedPoolDataMapping] = None
) -> Result[sqlalchemy.Update, Failure]:
    """
    Create an ``UPDATE`` query for guest request state change.

    :param guestname: name of the guest request to update.
    :param new_state: desired new state.
    :param current_state: if set, the query will make change only if the request is in this state when the query
        is executed.
    :param set_values: optional fields to update along with the state.
    :param current_pool_data: if set, the query will make change only if the request's pool data match these when
        the query is executed.
    :returns: an ``UPDATE`` query reflecting the requested changes.
    """

    now = datetime.datetime.utcnow()

    query = sqlalchemy \
        .update(GuestRequest) \
        .where(GuestRequest.guestname == guestname)

    if current_state is not None:
        query = query.where(GuestRequest.state == current_state)

    if current_pool_data:
        query = query.where(GuestRequest._pool_data == current_pool_data)

    if set_values:
        values = set_values
        values.update({
            'state': new_state,
            'state_mtime': now
        })

    else:
        values = {
            'state': new_state,
            'state_mtime': now
        }

    query = query.values(**values)

    return Ok(query)


def _update_guest_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    new_state: GuestState,
    current_state: Optional[GuestState] = None,
    set_values: Optional[GuestFieldStates] = None,
    poolname: Optional[str] = None,
    current_pool_data: Optional[SerializedPoolDataMapping] = None,
    **details: Any
) -> Result[None, Failure]:
    current_state_label = current_state.value if current_state is not None else '<ignored>'

    def handle_error(r: Result[Any, Failure], message: str) -> Result[None, Failure]:
        assert r.is_error

        return Error(
            Failure.from_failure(
                message,
                r.unwrap_error(),
                current_state=current_state_label,
                new_state=new_state.value
            ).update(poolname=poolname, **details)
        )

    logger.warning(f'state switch: {current_state_label} => {new_state.value}')

    r_query = _guest_state_update_query(
        guestname=guestname,
        new_state=new_state,
        current_state=current_state,
        set_values=set_values,
        current_pool_data=current_pool_data
    )

    if r_query.is_error:
        return handle_error(r_query, 'failed to create state update query')

    r_execute: DMLResult[GuestRequest] = execute_dml(logger, session, r_query.unwrap())

    if r_execute.is_error:
        return handle_error(r_execute, 'failed to switch guest state')

    logger.warning(f'state switch: {current_state_label} => {new_state.value}: proposed')

    GuestRequest.log_event_by_guestname(
        logger,
        session,
        guestname,
        'state-changed',
        new_state=new_state.value,
        current_state=current_state_label,
        poolname=poolname,
        **details,
    )

    # TODO: dubious without immediate commit
    metrics.ProvisioningMetrics.inc_guest_state_transition(poolname, current_state, new_state)

    return Ok(None)


def _update_guest_state_and_request_task(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    new_state: GuestState,
    task: Actor,
    *task_arguments: ActorArgumentType,
    current_state: Optional[GuestState] = None,
    set_values: Optional[GuestFieldStates] = None,
    poolname: Optional[str] = None,
    current_pool_data: Optional[SerializedPoolDataMapping] = None,
    delay: Optional[int] = None,
    **details: Any
) -> Result[None, Failure]:
    current_state_label = current_state.value if current_state is not None else '<ignored>'

    def handle_error(r: Result[Any, Any], message: str) -> Result[None, Failure]:
        assert r.is_error

        return Error(
            Failure.from_failure(
                message,
                r.unwrap_error(),
                current_state=current_state_label,
                new_state=new_state.value,
                task_name=task.actor_name,
                task_args=task_arguments
            ).update(poolname=poolname, **details)
        )

    logger.warning(f'state switch: {current_state_label} => {new_state.value}')

    r_state_update_query = _guest_state_update_query(
        guestname=guestname,
        new_state=new_state,
        current_state=current_state,
        set_values=set_values,
        current_pool_data=current_pool_data
    )

    if r_state_update_query.is_error:
        return handle_error(r_state_update_query, 'failed to create state update query')

    r_execute: DMLResult[GuestRequest] = execute_dml(logger, session, r_state_update_query.unwrap())

    if r_execute.is_error:
        return handle_error(r_execute, 'failed to switch guest state')

    logger.warning(f'state switch: {current_state_label} => {new_state.value}: proposed')

    r_task = _request_task(logger, session, task, *task_arguments, delay=delay)

    if r_task.is_error:
        return handle_error(r_task, 'failed to add task request')

    GuestRequest.log_event_by_guestname(
        logger,
        session,
        guestname,
        'state-changed',
        new_state=new_state.value,
        current_state=current_state_label,
        poolname=poolname,
        **details,
    )

    # TODO: without immediate commit, these two are dubious...
    # logger.warning(f'state switch: {current_state_label} => {new_state.value}: succeeded')
    metrics.ProvisioningMetrics.inc_guest_state_transition(poolname, current_state, new_state)

    return Ok(None)


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


def get_shelf_logger(
    task_name: str,
    logger: gluetool.log.ContextAdapter,
    shelfname: str,
) -> TaskLogger:
    return TaskLogger(
        ShelfLogger(logger, shelfname),
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


# TODO: all of the helpers could be converted to chainable methods, suitable for direct use with `step` decorator.
# That's something to work on, then we could call them directly from tasks. And test them, that would be also cool...
# But that needs a bit of support from type annotations, because the methods below often take many arguments, and we
# *must* preserve their signatures.
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

    logger: gluetool.log.ContextAdapter
    session: sqlalchemy.orm.session.Session
    guestname: Optional[str]
    task: Optional[str]
    db: DB

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: Optional[str] = None,
        task: Optional[str] = None,
        db: Optional[DB] = None,
        **default_details: Any
    ) -> None:
        self.logger = logger
        self.db = db or get_root_db(logger)
        self.session = session

        self.result: Optional[DoerReturnType] = None

        self.guestname: Optional[str] = guestname
        self.snapshotname: Optional[str] = None

        self.gr: Optional[GuestRequest] = None
        self.sr: Optional[SnapshotRequest] = None
        self.shelf: Optional[GuestShelf] = None
        self.ssh_key: Optional[SSHKey] = None
        self.pool: Optional[PoolDriver] = None
        self.is_pool_enabled: Optional[bool] = None
        self.guest_events: Optional[List[GuestEvent]] = None

        self.pools: List[PoolDriver] = []
        self.master_key: Optional[SSHKey] = None

        self.shelfname: Optional[str] = None

        self.spice_details: Dict[str, Any] = {**default_details}

        if task:
            self.spice_details['task'] = task

    @property
    def final_result(self) -> DoerReturnType:
        """
        Return result stored in this workspace.

        This property shall report tasks that fail to set any result - tasks' last step should be setting
        workspace's :py:attr:`result` to a valid result, usually :py:data:`SUCCESS`.

        :returns: value of :py:attr:`result`, or an error when ``result`` is still ``None``.
        """

        if self.result:
            return self.result

        return Error(Failure('task did not produce final result'))

    def _event(self, event: str, **details: Any) -> None:
        log_dict_yaml(self.logger.info, 'logged event', {
            'eventname': event,
            'details': details
        })

    def _guest_request_event(self, event: str, **details: Any) -> None:
        assert self.guestname

        GuestRequest.log_event_by_guestname(
            self.logger,
            self.session,
            self.guestname,
            event,
            **self.spice_details,
            **details
        )

    @contextlib.contextmanager
    def transaction(self) -> Generator[TransactionResult, None, None]:
        with transaction(self.logger, self.session) as t:
            yield t

        if not t.complete:
            assert t.failure is not None  # narrow type

            self.fail(t.failure, 'failed to complete transaction')

    def _begin(self) -> None:
        if self.guestname:
            if KNOB_TRACE_TASKS_AS_EVENTS.value:
                self._guest_request_event('entered-task')

            else:
                self._event('entered-task')

        else:
            self._event('entered-task')

    def begin(self: WorkspaceBound) -> WorkspaceBound:
        if self.guestname:
            with self.transaction():
                self._guest_request_event('entered-task')

        else:
            self._event('entered-task')

        return self

    def _progress(self, eventname: str, **details: Any) -> None:
        if self.guestname:
            self._guest_request_event(eventname, **details)

        else:
            self._event(eventname, **details)

    def _complete(self) -> None:
        if self.guestname:
            if KNOB_TRACE_TASKS_AS_EVENTS.value:
                self._guest_request_event('finished-task')

            else:
                self._event('finished-task')

        else:
            self._event('finished-task')

        if not self.result:
            self.result = SUCCESS

    def complete(self: WorkspaceBound) -> WorkspaceBound:
        if self.guestname:
            with self.transaction():
                self._guest_request_event('finished-task')

        else:
            self._event('finished-task')

        if not self.result:
            self.result = SUCCESS

        return self

    def _reschedule(self) -> None:
        if self.guestname:
            if KNOB_TRACE_TASKS_AS_EVENTS.value:
                self._guest_request_event('rescheduled')

            else:
                self._event('rescheduled')

        else:
            self._event('rescheduled')

        if not self.result:
            self.result = RESCHEDULE

    def _fail(
        self,
        failure: Failure,
        label: str,
        no_effect: bool = False
    ) -> None:
        failure.handle(self.logger, label=label, sentry=True, guestname=self.guestname, **self.spice_details)

        if self.guestname:
            GuestRequest.log_error_event_by_guestname(
                self.logger,
                self.session,
                self.guestname,
                label,
                failure
            )

        else:
            self._event(label, failure=failure.get_event_details())

        if not no_effect:
            if failure.recoverable is True:
                self.result = Error(failure)

            else:
                self.result = IGNORE(Error(failure))

    def fail(
        self,
        failure: Failure,
        label: str,
        no_effect: bool = False
    ) -> None:
        with self.transaction():
            self._fail(failure, label, no_effect=no_effect)

    def _error(
        self,
        error: Result[Any, Failure],
        label: str,
        no_effect: bool = False
    ) -> None:
        self._fail(error.unwrap_error(), label, no_effect=no_effect)

    def update_guest_state(
        self,
        new_state: GuestState,
        current_state: Optional[GuestState] = None,
        set_values: Optional[GuestFieldStates] = None,
        poolname: Optional[str] = None,
        current_pool_data: Optional[SerializedPoolDataMapping] = None,
        **details: Any
    ) -> None:
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
            poolname=poolname or (self.gr.poolname if self.gr else None),
            current_pool_data=current_pool_data,
            **details
        )

        if r.is_error:
            self._error(r, 'failed to update guest request')

    #
    #
    #

    def load_guest_request(
        self: WorkspaceBound,
        guestname: str,
        state: Optional[GuestState] = None
    ) -> WorkspaceBound:
        """ Load a guest request from a database, as long as it is in a given state. """

        if self.result:
            return self

        self.guestname = guestname

        if state is None:
            r = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.guestname == guestname) \
                .one_or_none()

        else:
            r = SafeQuery.from_session(self.session, GuestRequest) \
                .filter(GuestRequest.guestname == guestname) \
                .filter(GuestRequest.state == state) \
                .one_or_none()

        if r.is_error:
            self._error(r, 'failed to load guest request')
            return self

        gr = r.unwrap()

        if not gr:
            self._complete()
            return self

        self.gr = gr

        self.mark_note_poolname()

        return self

    def load_master_ssh_key(self: WorkspaceBound) -> WorkspaceBound:
        if self.result:
            return self

        r = _get_ssh_key('artemis', 'master-key')

        if r.is_error:
            self._error(r, 'failed to get master SSH key')
            return self

        self.master_key = r.unwrap()

        if self.master_key is None:
            self._fail(
                Failure(
                    'no such SSH key',
                    ownername='artemis',
                    keyname='master-key'
                ),
                'failed to find SSH key'
            )
            return self

        return self

    def load_shelf(self, shelfname: str, state: Optional[GuestState] = None) -> None:
        if self.result:
            return

        self.shelfname = shelfname

        query = SafeQuery.from_session(self.session, GuestShelf) \
            .filter(GuestShelf.shelfname == shelfname)

        if state is not None:
            query = query.filter(GuestShelf.state == state)

        r = query.one_or_none()

        if r.is_error:
            self._error(r, 'failed to load shelf')
            return

        shelf = r.unwrap()

        if not shelf:
            self.result = SUCCESS
            return

        self.shelf = shelf

    def load_gr_pool(self: WorkspaceBound) -> WorkspaceBound:
        """
        Load a pool as specified by a guest request.
        """

        if self.result:
            return self

        assert self.gr
        assert self.gr.poolname is not None

        r = PoolDriver.load(self.logger, self.session, self.gr.poolname)

        if r.is_error:
            self._error(r, 'pool sanity failed')
            return self

        self.pool = r.unwrap()

        return self

    def test_pool_enabled(self: WorkspaceBound) -> WorkspaceBound:
        if self.result:
            return self

        assert self.pool

        r = self.pool.is_enabled(self.session)

        if r.is_error:
            self._error(r, 'pool enablement check failed')
            return self

        self.is_pool_enabled = r.unwrap()

        return self

    def load_guest_events(self, eventname: Optional[str] = None) -> None:
        if self.result:
            return

        assert self.guestname

        r_events = GuestEvent.fetch(
            self.session,
            eventname=eventname,
            guestname=self.guestname
        )

        if r_events.is_error:
            return self._error(r_events, 'failed to fetch events')

        self.guest_events = r_events.unwrap()

    def dispatch_task(
        self,
        task: Actor,
        *args: Any,
        delay: Optional[int] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None
    ) -> None:
        if self.result:
            return

        logger = logger or self.logger

        r = dispatch_task(logger, task, *args, delay=delay)

        if r.is_error:
            self._error(r, 'failed to dispatch task')

    def request_task(
        self,
        task: Actor,
        *task_arguments: ActorArgumentType,
        delay: Optional[int] = None
    ) -> None:
        if self.result:
            return

        r = _request_task(self.logger, self.session, task, *task_arguments, delay=delay)

        if r.is_error:
            self._error(r, 'failed to create task request')

    def request_task_sequence(
        self,
        tasks: List[Tuple[Actor, Tuple[ActorArgumentType, ...]]],
        delay: Optional[int] = None
    ) -> None:
        if self.result:
            return

        r = _request_task_sequence(self.logger, self.session, tasks, delay=delay)

        if r.is_error:
            self._error(r, 'failed to create task sequence request')

    def run_hook(self, hook_name: str, **kwargs: Any) -> Result[Any, Failure]:
        r_engine = hook_engine(hook_name)

        if r_engine.is_error:
            return Error(Failure.from_failure(f'failed to load {hook_name} hook', r_engine.unwrap_error()))

        engine = r_engine.unwrap()

        with Sentry.start_span(
            TracingOp.FUNCTION,
            description='run_hook',
            tags={
                'hookname': hook_name
            }
        ):
            try:
                r = engine.run_hook(
                    hook_name,
                    logger=self.logger,
                    **kwargs
                )

            except Exception as exc:
                r = Error(Failure.from_exc('unhandled hook error', exc))

        return r

    def load_pools(self: WorkspaceBound) -> WorkspaceBound:
        if self.result:
            return self

        r_pools = PoolDriver.load_all(self.logger, self.session)

        if r_pools.is_error:
            self._error(r_pools, 'failed to fetch pools')
            return self

        self.pools = r_pools.unwrap()

        return self

    def mark_note_poolname(self: WorkspaceBound) -> WorkspaceBound:
        if self.result:
            return self

        from ..middleware import NOTE_POOLNAME, set_message_note

        assert self.gr

        if self.gr.poolname:
            set_message_note(NOTE_POOLNAME, self.gr.poolname)

            self.spice_details['poolname'] = self.gr.poolname

        return self

    def update_guest_state_and_request_task(
        self: WorkspaceBound,
        new_state: GuestState,
        task: Actor,
        *task_arguments: ActorArgumentType,
        current_state: Optional[GuestState] = None,
        set_values: Optional[GuestFieldStates] = None,
        poolname: Optional[str] = None,
        current_pool_data: Optional[SerializedPoolDataMapping] = None,
        delay: Optional[int] = None,
        **details: Any
    ) -> WorkspaceBound:
        """
        Update guest request state and plan a follow-up task.
        """

        if self.result:
            return self

        assert self.guestname

        r = _update_guest_state_and_request_task(
            self.logger,
            self.session,
            self.guestname,
            new_state,
            task,
            *task_arguments,
            current_state=current_state,
            set_values=set_values,
            poolname=poolname or (self.gr.poolname if self.gr else None),
            current_pool_data=current_pool_data,
            delay=delay,
            **details
        )

        if r.is_error:
            self._error(r, 'failed to update guest state and dispatch task')

        return self


class GuestRequestWorkspace(Workspace):
    guestname: str

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        db: DB,
        guestname: str,
        task: Optional[str] = None,
        **default_details: Any
    ) -> None:
        super().__init__(logger, session, guestname=guestname, task=task, db=db, **default_details)


class TailHandler:
    def get_failure_details(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall
    ) -> Dict[str, str]:
        return {}

    def get_logger(
        self,
        logger: gluetool.log.ContextAdapter,
        task_call: TaskCall
    ) -> gluetool.log.ContextAdapter:
        return logger

    def do_handle_tail(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall,
        failure_details: Dict[str, str]
    ) -> DoerReturnType:
        raise NotImplementedError

    def handle_tail(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall
    ) -> bool:
        logger = self.get_logger(logger, task_call)
        failure_details = self.get_failure_details(logger, db, session, task_call)

        r = self.do_handle_tail(logger, db, session, task_call, failure_details)

        if r.is_ok:
            if r is SUCCESS:
                logger.info('successfuly handled the chain tail')

                return True

            if r is RESCHEDULE:
                logger.warning('failed to handle the chain tail')

                return False

            if is_ignore_result(r):
                logger.warning('failed to handle the chain tail but ignoring the error')

                return True

            Failure(
                'unexpected outcome of tail handler',
                task_call=task_call,
                **cast(Any, failure_details)
            ).handle(logger)

            return False

        # Failures were already handled by this point
        return False


class ProvisioningTailHandler(TailHandler):
    def __init__(
        self,
        current_state: Literal[
            GuestState.SHELF_LOOKUP,
            GuestState.ROUTING,
            GuestState.PROVISIONING,
            GuestState.PROMISED,
            GuestState.PREPARING,
            GuestState.READY
        ],
        # Note: when adding newly supported new state, be sure to add a corresponding reaction to the `do_handle_tail()`
        # method.
        new_state: Literal[
            GuestState.SHELF_LOOKUP,
            GuestState.ROUTING,
            GuestState.ERROR
        ]
    ) -> None:
        self.current_state = current_state
        self.new_state = new_state

    def get_failure_details(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall
    ) -> Dict[str, str]:
        details: Dict[str, str] = {}

        if 'guestname' in task_call.named_args:
            details['guestname'] = cast(str, task_call.named_args['guestname'])

        return details

    def get_logger(
        self,
        logger: gluetool.log.ContextAdapter,
        task_call: TaskCall
    ) -> gluetool.log.ContextAdapter:
        return TaskLogger(logger, 'provisioning-tail')

    def do_handle_tail(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall,
        failure_details: Dict[str, str]
    ) -> DoerReturnType:
        workspace = Workspace(
            logger,
            session,
            db=db,
            task='provisioning-tail',
            **failure_details
        )

        workspace._begin()

        # Chicken and egg problem: we need guestname for logging context, but if it's missing,
        # we need to report the failure, and that's usually done by calling `error`.
        # Which needs guestname...
        if not task_call.has_args('guestname'):
            r: DoerReturnType = Error(Failure(
                'cannot handle chain tail with undefined arguments',
                task_call=task_call
            ))

            workspace._error(r, 'failed to extract actor arguments')

            return IGNORE(r)

        guestname, *_ = task_call.extract_args('guestname')

        # guestname can never be None
        assert isinstance(guestname, str)

        workspace.load_guest_request(guestname, state=self.current_state)

        if workspace.result:
            return workspace.result

        assert workspace.gr

        if workspace.gr.poolname and not workspace.gr.pool_data.is_empty(workspace.gr.poolname):
            workspace.spice_details['poolname'] = workspace.gr.poolname

            workspace.load_gr_pool()

            if workspace.result:
                return workspace.result

            assert workspace.pool

            # Don't release the guests if preserve-for-investigation is set
            if not workspace.pool.preserve_for_investigation:
                r_release = workspace.pool.release_guest(logger, workspace.session, workspace.gr)

                if r_release.is_error:
                    workspace._error(r_release, 'failed to release guest resources')

                    return RESCHEDULE

        set_values: GuestFieldStates = {
            'poolname': None,
            'last_poolname': workspace.gr.poolname,
            'address': None
        }

        if workspace.gr.poolname:
            set_values['_pool_data'] = workspace.gr.pool_data.reset(workspace.gr.poolname)

        if self.new_state == GuestState.SHELF_LOOKUP:
            from .guest_shelf_lookup import guest_shelf_lookup

            workspace.update_guest_state_and_request_task(
                self.new_state,
                guest_shelf_lookup,
                workspace.guestname,
                current_state=self.current_state,
                current_pool_data=workspace.gr._pool_data,
                set_values=set_values
            )

        elif self.new_state == GuestState.ROUTING:
            from .route_guest_request import route_guest_request

            workspace.update_guest_state_and_request_task(
                self.new_state,
                route_guest_request,
                workspace.guestname,
                current_state=self.current_state,
                current_pool_data=workspace.gr._pool_data,
                set_values=set_values
            )

        elif self.new_state == GuestState.ERROR:
            workspace.update_guest_state(
                self.new_state,
                current_state=self.current_state,
                current_pool_data=workspace.gr._pool_data,
                set_values=set_values
            )

        else:
            workspace._fail(
                Failure(
                    'unhandled new state in provisioning tail handler',
                    new_state=self.new_state.value
                ),
                'unhandled new state in provisioning tail handler'
            )

            return workspace.result

        if workspace.result:
            return workspace.result

        workspace._progress(f'reverted to {self.new_state.value}')

        workspace._complete()

        return SUCCESS


class LoggingTailHandler(TailHandler):
    def get_failure_details(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall
    ) -> Dict[str, str]:
        details: Dict[str, str] = {}

        if 'guestname' in task_call.named_args:
            details['guestname'] = cast(str, task_call.named_args['guestname'])

        if 'logname' in task_call.named_args:
            details['logname'] = cast(str, task_call.named_args['logname'])

        if 'contenttype' in task_call.named_args:
            details['contenttype'] = cast(str, task_call.named_args['contenttype'])

        return details

    def get_logger(
        self,
        logger: gluetool.log.ContextAdapter,
        task_call: TaskCall
    ) -> gluetool.log.ContextAdapter:
        return TaskLogger(logger, 'logging-tail')

    def do_handle_tail(
        self,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        task_call: TaskCall,
        failure_details: Dict[str, str]
    ) -> DoerReturnType:
        workspace = Workspace(
            logger,
            session,
            db=db,
            task='logging-tail',
            **failure_details
        )

        workspace._begin()

        # Chicken and egg problem: we need guestname for logging context, but if it's missing,
        # we need to report the failure, and that's usually done by calling `error`.
        # Which needs guestname...
        if not task_call.has_args('guestname', 'logname', 'contenttype'):
            r: DoerReturnType = Error(Failure(
                'cannot handle logging tail with undefined arguments',
                task_call=task_call
            ))

            workspace._error(r, 'failed to extract actor arguments')

            return IGNORE(r)

        guestname, logname, _contenttype = task_call.extract_args(
            'guestname',
            'logname',
            'contenttype'
        )

        contenttype = GuestLogContentType(_contenttype)

        query = sqlalchemy \
            .update(GuestLog) \
            .where(GuestLog.guestname == guestname) \
            .where(GuestLog.logname == logname) \
            .where(GuestLog.contenttype == contenttype) \
            .values(
                updated=datetime.datetime.utcnow(),
                state=GuestLogState.ERROR
            )

        r_store: DMLResult[GuestLog] = execute_dml(logger, workspace.session, query)

        if r_store.is_error:
            workspace._error(r_store, 'failed to update the log')

        if workspace.result:
            return workspace.result

        workspace._complete()

        return SUCCESS
