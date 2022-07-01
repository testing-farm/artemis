# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
import os
import threading
import traceback
from typing import TYPE_CHECKING, Any, Dict, Optional, Set, cast

import dramatiq.broker
import dramatiq.message
import dramatiq.middleware
import dramatiq.middleware.retries
import dramatiq.worker
import gluetool.log
import redis
from dramatiq.common import compute_backoff, current_millis
from gluetool.result import Ok

if TYPE_CHECKING:
    from . import ExceptionInfoType
    from .tasks import Actor, ActorArgumentType, TaskCall


# Dramatiq does not have a global default for maximal number of retries, the value is only present as a default
# of `Retries` middleware's `retries` keyword parameter.
DEFAULT_MAX_RETRIES = 20


def _dump_message(message: dramatiq.message.Message) -> Dict[str, Any]:
    # message.asdict() is nice, but returns ordered dict. we don't care about
    # order, and OrderedDict would need extra care when serializing anywhere,
    # so convert it to plain dict.

    return dict(**message.asdict())


def _get_message_limit(
    message: dramatiq.broker.MessageProxy,
    key: str,
    default: int,
    actor: Optional['Actor'] = None,
) -> int:
    value = cast(Optional[int], message.options.get(key))

    if value:
        return value

    if actor:
        value = cast(Optional[int], actor.options.get(key))

        if value:
            return value

    return default


def _message_max_retries(message: dramatiq.broker.MessageProxy, actor: Optional['Actor'] = None) -> int:
    return _get_message_limit(message, 'max_retries', DEFAULT_MAX_RETRIES, actor=actor)


def _message_min_backoff(message: dramatiq.broker.MessageProxy, actor: Optional['Actor'] = None) -> int:
    return _get_message_limit(message, 'min_backoff', dramatiq.middleware.retries.DEFAULT_MIN_BACKOFF, actor=actor)


def _message_max_backoff(message: dramatiq.broker.MessageProxy, actor: Optional['Actor'] = None) -> int:
    return _get_message_limit(message, 'max_backoff', dramatiq.middleware.retries.DEFAULT_MAX_BACKOFF, actor=actor)


def _message_backoff(
    message: dramatiq.broker.MessageProxy,
    retries: int,
    actor: Optional['Actor'] = None
) -> int:
    return cast(
        int,
        compute_backoff(
            retries,
            factor=_message_min_backoff(message, actor=actor),
            max_backoff=_message_max_backoff(message, actor=actor)
        )[1]
    )


def _retry_message(
    logger: gluetool.log.ContextAdapter,
    broker: dramatiq.broker.Broker,
    message: dramatiq.message.Message,
    task_call: Optional['TaskCall'] = None,
    exc_info: Optional['ExceptionInfoType'] = None
) -> None:
    """
    Enqueue a given message while increasing its "retried" count by 1.
    """

    message.options['retries'] = message.options.get('retries', 0) + 1

    if exc_info:
        message.options['traceback'] = '\n'.join(traceback.format_exception(*exc_info, limit=30))

    retries = cast(int, message.options['retries'])
    backoff = _message_backoff(message, retries, actor=task_call.actor if task_call else None)

    retry_at = datetime.datetime.utcnow() + datetime.timedelta(milliseconds=backoff)

    logger.info(f'retries: message={message.message_id} retries={retries} backoff={backoff} retrying-at={retry_at}')

    broker.enqueue(message, delay=backoff)


def _fail_message(
    logger: gluetool.log.ContextAdapter,
    message: dramatiq.message.Message,
    error_message: str,
    **details: Any
) -> None:
    """
    Mark the given message as failed.
    """

    from . import Failure

    details['broker_message'] = _dump_message(message)

    Failure(error_message, **details).handle(logger)

    message.fail()


def _handle_tails(
    logger: gluetool.log.ContextAdapter,
    message: dramatiq.message.Message,
    task_call: 'TaskCall'
) -> bool:
    """
    Handle the "tails": when we run out of retries on a task, we cannot just let it fail, but we must take
    of whatever resources it might have allocated.

    We have different handlers for each chain of tasks, and these handlers take care of their particular cleanup.
    The task here is to dispatch the correct handler.
    """

    from .tasks import get_root_db

    tail_handler = task_call.tail_handler
    assert tail_handler is not None

    tail_logger = tail_handler.get_logger(logger, task_call)

    db = get_root_db(tail_logger)

    with db.get_session() as session:
        if tail_handler.handle_tail(tail_logger, db, session, task_call):
            return True

    tail_logger.error('failed to handle the chain tail')

    # This would cause the message to be dropped, effectively halting any work towards provisioning
    # of the guest or capturing its logs.
    #
    # In the spirit of "let's try again...", falling through to rescheduling the original task.
    #
    # message.fail()

    return False


def resolve_retry_message(
    logger: gluetool.log.ContextAdapter,
    broker: dramatiq.broker.Broker,
    task_call: 'TaskCall'
) -> None:
    from . import log_dict_yaml

    assert task_call.broker_message is not None

    # `retries` key is initialized to 0 - while other fields are optional, this one is expected to exist.
    retries = task_call.broker_message.options.setdefault('retries', 0)
    max_retries = _message_max_retries(task_call.broker_message, task_call.actor)

    log_dict_yaml(
        logger.info,
        'retry message',
        {
            'task_call': task_call.serialize(),
            'retries': {
                'current': retries,
                'max': max_retries
            }
        }
    )

    if max_retries is not None and retries >= max_retries:
        # Kill messages for tasks we don't handle in any better way. After all, they did run out of retires.
        if not task_call.has_tail_handler:
            return _fail_message(
                logger,
                task_call.broker_message,
                'retries exceeded',
                task_call=task_call,
                guestname=task_call.named_args.get('guestname', None),
                retries={
                    'current': retries,
                    'max': max_retries
                }
            )

        if _handle_tails(logger, task_call.broker_message, task_call) is True:
            return

    _retry_message(logger, broker, task_call.broker_message, task_call=task_call)


class Retries(dramatiq.middleware.retries.Retries):  # type: ignore[misc]  # cannot subclass 'Retries'
    @property
    def actor_options(self) -> Set[str]:
        return {
            # These come from our superclass...
            'max_retries',
            'min_backoff',
            'max_backoff',
            'retry_when',
            'throws',
            # ... and this one is our addition so we could attach tail handler to each actor.
            'tail_handler'
        }

    def after_process_message(
        self,
        broker: dramatiq.broker.Broker,
        message: dramatiq.message.Message,
        *,
        # This is on purpose, our tasks never return anything useful.
        result: None = None,
        exception: Optional[BaseException] = None
    ) -> None:
        # If the task did not raise an exception, there's obviously no need to retry it in the future. We're done.
        if exception is None:
            return

        from . import get_logger
        from .tasks import TaskCall

        logger = get_logger()
        task_call = TaskCall.from_message(broker, message)

        resolve_retry_message(task_call.logger(logger), broker, task_call)


MESSAGE_NOTE_OPTION_KEY = 'artemis_notes'
NOTE_POOLNAME = 'poolname'


# TODO: once circular imports are resolved, use @with_context
def set_message_note(note: str, value: str) -> None:
    """
    Attach a "note" to the current message.

    Tasks may need to expose some additional information that cannot be passed to middleware directly, to extend
    context available to the middleware. This information in stored under special keys of current message's ``options``
    mapping.
    """

    from .context import CURRENT_MESSAGE

    message_proxy = CURRENT_MESSAGE.get()
    assert message_proxy is not None

    options = cast(Dict[str, Dict[str, str]], message_proxy.options)
    options.setdefault(MESSAGE_NOTE_OPTION_KEY, {})
    options[MESSAGE_NOTE_OPTION_KEY][note] = value


def get_metric_note(note: str) -> Optional[str]:
    """
    Get an optional note from the current message.
    """

    from .context import CURRENT_MESSAGE

    message_proxy = CURRENT_MESSAGE.get()
    assert message_proxy is not None

    options = cast(Dict[str, Dict[str, str]], message_proxy.options)

    return options.get(MESSAGE_NOTE_OPTION_KEY, {}).get(note)


class Prometheus(dramatiq.middleware.Middleware):  # type: ignore[misc]  # cannot subclass 'Middleware'
    def __init__(self) -> None:
        super().__init__()

        self._delayed_messages: Set[str] = set()
        self._message_start_times: Dict[str, int] = {}

    @property
    def actor_options(self) -> Set[str]:
        return {MESSAGE_NOTE_OPTION_KEY}

    def after_nack(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from .metrics import TaskMetrics

        TaskMetrics.inc_overall_rejected_messages(message.queue_name, message.actor_name)

    def after_enqueue(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message, delay: int) -> None:
        from .metrics import TaskMetrics

        if "retries" in message.options:
            TaskMetrics.inc_overall_retried_messages(message.queue_name, message.actor_name)

    def before_delay_message(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from .metrics import TaskMetrics

        self._delayed_messages.add(message.message_id)

        TaskMetrics.inc_current_delayed_messages(message.queue_name, message.actor_name)

    def before_process_message(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from .metrics import TaskMetrics

        labels = (message.queue_name, message.actor_name)

        if message.message_id in self._delayed_messages:
            self._delayed_messages.remove(message.message_id)

            TaskMetrics.dec_current_delayed_messages(message.queue_name, message.actor_name)

        TaskMetrics.inc_current_messages(*labels)

        self._message_start_times[message.message_id] = current_millis()

    def after_process_message(
        self,
        broker: dramatiq.broker.Broker,
        message: dramatiq.message.Message,
        *,
        # This is on purpose, our tasks never return anything useful.
        result: None = None,
        exception: Optional[BaseException] = None
    ) -> None:
        from .metrics import TaskMetrics
        from .tasks import TaskCall

        labels = (message.queue_name, message.actor_name)

        task_call = TaskCall.from_message(broker, message)

        message_start_time = self._message_start_times.pop(message.message_id, current_millis())
        message_duration = current_millis() - message_start_time

        # Extract the poolname. `None` is a good starting value, but it turns out that most of the tasks
        # relate to a particular pool in one way or another. Some tasks are given the poolname as a parameter,
        # and some can tell us by attaching a note to the message.
        poolname: ActorArgumentType = None

        if 'poolname' in task_call.named_args:
            poolname = task_call.named_args['poolname']

        elif message.options:
            poolname = get_metric_note(NOTE_POOLNAME)

        TaskMetrics.inc_message_durations(
            message.queue_name,
            message.actor_name,
            message_duration,
            poolname
        )

        TaskMetrics.dec_current_messages(*labels)
        TaskMetrics.inc_overall_messages(*labels)

        if exception is not None:
            TaskMetrics.inc_overall_errored_messages(*labels)

    after_skip_message = after_process_message


class WorkerMetrics(dramatiq.middleware.Middleware):  # type: ignore[misc]  # cannot subclass 'Middleware'
    """
    Dramatiq broker middleware spawning a thread to keep refreshing worker metrics.
    """

    def __init__(self, worker_name: str, interval: int) -> None:
        super().__init__()

        self.worker_name = worker_name
        self.interval = interval

        self._refresher: Optional[threading.Thread] = None

    def after_worker_boot(self, signal: str, worker: dramatiq.worker.Worker) -> None:
        from . import get_logger
        from .metrics import WorkerMetrics as _WorkerMetrics

        get_logger().warning('metrics refresher started')

        self._refresher = _WorkerMetrics.spawn_metrics_refresher(
            get_logger(),
            self.worker_name,
            self.interval,
            lambda _worker: Ok((1, len(worker.workers))),
            worker_instance=worker
        )


class WorkerTraffic(dramatiq.middleware.Middleware):  # type: ignore[misc]  # cannot subclass 'Middleware'
    KEY_WORKER_TASK = 'tasks.workers.traffic.{worker}.{pid}.{tid}'  # noqa: FS003
    KEY_WORKER_TASK_PATTERN = 'tasks.workers.traffic.*'

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        worker_name: str
    ) -> None:
        super().__init__()

        self.logger = logger
        self.cache = cache
        self.worker_name = worker_name
        self.worker_pid = os.getpid()

    @property
    def current_key(self) -> str:
        return self.KEY_WORKER_TASK.format(  # noqa: FS002
            worker=self.worker_name,
            pid=self.worker_pid,
            tid=threading.get_ident()
        )

    def before_process_message(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from .cache import set_cache_value
        from .knobs import KNOB_WORKER_TRAFFIC_METRICS_TTL
        from .metrics import WorkerTrafficTask
        from .tasks import TaskCall

        task_call = TaskCall.from_message(broker, message)

        tid = threading.get_ident()

        set_cache_value(
            self.logger,
            self.cache,
            self.current_key,
            WorkerTrafficTask(
                workername=self.worker_name,
                worker_pid=self.worker_pid,
                worker_tid=tid,
                ctime=datetime.datetime.utcnow(),
                queue=cast(str, message.queue_name),
                actor=cast(str, message.actor_name),
                args=task_call.named_args
            ).serialize_to_json().encode(),
            ttl=KNOB_WORKER_TRAFFIC_METRICS_TTL.value
        )

    def after_process_message(
        self,
        broker: dramatiq.broker.Broker,
        message: dramatiq.message.Message,
        *,
        # This is on purpose, our tasks never return anything useful.
        result: None = None,
        exception: Optional[BaseException] = None
    ) -> None:
        from .cache import delete_cache_value

        delete_cache_value(self.logger, self.cache, self.current_key)

    after_skip_message = after_process_message


class CurrentMessage(dramatiq.middleware.Middleware):  # type: ignore[misc]  # cannot subclass 'Middleware'
    """
    Middleware that exposes the current message via a context variable.

    Based on :py:class:`dramatiq.middleware.current_message.CurrentMessage`,
    but modifies our context variables instead of managing its own storage.
    """

    def before_process_message(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from .context import CURRENT_MESSAGE

        CURRENT_MESSAGE.set(message)

    def after_process_message(
        self,
        broker: dramatiq.broker.Broker,
        message: dramatiq.message.Message,
        *,
        # This is on purpose, our tasks never return anything useful.
        result: None = None,
        exception: Optional[BaseException] = None
    ) -> None:
        from .context import CURRENT_MESSAGE

        CURRENT_MESSAGE.set(None)


class SingletonTask(dramatiq.middleware.Middleware):  # type: ignore[misc]  # cannot subclass 'Middleware'
    def __init__(self, cache: redis.Redis) -> None:
        super().__init__()

        self.cache = cache

        self._tokens: Dict[str, str] = {}

    @property
    def actor_options(self) -> Set[str]:
        return {
            'singleton',
            'singleton_deadline'
        }

    @staticmethod
    def _lock_name(task_call: 'TaskCall') -> str:
        lockname = f'tasks.singleton.{task_call.actor.actor_name}'

        if not task_call.args:
            return lockname

        return f'{lockname}.{":".join(str(arg) for arg in task_call.args)}'

    def before_process_message(self, broker: dramatiq.broker.Broker, message: dramatiq.message.Message) -> None:
        from . import Failure, get_logger
        from .knobs import KNOB_LOGGING_SINGLETON_LOCKS
        from .tasks import TaskCall

        logger = get_logger()

        task_call = TaskCall.from_message(broker, message)

        failure_details: Dict[str, Any] = {
            'task_call': task_call
        }

        logger = task_call.logger(logger, failure_details)

        if not task_call.actor.options['singleton']:
            logger.debug('not a singleton')
            return

        from .cache import acquire_lock

        lockname = failure_details['lockname'] = self._lock_name(task_call)
        ttl = failure_details['lock_deadline'] = task_call.actor.options['singleton_deadline']

        token = acquire_lock(logger, self.cache, lockname, ttl=ttl)

        if token is None:
            if KNOB_LOGGING_SINGLETON_LOCKS.value is True:
                logger.info(f'singleton-lock: lockname={lockname} acquire=failed')

            failure_details['broker_message'] = _dump_message(message)
            Failure('failed to acquire singleton lock', **failure_details).handle(logger)

            resolve_retry_message(logger, broker, task_call)

            raise dramatiq.middleware.SkipMessage('failed to acquire singleton lock')

        self._tokens[message.message_id] = token

        if KNOB_LOGGING_SINGLETON_LOCKS.value is True:
            logger.info(f'singleton-lock: lockname={lockname} acquire=succeeded token={token}')

        logger.info(f'acquired singleton lock with token {token}')

    def after_process_message(
        self,
        broker: dramatiq.broker.Broker,
        message: dramatiq.message.Message,
        *,
        # This is on purpose, our tasks never return anything useful.
        result: None = None,
        exception: Optional[BaseException] = None
    ) -> None:
        from . import get_logger
        from .knobs import KNOB_LOGGING_SINGLETON_LOCKS
        from .tasks import TaskCall

        logger = get_logger()

        task_call = TaskCall.from_message(broker, message)

        failure_details: Dict[str, Any] = {
            'task_call': task_call
        }

        logger = task_call.logger(logger, failure_details)

        if not task_call.actor.options['singleton']:
            logger.debug('not a singleton')
            return

        from .cache import release_lock

        lockname = failure_details['lockname'] = self._lock_name(task_call)
        token = failure_details['token'] = self._tokens.pop(message.message_id, None)

        if token is None:
            return _fail_message(
                logger,
                message,
                'lost singleton lock token',
                recoverable=False,
                **failure_details
            )

        released = release_lock(logger, self.cache, lockname, token)

        if released is False:
            if KNOB_LOGGING_SINGLETON_LOCKS.value is True:
                logger.info(f'singleton-lock: lockname={lockname} release=failed token={token}')

            return _fail_message(
                logger,
                message,
                'failed to release singleton lock',
                recoverable=False,
                **failure_details
            )

        if KNOB_LOGGING_SINGLETON_LOCKS.value is True:
            logger.info(f'singleton-lock: lockname={lockname} release=succeeded token={token}')

        logger.info('released singleton lock')
