import datetime
import inspect
import traceback
from typing import TYPE_CHECKING, Dict, Optional, Set, Union, cast

import dramatiq.broker
import dramatiq.message
import dramatiq.middleware
import dramatiq.middleware.retries
import gluetool.log
from dramatiq.common import compute_backoff, current_millis

from .db import GuestLogContentType
from .guest import GuestLogger

if TYPE_CHECKING:
    from . import ExceptionInfoType
    from .tasks import Actor


# Dramatiq does not have a global default for maximal number of retries, the value is only present as a default
# of `Retries` middleware's `retries` keyword parameter.
DEFAULT_MAX_RETRIES = 20


def _actor_arguments(
    logger: gluetool.log.ContextAdapter,
    message: dramatiq.message.Message,
    actor: 'Actor'
) -> Dict[str, Union[str, None]]:
    signature = inspect.signature(actor.fn)

    gluetool.log.log_dict(logger.debug, 'raw message data', message._message)

    if len(signature.parameters) != len(message._message[2]):
        from . import Failure

        Failure(
            'actor signature parameters does not match message content',
            signature=[name for name in signature.parameters.keys()],
            arguments=[repr(arg) for arg in message._message[2]]
        ).handle(logger)

        return {}

    return {
        name: message._message[2][index]
        for index, name in enumerate(signature.parameters.keys())
    }


def _get_message_limit(
    message: dramatiq.broker.MessageProxy,
    actor: 'Actor',
    key: str,
    default: int
) -> int:
    value = cast(Optional[int], message.options.get(key))

    if value:
        return value

    value = cast(Optional[int], actor.options.get(key))

    if value:
        return value

    return default


def _message_max_retries(message: dramatiq.broker.MessageProxy, actor: 'Actor') -> int:
    return _get_message_limit(message, actor, 'max_retries', DEFAULT_MAX_RETRIES)


def _message_min_backoff(message: dramatiq.broker.MessageProxy, actor: 'Actor') -> int:
    return _get_message_limit(message, actor, 'min_backoff', dramatiq.middleware.retries.DEFAULT_MIN_BACKOFF)


def _message_max_backoff(message: dramatiq.broker.MessageProxy, actor: 'Actor') -> int:
    return _get_message_limit(message, actor, 'max_backoff', dramatiq.middleware.retries.DEFAULT_MAX_BACKOFF)


def _message_backoff(
    message: dramatiq.broker.MessageProxy,
    actor: 'Actor',
    retries: int
) -> int:
    return cast(
        int,
        compute_backoff(
            retries,
            factor=_message_min_backoff(message, actor),
            max_backoff=_message_max_backoff(message, actor)
        )[1]
    )


def _retry_message(
    logger: gluetool.log.ContextAdapter,
    broker: dramatiq.broker.Broker,
    message: dramatiq.message.Message,
    actor: 'Actor',
    exc_info: Optional['ExceptionInfoType'] = None
) -> None:
    """
    Enqueue a given message while increasing its "retried" count by 1.
    """

    message.options['retries'] = message.options.get('retries', 0) + 1

    if exc_info:
        message.options['traceback'] = '\n'.join(traceback.format_exception(*exc_info, limit=30))

    retries = cast(int, message.options['retries'])
    backoff = _message_backoff(message, actor, retries)

    retry_at = datetime.datetime.utcnow() + datetime.timedelta(milliseconds=backoff)

    logger.info(f'retries: message={message.message_id} retries={retries} backoff={backoff} retrying-at={retry_at}')

    broker.enqueue(message, delay=backoff)


def _fail_message(
    logger: gluetool.log.ContextAdapter,
    message: dramatiq.message.Message,
    error_message: str
) -> None:
    """
    Mark the given message as failed.
    """

    from . import Failure

    Failure(error_message).handle(logger)

    message.fail()


def _handle_tails(
    logger: gluetool.log.ContextAdapter,
    message: dramatiq.message.Message,
    actor: 'Actor',
    actor_arguments: Dict[str, Optional[str]]
) -> bool:
    """
    Handle the "tails": when we run out of retries on a task, we cannot just let it fail, but we must take
    of whatever resources it might have allocated.

    We have different handlers for each chain of tasks, and these handlers take care of their particular cleanup.
    The task here is to dispatch the correct handler.
    """

    from .tasks import TaskLogger, get_root_db, handle_logging_chain_tail, handle_provisioning_chain_tail, \
        is_logging_tail_task, is_provisioning_tail_task

    if is_provisioning_tail_task(actor):
        tail_logger: gluetool.log.ContextAdapter = TaskLogger(logger, 'provisioning-tail')

    elif is_logging_tail_task(actor):
        tail_logger = TaskLogger(logger, 'logging-tail')

    else:
        tail_logger = logger

    guestname = actor_arguments['guestname'] if actor_arguments and 'guestname' in actor_arguments else None

    # So far, all tail work within the context of a particular guest, therefore there must be a guestname.
    if not guestname:
        _fail_message(tail_logger, message, 'cannot handle chain tail with undefined guestname')

        return True

    # Logging chain has additional arguments
    if is_logging_tail_task(actor):
        logname = actor_arguments['logname'] \
            if actor_arguments and 'logname' in actor_arguments else None

        contenttype = actor_arguments['contenttype'] \
            if actor_arguments and 'contenttype' in actor_arguments else None

        if not logname or not contenttype:
            _fail_message(
                tail_logger,
                message,
                'cannot handle logging chain tail with undefined logname or contenttype'
            )

            return True

    db = get_root_db(tail_logger)

    with db.get_session() as session:
        if is_provisioning_tail_task(actor):
            if handle_provisioning_chain_tail(
                tail_logger,
                db,
                session,
                guestname,
                actor
            ):
                tail_logger.info('successfuly handled the provisioning tail')

                return True

        elif is_logging_tail_task(actor):
            assert logname is not None
            assert contenttype is not None

            if handle_logging_chain_tail(
                tail_logger,
                db,
                session,
                guestname,
                logname,
                GuestLogContentType(contenttype),
                actor
            ):
                tail_logger.info('successfuly handled the logging tail')

                return True

    tail_logger.error('failed to handle the chain tail')

    # This would cause the message to be dropped, effectively halting any work towards provisioning
    # of the guest or capturing its logs.
    #
    # In the spirit of "let's try again...", falling through to rescheduling the original task.
    #
    # message.fail()

    return False


class Retries(dramatiq.middleware.retries.Retries):  # type: ignore  # Class cannot subclass 'Retries
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

        logger = get_logger()

        actor = cast('Actor', broker.get_actor(message.actor_name))

        # `retries` key is initialized to 0 - while other fields are optional, this one is expected to exist.
        retries = message.options.setdefault('retries', 0)
        max_retries = _message_max_retries(message, actor)
        retry_when = actor.options.get('retry_when', self.retry_when)

        actor_arguments = _actor_arguments(logger, message, actor)

        guestname = actor_arguments['guestname'] if actor_arguments and 'guestname' in actor_arguments else None

        if guestname:
            logger = GuestLogger(logger, guestname)

        logger.info(f'retries: message={message.message_id} actor={actor.actor_name} current-retries={retries} max-retries={max_retries}')  # noqa

        if retry_when is not None and not retry_when(retries, exception) or \
           retry_when is None and max_retries is not None and retries >= max_retries:

            from .tasks import is_logging_tail_task, is_provisioning_tail_task

            # Kill messages for tasks we don't handle in any better way. After all, they did run out of retires.
            if not is_provisioning_tail_task(actor) and not is_logging_tail_task(actor):
                return _fail_message(logger, message, f'retries exceeded for message {message.message_id}')

            if _handle_tails(logger, message, actor, actor_arguments) is True:
                return

        _retry_message(logger, broker, message, actor)


class Prometheus(dramatiq.middleware.Middleware):  # type: ignore  # Class cannot subclass 'Middleware'
    def __init__(self) -> None:
        super(Prometheus, self).__init__()

        self._delayed_messages: Set[str] = set()
        self._message_start_times: Dict[str, int] = {}

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
        from . import get_logger
        from .metrics import TaskMetrics

        logger = get_logger()

        labels = (message.queue_name, message.actor_name)
        actor = broker.get_actor(message.actor_name)

        actor_arguments = _actor_arguments(logger, message, actor)

        message_start_time = self._message_start_times.pop(message.message_id, current_millis())
        message_duration = current_millis() - message_start_time
        TaskMetrics.inc_message_durations(
            message.queue_name,
            message.actor_name,
            message_duration,
            actor_arguments.get('poolname', None)
        )

        TaskMetrics.dec_current_messages(*labels)
        TaskMetrics.inc_overall_messages(*labels)

        if exception is not None:
            TaskMetrics.inc_overall_errored_messages(*labels)

    after_skip_message = after_process_message
