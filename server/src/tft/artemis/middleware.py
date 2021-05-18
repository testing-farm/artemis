import datetime
import inspect
import traceback
from typing import TYPE_CHECKING, Dict, Optional, Set, Union

import dramatiq.broker
import dramatiq.message
import dramatiq.middleware
import dramatiq.middleware.retries
import gluetool.log
from dramatiq.common import compute_backoff, current_millis

from .guest import GuestLogger

if TYPE_CHECKING:
    from .tasks import Actor


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
            arguments=message._message[2]
        ).handle(logger)

        return {}

    return {
        name: message._message[2][index]
        for index, name in enumerate(signature.parameters.keys())
    }


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
        if exception is None:
            return

        from . import get_logger
        from .tasks import get_root_db

        logger = get_logger()

        actor = broker.get_actor(message.actor_name)
        retries = message.options.setdefault("retries", 0)
        max_retries = message.options.get("max_retries") or actor.options.get("max_retries", self.max_retries)
        retry_when = actor.options.get("retry_when", self.retry_when)

        actor_arguments = _actor_arguments(logger, message, actor)

        guestname = actor_arguments['guestname'] if actor_arguments and 'guestname' in actor_arguments else None

        if guestname:
            logger = GuestLogger(logger, guestname)

        logger.info(
            'retries: message={} actor={} attempts={} max_retries={}'.format(
                message.message_id, message.actor_name, retries, max_retries
            )
        )

        if retry_when is not None and not retry_when(retries, exception) or \
           retry_when is None and max_retries is not None and retries >= max_retries:
            # Handle the provisioning "tail": when we run out of retries on a task that works on
            # provisioning, and we need to release anything we already acquired, and start again.
            #
            # By this point, most likely, the provisioning is probably stuck with a broken pool,
            # or we already have a guest and we can't reach it, or something like that. Something
            # happened after routing and before successfully reaching READY state. We need to
            # release all the resources we have, to avoid leaks, and fall back to routing.
            #
            # This error path should be relatively cheap and straightforward, but not free of points
            # where it can fail on its own - after all, it will try to load the guest request from
            # database, and schedule routing task. It can fail, it may fail. The problem is, what to
            # do in such a situation? We don't want to reschedule the message, that would reschedule
            # the original task and by this time we kind of decided it's doomed and it's time to start
            # again. We can't schedule this "release & revert to routing" as a standalone task - we did
            # fail to schedule the routing task, we probably won't get away with a different actor.
            #
            # As of now, if we want to keep any chance of falling back to routing, rescheduling the
            # message seems to be the only way. It's quite likely it will fail again, giving us another
            # chance for release & revert. Note that this applies to situations where "release & revert"
            # attempt fails, i.e. DB or broker issues, most likely.

            from .tasks import TaskLogger, handle_provisioning_chain_tail, is_provisioning_tail_task

            if is_provisioning_tail_task(actor):
                tail_logger = TaskLogger(logger, 'provisioning-tail')

                if not guestname:
                    from . import Failure

                    Failure(
                        'cannot handle provisioning tail with undefined guestname',
                    ).handle(tail_logger)

                    message.fail()
                    return

                db = get_root_db(tail_logger)

                with db.get_session() as session:
                    if handle_provisioning_chain_tail(
                        tail_logger,
                        db,
                        session,
                        guestname,
                        actor
                    ):
                        tail_logger.info('successfuly handled the provisioning tail')
                        return

                tail_logger.error('failed to handle the provisioning tail')

                # This would cause the message to be dropped, effectively halting any work towards provisioning
                # of the guest.
                #
                # In the spirit of "let's try again...", falling through to rescheduling the original task.
                #
                # message.fail()

            else:
                # Kill messages for tasks we don't handle in any better way. After all, they did run out of retires.
                logger.warning('retries: retries exceeded for message {}.'.format(message.message_id))
                message.fail()

                return

        message.options["retries"] += 1
        message.options["traceback"] = traceback.format_exc(limit=30)
        min_backoff = message.options.get("min_backoff") or actor.options.get("min_backoff", self.min_backoff)
        max_backoff = message.options.get("max_backoff") or actor.options.get("max_backoff", self.max_backoff)
        max_backoff = min(max_backoff, dramatiq.middleware.retries.DEFAULT_MAX_BACKOFF)
        _, backoff = compute_backoff(retries, factor=min_backoff, max_backoff=max_backoff)

        retry_at = datetime.datetime.utcnow() + datetime.timedelta(milliseconds=backoff)
        logger.info("retries: message={} backoff={} retrying_at='{}'".format(message.message_id, backoff, retry_at))

        broker.enqueue(message, delay=backoff)


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
