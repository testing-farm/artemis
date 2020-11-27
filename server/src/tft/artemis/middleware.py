import datetime
import traceback

import dramatiq.middleware.retries
from dramatiq.common import compute_backoff

from .guest import GuestLogger

from typing import cast, Any, Optional


class Retries(dramatiq.middleware.retries.Retries):  # type: ignore  # Class cannot subclass 'Retries
    def _guestname_from_message(self, message: Any) -> Optional[str]:
        try:
            return cast(
                str,
                message._message[2][0]
            )

        except IndexError:
            return None

    def after_process_message(
        self,
        broker: Any,
        message: Any,
        *,
        result: Optional[Any] = None,
        exception: Optional[Any] = None
    ) -> None:
        if exception is None:
            return

        from . import get_logger, get_db

        logger = get_logger()

        actor = broker.get_actor(message.actor_name)
        retries = message.options.setdefault("retries", 0)
        max_retries = message.options.get("max_retries") or actor.options.get("max_retries", self.max_retries)
        retry_when = actor.options.get("retry_when", self.retry_when)

        guestname = self._guestname_from_message(message)

        if guestname:
            logger = GuestLogger(logger, guestname)

        logger.info(
            'retries: message={} actor={} attempts={} max_retries={}'.format(
                message.message_id, message.actor_name, retries, max_retries
            )
        )

        if retry_when is not None and not retry_when(retries, exception) or \
           retry_when is None and max_retries is not None and retries >= max_retries:

            # We are not interested in special handling of messages that don't relate to guests.
            if not guestname:
                logger.warning('retries: retries exceeded for message {}.'.format(message.message_id))
                message.fail()
                return

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

            from .tasks import TaskLogger, handle_provisioning_chain_tail

            tail_logger = TaskLogger(logger, 'provisioning-tail')

            db = get_db(tail_logger)

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

        message.options["retries"] += 1
        message.options["traceback"] = traceback.format_exc(limit=30)
        min_backoff = message.options.get("min_backoff") or actor.options.get("min_backoff", self.min_backoff)
        max_backoff = message.options.get("max_backoff") or actor.options.get("max_backoff", self.max_backoff)
        max_backoff = min(max_backoff, dramatiq.middleware.retries.DEFAULT_MAX_BACKOFF)
        _, backoff = compute_backoff(retries, factor=min_backoff, max_backoff=max_backoff)

        retry_at = datetime.datetime.utcnow() + datetime.timedelta(milliseconds=backoff)
        logger.info("retries: message={} backoff={} retrying_at='{}'".format(message.message_id, backoff, retry_at))

        broker.enqueue(message, delay=backoff)
