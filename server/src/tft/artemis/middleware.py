import datetime
import traceback

import dramatiq.middleware.retries
import gluetool
from dramatiq.common import compute_backoff

from .guest import GuestLogger, GuestState

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

    def _move_to_routing(
        self,
        logger: gluetool.log.ContextAdapter,
        guestname: str,
        current_state: GuestState
    ) -> None:
        # we need to import late, because middleware is called initialized in __init__
        from .tasks import _update_guest_state, route_guest_request

        # try to move from given state to ROUTING
        with (self.logger).get_session() as session:
            if not _update_guest_state(
                self.logger,
                session,
                guestname,
                current_state,
                GuestState.ROUTING
            ):
                # Somebody already did our job, the guest request is not in expected state anymore.
                return

            # Avoid circular imports
            from .tasks import dispatch_task

            dispatch_task(
                self.logger,
                route_guest_request,
                guestname
            )

            logger.info('returned back to routing')

    def _move_to_error(
        self,
        logger: gluetool.log.ContextAdapter,
        guestname: str,
        current_state: GuestState
    ) -> None:
        # we need to import late, because middleware is called initialized in __init__
        from . import get_db
        from .tasks import _update_guest_state

        # try to move from given state to ERROR
        with get_db(self.logger).get_session() as session:
            if not _update_guest_state(
                self.logger,
                session,
                guestname,
                current_state,
                GuestState.ERROR
            ):
                # Somebody already did our job, the guest request is not in expected state anymore.
                return

            logger.info('moved to error state')

    def _retry_routing(
        self,
        logger: gluetool.log.ContextAdapter,
        guestname: str,
        actor: Any,
        message: Any
    ) -> bool:
        # for acquire_guest, move from PROVISIONING back to ROUTING
        if actor.actor_name == 'acquire_guest':
            self._move_to_routing(logger, guestname, GuestState.PROVISIONING)
            return True

        # for do_update_guest, move from PROMISED back to ROUTING
        elif actor.actor_name == 'update_guest':
            self._move_to_routing(logger, guestname, GuestState.PROMISED)
            return True

        # for route_guest_request, stay in ROUTING
        elif actor.actor_name == 'route_guest_request':
            self._move_to_error(logger, guestname, GuestState.ROUTING)
            return False

        logger.warning('cannot retry routing from actor {}'.format(actor.actor_name))
        return False

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

        from . import get_logger

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

            if not guestname:
                logger.warning('retries: retries exceeded for message {}.'.format(message.message_id))
                message.fail()
                return

            # try to move the request back to ROUTING for retry and finish
            if not self._retry_routing(logger, guestname, actor, message):
                logger.error('failed to retry routing')
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
