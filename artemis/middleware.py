import traceback

import dramatiq.middleware.retries
from dramatiq.common import compute_backoff

import artemis
import artemis.guest

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
        logger: artemis.guest.GuestLogger,
        guestname: str,
        current_state: artemis.guest.GuestState
    ) -> None:
        # we need to import late, because middleware is called initialized in __init__
        # from artemis.tasks import _update_guest_state
        from artemis.tasks import _update_guest_state, route_guest_request

        # try to move from given state to ROUTING
        with artemis.get_db(self.logger).get_session() as session:
            if not _update_guest_state(
                self.logger,
                session,
                guestname,
                current_state,
                artemis.guest.GuestState.ROUTING
            ):
                # Somebody already did our job, the guest request is not in expected state anymore.
                return

            route_guest_request.send(guestname)

            logger.info('returned back to routing')

    def _retry_routing(
        self,
        logger: artemis.guest.GuestLogger,
        guestname: str,
        actor: Any,
        message: Any
    ) -> bool:
        # for acquire_guest, move from PROVISIONING back to ROUTING
        if actor.actor_name == 'acquire_guest':
            self._move_to_routing(logger, guestname, artemis.guest.GuestState.PROVISIONING)
            return True

        # for do_update_guest, move from PROMISED back to ROUTING
        elif actor.actor_name == 'update_guest':
            self._move_to_routing(logger, guestname, artemis.guest.GuestState.PROMISED)
            return True

        # for route_guest_request, stay in ROUTING
        elif actor.actor_name == 'route_guest_request':
            return True

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

        actor = broker.get_actor(message.actor_name)
        retries = message.options.setdefault("retries", 0)
        max_retries = message.options.get("max_retries") or actor.options.get("max_retries", self.max_retries)
        retry_when = actor.options.get("retry_when", self.retry_when)
        if retry_when is not None and not retry_when(retries, exception) or \
           retry_when is None and max_retries is not None and retries >= max_retries:
            root_logger = artemis.get_logger()

            guestname = self._guestname_from_message(message)

            if not guestname:
                root_logger.warning('Retries exceeded for message %r.', message.message_id)
                message.fail()
                return

            logger = artemis.guest.GuestLogger(root_logger, guestname)

            # try to move the request back to ROUTING for retry and finish
            if not self._retry_routing(logger, guestname, actor, message):
                logger.error('failed to retry routing')
                message.fail()
                return

            return

        message.options["retries"] += 1
        message.options["traceback"] = traceback.format_exc(limit=30)
        min_backoff = message.options.get("min_backoff") or actor.options.get("min_backoff", self.min_backoff)
        max_backoff = message.options.get("max_backoff") or actor.options.get("max_backoff", self.max_backoff)
        max_backoff = min(max_backoff, dramatiq.middleware.retries.DEFAULT_MAX_BACKOFF)
        _, backoff = compute_backoff(retries, factor=min_backoff, max_backoff=max_backoff)
        self.logger.info("Retrying message %r in %d milliseconds.", message.message_id, backoff)
        broker.enqueue(message, delay=backoff)
