import time

import gluetool.log
import sqlalchemy.orm.session

import artemis
import artemis.guest

from artemis.tasks import TaskLogger, route_guest_request, release_guest_request, _update_guest_state


def _dispatch_guest_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest: artemis.db.GuestRequest
) -> None:
    logger = TaskLogger(
        artemis.guest.GuestLogger(root_logger, guest.guestname),
        'dispatch-acquire'
    )

    logger.begin()

    # Release the guest to the next stage. If this succeeds, dispatcher will no longer have any power
    # over the guest, and completion of the request would be taken over by a set of tasks.
    if not _update_guest_state(
        logger,
        session,
        guest.guestname,
        artemis.guest.GuestState.PENDING,
        artemis.guest.GuestState.ROUTING
    ):
        # Somebody already did our job, the guest request is not in PENDING state anymore.
        logger.finished()
        return

    # Kick of the task chain for this request.
    route_guest_request.send(guest.guestname)

    logger.finished()


def _release_guest_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest: artemis.db.GuestRequest
) -> None:
    logger = TaskLogger(
        artemis.guest.GuestLogger(root_logger, guest.guestname),
        'dispatch-release'
    )

    logger.begin()

    # Schedule task to remove the given guest request.
    release_guest_request.send(guest.guestname)

    logger.finished()


def main() -> None:
    root_logger = artemis.get_logger()
    db = artemis.get_db(root_logger)

    # Spawn HTTP server to provide metrics for Prometheus
    # ...

    while True:
        root_logger.info('tick...')

        # For each pending guest request, start their processing by submitting the first, routing task.
        with db.get_session() as session:
            guest_requests = session \
                             .query(artemis.db.GuestRequest) \
                             .filter(artemis.db.GuestRequest.state == artemis.guest.GuestState.PENDING.value) \
                             .all()

            for guest in guest_requests:
                _dispatch_guest_request(root_logger, session, guest)

            guest_requests = session \
                .query(artemis.db.GuestRequest) \
                .filter(artemis.db.GuestRequest.state == artemis.guest.GuestState.CONDEMNED.value) \
                .all()

            for guest in guest_requests:
                _release_guest_request(root_logger, session, guest)

        time.sleep(10)


if __name__ == '__main__':
    main()
