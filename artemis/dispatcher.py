import time

import gluetool.log
import sqlalchemy.orm.session

import artemis
import artemis.guest

from artemis.tasks import route_guest_request, release_guest_request


def _dispatch_guest_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest: artemis.db.Guest
) -> None:
    logger = artemis.guest.GuestLogger(root_logger, guest.guestname)

    logger.info('pending request')

    # Release the guest to the next stage. If this succeeds, dispatcher will no longer have any power
    # over the guest, and completion of the request would be taken over by a set of tasks.
    guest.state = artemis.guest.GuestState.ROUTING.value
    session.commit()

    # Kick of the task chain for this request.
    route_guest_request.send(guest.guestname)

    logger.info('scheduled routing task')


def _release_guest_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest: artemis.db.Guest
) -> None:
    logger = artemis.guest.GuestLogger(root_logger, guest.guestname)

    logger.info('condemned request')

    # Schedule task to remove the given guest request.
    release_guest_request.send(guest.guestname)

    logger.info('scheduled removal task')


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
                             .query(artemis.db.Guest) \
                             .filter(artemis.db.Guest.state == artemis.guest.GuestState.PENDING.value) \
                             .all()

            for guest in guest_requests:
                _dispatch_guest_request(root_logger, session, guest)

            guest_requests = session \
                .query(artemis.db.Guest) \
                .filter(artemis.db.Guest.state == artemis.guest.GuestState.CONDEMNED.value) \
                .all()

            for guest in guest_requests:
                _release_guest_request(root_logger, session, guest)

        time.sleep(10)


if __name__ == '__main__':
    main()
