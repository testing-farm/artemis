import time

import gluetool.log
import sqlalchemy.orm.session

import artemis
import artemis.guest
import artemis.snapshot

from artemis.tasks import get_guest_logger, get_snapshot_logger
from artemis.tasks import route_guest_request, release_guest_request, _update_guest_state
from artemis.tasks import route_snapshot_request, release_snapshot_request, restore_snapshot_request
from artemis.tasks import _update_snapshot_state


def _dispatch_guest_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest: artemis.db.GuestRequest
) -> None:
    logger = get_guest_logger('dispatch-acquire', root_logger, guest.guestname)

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
    logger = get_guest_logger('dispatch-release', root_logger, guest.guestname)

    logger.begin()

    # Schedule task to release the given guest request.
    release_guest_request.send(guest.guestname)

    logger.finished()


def _dispatch_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: artemis.db.SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-create', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Release the snapshot to the next stage. If this succeeds, dispatcher will no longer have any power
    # over the snapshot, and completion of the request would be taken over by a set of tasks.
    if not _update_snapshot_state(
        logger,
        session,
        snapshot.snapshotname,
        snapshot.guestname,
        artemis.guest.GuestState.PENDING,
        artemis.guest.GuestState.ROUTING
    ):
        # Somebody already did our job, the snapshot request is not in PENDING state anymore.
        logger.finished()
        return

    route_snapshot_request.send(snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _release_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: artemis.db.SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-release', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot request.
    release_snapshot_request.send(snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _restore_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: artemis.db.SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-restore', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot equest.
    restore_snapshot_request.send(snapshot.guestname, snapshot.snapshotname)

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

            snapshot_requests = session \
                .query(artemis.db.SnapshotRequest) \
                .filter(artemis.db.SnapshotRequest.state == artemis.guest.GuestState.PENDING.value) \
                .all()

            for snapshot in snapshot_requests:
                _dispatch_snapshot_request(root_logger, session, snapshot)

            snapshot_requests = session \
                .query(artemis.db.SnapshotRequest) \
                .filter(artemis.db.SnapshotRequest.state == artemis.guest.GuestState.CONDEMNED.value) \
                .all()

            for snapshot in snapshot_requests:
                _release_snapshot_request(root_logger, session, snapshot)

            snapshot_requests = session \
                .query(artemis.db.SnapshotRequest) \
                .filter(artemis.db.SnapshotRequest.state == artemis.guest.GuestState.RESTORING.value) \
                .all()

            for snapshot in snapshot_requests:
                _restore_snapshot_request(root_logger, session, snapshot)

        time.sleep(10)


if __name__ == '__main__':
    main()
