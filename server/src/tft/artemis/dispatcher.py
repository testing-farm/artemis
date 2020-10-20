import time

import gluetool.log
import sqlalchemy.orm.session

from . import get_logger, get_db
from .db import SnapshotRequest
from .guest import GuestState
from .tasks import get_snapshot_logger, dispatch_task
from .tasks import route_snapshot_request, release_snapshot_request, restore_snapshot_request
from .tasks import _update_snapshot_state


def _dispatch_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
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
        GuestState.PENDING,
        GuestState.ROUTING
    ):
        # Somebody already did our job, the snapshot request is not in PENDING state anymore.
        logger.finished()
        return

    dispatch_task(logger, route_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _release_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-release', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot request.
    dispatch_task(logger, release_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def _restore_snapshot_request(
    root_logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    snapshot: SnapshotRequest
) -> None:
    logger = get_snapshot_logger('dispatch-snapshot-restore', root_logger, snapshot.guestname, snapshot.snapshotname)

    logger.begin()

    # Schedule task to remove the given snapshot equest.
    dispatch_task(logger, restore_snapshot_request, snapshot.guestname, snapshot.snapshotname)

    logger.finished()


def main() -> None:
    root_logger = get_logger()
    db = get_db(root_logger)

    # Spawn HTTP server to provide metrics for Prometheus
    # ...

    while True:
        root_logger.info('tick...')

        # For each pending guest request, start their processing by submitting the first, routing task.
        with db.get_session() as session:
            snapshot_requests = session \
                .query(SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.PENDING.value) \
                .all()

            for snapshot in snapshot_requests:
                _dispatch_snapshot_request(root_logger, session, snapshot)

            snapshot_requests = session \
                .query(SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.CONDEMNED.value) \
                .all()

            for snapshot in snapshot_requests:
                _release_snapshot_request(root_logger, session, snapshot)

            snapshot_requests = session \
                .query(SnapshotRequest) \
                .filter(SnapshotRequest.state == GuestState.RESTORING.value) \
                .all()

            for snapshot in snapshot_requests:
                _restore_snapshot_request(root_logger, session, snapshot)

        time.sleep(10)


if __name__ == '__main__':
    main()
