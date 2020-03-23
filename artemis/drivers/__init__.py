import argparse
import dataclasses
import sqlalchemy

import gluetool.log
from gluetool.result import Result, Ok

import artemis
import artemis.environment
from artemis import Failure
from artemis.guest import Guest, GuestState
import artemis.snapshot

# Type annotations
from typing import Any, List, Dict, Optional, cast
import threading


class PoolCapabilities(argparse.Namespace):
    supports_snapshots = False


@dataclasses.dataclass
class PoolMetrics:
    current_guest_request_count: int = 0
    current_guest_request_count_per_state: Dict[artemis.guest.GuestState, int] = \
        dataclasses.field(default_factory=dict)


class PoolDriver(gluetool.log.LoggerMixin):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        pool_config: Dict[str, Any],
        poolname: Optional[str] = None
    ) -> None:
        super(PoolDriver, self).__init__(logger)

        self.pool_config = pool_config
        self.poolname = poolname

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[Guest, Failure]:
        raise NotImplementedError()

    def snapshot_factory(
        self,
        snapshpt_request: artemis.db.SnapshotRequest
    ) -> Result[artemis.snapshot.Snapshot, Failure]:
        raise NotImplementedError()

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

    def can_acquire(
        self,
        environment: artemis.environment.Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """

        raise NotImplementedError()

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: artemis.db.GuestRequest,
        environment: artemis.environment.Environment,
        master_key: artemis.db.SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        If the returned guest is missing an address, it is considered to be unfinished,
        and followup calls to ``update_guest`` would be scheduled by Artemis core.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key used for SSH connection.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        raise NotImplementedError()

    def update_guest(
        self,
        guest: Guest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """

        raise NotImplementedError()

    def release_guest(self, guest: Guest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def create_snapshot(
        self,
        snapshot_request: artemis.db.SnapshotRequest,
        guest: artemis.guest.Guest
    ) -> Result[artemis.snapshot.Snapshot, Failure]:
        """
        Create snapshot of a guest.
        If the returned snapshot is not active, ``update_snapshot`` would be scheduled by Artemis core.

        :param SnapshotRequest snapshot_request: snapshot request to process
        :param Guest guest: a guest, which will be snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`artemis.snapshot.Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def update_snapshot(
        self,
        snapshot: artemis.snapshot.Snapshot,
        guest: artemis.guest.Guest,
        canceled: Optional[threading.Event] = None
    ) -> Result[artemis.snapshot.Snapshot, Failure]:
        """
        Update state of the snapshot.
        Called for unfinished snapshot.
        If snapshot status is active, snapshot request is evaluated as finished

        :param Snapshot snapshot: snapshot to update
        :param Guest guest: a guest, which was snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`artemis.snapshot.Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def remove_snapshot(
        self,
        snapshot: artemis.snapshot.Snapshot,
    ) -> Result[bool, Failure]:
        """
        Remove snapshot from the pool.

        :param Snapshot snapshot: snapshot to remove
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """
        raise NotImplementedError()

    def restore_snapshot(
        self,
        snapshot_request: artemis.db.SnapshotRequest,
        guest: artemis.guest.Guest
    ) -> Result[bool, Failure]:
        """
        Restore the guest to the snapshot.

        :param SnapshotRequest snapshot_request: snapshot request to process
        :param Guest guest: a guest, which will be restored
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """
        raise NotImplementedError()

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        # nothing yet, thinking about what capabilities might Beaker provide...

        return Result.Ok(PoolCapabilities())

    def current_guests_in_pool(self, session: sqlalchemy.orm.session.Session) -> List[artemis.db.GuestRequest]:
        return cast(List[artemis.db.GuestRequest],
                    session.query(artemis.db.GuestRequest)
                    .filter(artemis.db.GuestRequest.poolname == self.poolname)
                    .all())

    def metrics(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session
    ) -> PoolMetrics:
        """ Provide Promethues metrics about current pool state. """

        assert self.poolname
        metrics = PoolMetrics()

        current_guests = self.current_guests_in_pool(session)
        metrics.current_guest_request_count = len(current_guests)

        for state in GuestState:
            current_guest_count = len([guest for guest in current_guests if guest.state == state.value])
            metrics.current_guest_request_count_per_state[state] = current_guest_count

        return metrics
