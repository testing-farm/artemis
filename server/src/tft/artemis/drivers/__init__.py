import argparse
import dataclasses
import threading
import sqlalchemy
import sqlalchemy.orm.session

import gluetool.log
from gluetool.result import Result, Ok, Error

from .. import Failure
from ..db import GuestRequest, SnapshotRequest, SSHKey, Query
from ..db import PoolResourcesMetrics as PoolResourcesMetricsRecord, PoolResourcesMetricsDimensions
from ..environment import Environment
from ..guest import Guest, GuestState
from ..snapshot import Snapshot

# Type annotations
from typing import cast, Any, Callable, List, Dict, Optional


class PoolLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str) -> None:
        super(PoolLogger, self).__init__(logger, {
            'ctx_pool_name': (10, poolname)
        })


class PoolCapabilities(argparse.Namespace):
    supports_snapshots = False


@dataclasses.dataclass
class PoolResources:
    """
    Describes current values of pool resources. It is intentionally left
    "dimension-less", not tied to limits nor usage side of the equation, as the
    actual resource types do not depend on this information.

    All fields are optional, leaving them unset signals the pool driver is not
    able/not interested in tracking the given field.

    This is a main class we use for transporting resources metrics between
    interested parties. On the database boundary, we translate this class
    to/from database records, represented by
    :py:class:`PoolResourcesMetricsRecord`.
    """

    instances: Optional[int] = None
    """
    Number of instances (or machines, VMs, servers, etc. - depending on pool's
    terminology).
    """

    cores: Optional[int] = None
    """
    Number of CPU cores. Given the virtual nature of many pools, cores are more
    common commodity than CPUs.
    """

    memory: Optional[int] = None
    """
    Size of RAM, in bytes.
    """

    diskspace: Optional[int] = None
    """
    Size of disk space, in bytes.
    """

    snapshots: Optional[int] = None
    """
    Number of instance snapshots.
    """

    @classmethod
    def from_db(cls, record: PoolResourcesMetricsRecord) -> 'PoolResources':
        """
        Initialize fields from a gien database record.
        """

        container = cls()

        for field in dataclasses.fields(container):
            setattr(container, field.name, getattr(record, field.name))

        return container

    def _to_db(
        self,
        pool: 'PoolDriver',
        dimension: PoolResourcesMetricsDimensions,
    ) -> PoolResourcesMetricsRecord:
        return PoolResourcesMetricsRecord(
            poolname=pool.poolname,
            dimension=dimension.value,
            **{
                field.name: getattr(self, field.name)
                for field in dataclasses.fields(self)
            }
        )

    def to_db(self, pool: 'PoolDriver') -> PoolResourcesMetricsRecord:
        """
        Convert into a corresponding database record.
        """

        raise NotImplementedError()


class PoolResourcesUsage(PoolResources):
    """
    Describes current usage of pool resources.
    """

    @classmethod
    def from_db(cls, record: PoolResourcesMetricsRecord) -> 'PoolResourcesUsage':
        return cast(
            PoolResourcesUsage,
            super(PoolResourcesUsage, cls).from_db(record)
        )

    def to_db(
        self,
        pool: 'PoolDriver',
    ) -> PoolResourcesMetricsRecord:
        return self._to_db(pool, PoolResourcesMetricsDimensions.USAGE)


class PoolResourcesLimits(PoolResources):
    """
    Describes current limits of pool resources.
    """

    @classmethod
    def from_db(cls, record: PoolResourcesMetricsRecord) -> 'PoolResourcesLimits':
        return cast(
            PoolResourcesLimits,
            super(PoolResourcesLimits, cls).from_db(record)
        )

    def to_db(
        self,
        pool: 'PoolDriver',
    ) -> PoolResourcesMetricsRecord:
        return self._to_db(pool, PoolResourcesMetricsDimensions.LIMITS)


@dataclasses.dataclass
class PoolResourcesDepleted:
    """
    Describes whether and which pool resources have been depleted.
    """

    instances: bool = False
    cores: bool = False
    memory: bool = False
    diskspace: bool = False
    snapshots: bool = False

    def is_depleted(self) -> bool:
        """
        Returns ``True`` if any of resources is marked as depleted.
        """

        return any(dataclasses.asdict(self).values())

    def depleted_resources(self) -> List[str]:
        """
        Returns list of resource names of resources which are marked as depleted.
        """

        return [
            field.name
            for field in dataclasses.fields(self)
            if getattr(self, field.name) is True
        ]


@dataclasses.dataclass
class PoolResourcesMetrics:
    """
    Describes resources of a pool, both limits and usage.
    """

    limits: PoolResourcesLimits = dataclasses.field(default_factory=PoolResourcesLimits)
    usage: PoolResourcesUsage = dataclasses.field(default_factory=PoolResourcesUsage)

    def get_depletion(
        self,
        is_enough: Callable[[str, int, int], bool]
    ) -> PoolResourcesDepleted:
        """
        Using a test callback, provided by caller, compare limits and usage,
        and yield :py:class:`PoolResourcesDepleted` instance describing what
        resources are depleted.

        A test callback ``is_enough`` is called for every resource, with
        resource name, its limit and usage as arguments, and its job is to
        decide whether the resource is depleted (``True``) or not (``False``).
        """

        delta = PoolResourcesDepleted()

        for field in dataclasses.fields(self.limits):
            limit, usage = getattr(self.limits, field.name), getattr(self.usage, field.name)

            # Skip undefined values: if left undefined, pool does not care about this dimension.
            if not limit or not usage:
                continue

            setattr(delta, field.name, not is_enough(field.name, limit, usage))

        return delta


@dataclasses.dataclass
class PoolMetrics:
    current_guest_request_count: int = 0
    current_guest_request_count_per_state: Dict[GuestState, int] = \
        dataclasses.field(default_factory=dict)

    resources: PoolResourcesMetrics = dataclasses.field(default_factory=PoolResourcesMetrics)


class PoolDriver(gluetool.log.LoggerMixin):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super(PoolDriver, self).__init__(logger)

        self.poolname = poolname
        self.pool_config = pool_config

        self._pool_resources_metrics: Optional[PoolResourcesMetrics] = None

    def __repr__(self) -> str:
        return '<{}: {}>'.format(self.__class__.__name__, self.poolname)

    def guest_factory(
        self,
        guest_request: GuestRequest,
        ssh_key: SSHKey
    ) -> Result[Guest, Failure]:
        raise NotImplementedError()

    def snapshot_factory(
        self,
        snapshpt_request: SnapshotRequest
    ) -> Result[Snapshot, Failure]:
        raise NotImplementedError()

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

    def can_acquire(
        self,
        environment: Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """

        raise NotImplementedError()

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
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
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
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
        snapshot_request: SnapshotRequest,
        guest: Guest
    ) -> Result[Snapshot, Failure]:
        """
        Create snapshot of a guest.
        If the returned snapshot is not active, ``update_snapshot`` would be scheduled by Artemis core.

        :param SnapshotRequest snapshot_request: snapshot request to process
        :param Guest guest: a guest, which will be snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def update_snapshot(
        self,
        snapshot: Snapshot,
        guest: Guest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[Snapshot, Failure]:
        """
        Update state of the snapshot.
        Called for unfinished snapshot.
        If snapshot status is active, snapshot request is evaluated as finished

        :param Snapshot snapshot: snapshot to update
        :param Guest guest: a guest, which was snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def remove_snapshot(
        self,
        snapshot: Snapshot,
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
        snapshot_request: SnapshotRequest,
        guest: Guest
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

    def current_guests_in_pool(self, session: sqlalchemy.orm.session.Session) -> List[GuestRequest]:
        return Query.from_session(session, GuestRequest) \
            .filter(GuestRequest.poolname == self.poolname) \
            .all()

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        """
        Responsible for fetching the most up-to-date resources metrics.

        This is the only method common driver needs to reimplement. The default
        implementation yields "do not care" defaults for all resources as it
        has no actual pool to query. The real driver would probably to query
        its pool's API, and retrieve actual data.
        """

        return Ok(PoolResourcesMetrics())

    def refresh_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session
    ) -> Result[None, Failure]:
        """
        Responsible for updating the database records with the most up-to-date
        metrics. For that purpose, it calls
        :py:meth:`fetch_pool_resources_metrics` to retrieve the actual data
        - this part is driver-specific, while the database operations are not.

        This is the "writer" - called periodically, it updates database with
        fresh metrics every now and then.
        :py:meth:`get_pool_resources_metrics` is the corresponding "reader".

        Since :py:meth:`fetch_pool_resources_metrics` is presumably going to
        talk to pool API, we cannot allow it to be part of the critical paths
        like routing, therefore we exchange metrics through the database.
        """

        r_resource_metrics = self.fetch_pool_resources_metrics(logger)

        if r_resource_metrics.is_error:
            return Error(r_resource_metrics.unwrap_error())

        resources = r_resource_metrics.unwrap()

        gluetool.log.log_dict(logger.info, 'resources metrics refresh', dataclasses.asdict(resources))

        session.merge(resources.limits.to_db(self))
        session.merge(resources.usage.to_db(self))

        return Ok(None)

    def get_pool_resources_metrics(
        self,
        session: sqlalchemy.orm.session.Session
    ) -> Result[PoolResourcesMetrics, Failure]:
        """
        Retrieve "current" resources metrics, as stored in the database. Given
        how the metrics are acquired, they will **always** be slightly
        outdated.

        This is the "reader" - called when needed, it returns what's considered
        to be the actual metrics. :py:meth:`refresh_pool_resources_metrics` is
        the corresponding "writer".
        """

        resources = PoolResourcesMetrics()

        limits_record = PoolResourcesMetricsRecord.get_limits_by_pool(session, self.poolname)
        usage_record = PoolResourcesMetricsRecord.get_usage_by_pool(session, self.poolname)

        if limits_record:
            resources.limits = PoolResourcesLimits.from_db(limits_record)

        if usage_record:
            resources.usage = PoolResourcesUsage.from_db(usage_record)

        return Ok(resources)

    def metrics(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session
    ) -> PoolMetrics:
        """ Provide Prometheus metrics about current pool state. """

        assert self.poolname
        metrics = PoolMetrics()

        current_guests = self.current_guests_in_pool(session)
        metrics.current_guest_request_count = len(current_guests)

        for state in GuestState:
            current_guest_count = len([guest for guest in current_guests if guest.state == state.value])
            metrics.current_guest_request_count_per_state[state] = current_guest_count

        if not self._pool_resources_metrics:
            r_resources_metrics = self.get_pool_resources_metrics(session)

            if r_resources_metrics.is_error:
                logger.warning('failed to fetch pool resources metrics')

            else:
                self._pool_resources_metrics = r_resources_metrics.unwrap()

                metrics.resources = self._pool_resources_metrics

        else:
            metrics.resources = self._pool_resources_metrics

        return metrics
