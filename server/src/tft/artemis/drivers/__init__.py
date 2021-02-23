import argparse
import contextlib
import dataclasses
import json
import os
import re
import tempfile
import threading
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union, cast

import gluetool
import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import CACHE, Failure, process_output_to_str, safe_call
from ..db import GuestRequest, GuestTag
from ..db import PoolResourcesMetrics as PoolResourcesMetricsRecord
from ..db import PoolResourcesMetricsDimensions, Query, SnapshotRequest, SSHKey
from ..environment import Environment
from ..guest import GuestState

PoolResourcesIDsType = Dict[str, Any]
GuestTagsType = Dict[str, str]


class _AnyArchitecture:
    pass

    def __repr__(self) -> str:
        return '<Any>'


AnyArchitecture = _AnyArchitecture()


class PoolLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str) -> None:
        super(PoolLogger, self).__init__(logger, {
            'ctx_pool_name': (10, poolname)
        })


@dataclasses.dataclass
class PoolImageInfoType:
    """
    Describes important information about a pool image.

    Name vs ID: many pool backends support 2 ways how to identify an image, a name and an ID. One is often nice
    and good looking, the other is ugly and hard to quickly identify. When talking to their backends, drivers
    almost exclusively use the ID, but when presenting information to users (logs, Sentry issues, events, compose
    => image mappings, and so on) the name is much better.

    :ivar name: a human-readable, easy-to-follow **name** of the image. It usually consists of distribution name,
        its version, maybe a release date and architecture, describing altogether what OS the image provides. For
        example, ``RHEL-8.3.0-20201012-x86_64`` is a typical "image name".
    :ivar id: ID of the image as understood by the pool backed. Images are often assigned an ID, ugly looking
        hash-ish ID the pool backend then uses to identify the image. :py:attr:`name` is supported by these
        clouds to make the situation easier for punny humans.
    """

    name: str
    id: str

    def __repr__(self) -> str:
        return '<PoolImageInfoType: name={} id={}>'.format(self.name, self.id)


class PoolCapabilities(argparse.Namespace):
    supported_architectures: Union[List[str], _AnyArchitecture]
    supports_snapshots = False

    def supports_arch(self, arch: str) -> bool:
        """
        Check whether a given architecture is supported. It is either listed among architectures supported
        by the pool, or pool supports *any* architecture.

        :param arch: architecture to test support for.
        """

        if self.supported_architectures is AnyArchitecture:
            return True

        # Here we know the attribute must be a list, because we ruled out the `AnyArchitecture` above, but mypy
        # can't deduce it.
        return arch in cast(List[str], self.supported_architectures)


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


@dataclasses.dataclass
class PoolData:
    """
    Base class for containers of pool-specific data stored in guests requests. It is up to each driver
    to declare its own fields.
    """

    @classmethod
    def is_empty(cls, guest_request: GuestRequest) -> bool:
        return guest_request.pool_data == json.dumps({})

    def serialize(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    @classmethod
    def unserialize(cls, guest_request: GuestRequest) -> Any:
        return cls(**json.loads(guest_request.pool_data))  # type: ignore


@dataclasses.dataclass
class ProvisioningProgress:
    """
    Container for reporting provisioning progress by drivers.
    """

    #: Whether the provisioning is complete.
    is_acquired: bool

    #: Pool-specific data drivers wishes to store for the guest request in question.
    pool_data: PoolData

    #: If the provisioning is complete - ``is_acquired`` is set to ``True``, driver is expected
    #: to set this property to guest's IP address.
    address: Optional[str] = None

    #: If set, it represents a suggestion from the pool driver: it does not make much sense
    #: to run :py:meth:`PoolDriver.update_guest` sooner than this second in the future. If
    #: left unset, Artemis core will probably run the update as soon as possible.
    delay_update: Optional[int] = None


class PoolDriver(gluetool.log.LoggerMixin):
    #: Template for a cache key holding pool image info.
    POOL_IMAGE_INFO_CACHE_KEY = 'pool.{}.image-info'

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

        self.image_info_cache_key = self.POOL_IMAGE_INFO_CACHE_KEY.format(self.poolname)

    def __repr__(self) -> str:
        return '<{}: {}>'.format(self.__class__.__name__, self.poolname)

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

    def dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_ids: PoolResourcesIDsType,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        """
        Schedule removal of given resources. Resources are identified by keys and values which are passed
        to :py:meth:`release_pool_resource` method. The actual keys are completely under control of the
        driver.
        """

        if not resource_ids:
            return Ok(None)

        # Local import, to avoid circular imports
        from ..tasks import dispatch_task, release_pool_resources

        return dispatch_task(
            logger,
            release_pool_resources,
            self.poolname,
            json.dumps(resource_ids),
            guest_request.guestname if guest_request else None
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        resources_ids: PoolResourcesIDsType
    ) -> Result[None, Failure]:
        """
        Release any pool resources identified by provided IDs.

        This method should implement the actual removal of cloud VM, instances, volumes, IP addresses and other
        resources that together comprise what has been provisioned for a guest or snapshot. Instead of performing
        this "cleanup" in the main acquire/update/release chains, the chains should schedule execution of this method
        by calling :py:meth:`dispatch_resource_cleanup`. This will let them proceed with update of their given guest
        without worrying about the cleaup after the previous - possibly crashed - provisioning attempt.

        :param resources_ids: mapping of resource names and their IDs. The content is fully cloud-specific and
            understandable by this particular driver only.
        """

        raise NotImplementedError()

    def can_acquire(
        self,
        environment: Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.

        :param Environment environment: environment to check
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """

        raise NotImplementedError()

    def image_info_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfoType, Failure]:
        """
        Search pool resources, and find a pool-specific information for an image identified by the given name.
        """

        raise NotImplementedError()

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified by `environment`.

        Method is expected to return :py:class:`ProvisioningProgress` instance, with ``is_acquired`` signaling
        whether the process has finished or not. If set to ``False``, :py:meth:`update_guest` call will be
        scheduled by Artemis core, to check and update the progress.

        If the process finished - ``is_acquired`` set to ``True`` - method is expected to provide guest details
        via :py:class:`ProvisioningProgress` fields, namely ``address``.

        :param logger: logger to use for logging.
        :param guest_request: guest request to provision for.
        :param enviroment: environment to satisfy.
        :param master_key: Artemis' master SSH key.
        :param cancelled: if provided, and set, method is expected to cancel its work, and release
            resources it already allocated.
        """

        raise NotImplementedError()

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Update provisioning progress of a given request. The method is expected to check what :py:meth:`acquire_guest`
        may have started.

        Method is expected to return :py:class:`ProvisioningProgress` instance, with ``is_acquired`` signaling
        whether the process has finished or not. If set to ``False``, :py:meth:`update_guest` call will be
        scheduled by Artemis core, to check and update the progress.

        If the process finished - ``is_acquired`` set to ``True`` - method is expected to provide guest details
        via :py:class:`ProvisioningProgress` fields, namely ``address``.

        :param logger: logger to use for logging.
        :param guest_request: guest request to provision for.
        :param enviroment: environment to satisfy.
        :param master_key: Artemis' master SSH key.
        :param cancelled: if provided, and set, method is expected to cancel its work, and release
            resources it already allocated.
        """

        raise NotImplementedError()

    def stop_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Instructs a guest to stop.

        :param Guest guest: a guest to be stopped
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def start_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Instructs a guest to stop.

        :param Guest guest: a guest to be started
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def is_guest_stopped(self, guest: GuestRequest) -> Result[bool, Failure]:
        """
        Check if a guest is stopped

        :param Guest guest: a guest to be checked
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def is_guest_running(self, guest: GuestRequest) -> Result[bool, Failure]:
        """
        Check if a guest is running

        :param Guest guest: a guest to be checked
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def create_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Create snapshot of given guest.

        Method is expected to return :py:class:`ProvisioningProgress` instance, with ``is_acquired`` signaling
        whether the process has finished or not. If set to ``False``, :py:meth:`update_snapshot` call will be
        scheduled by Artemis core, to check and update the progress.

        :param guest_request: guest request to provision for.
        :param snapshot_request: snapshot request to satisfy.
        """
        raise NotImplementedError()

    def update_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Update progress of snapshot creation.

        Method is expected to return :py:class:`ProvisioningProgress` instance, with ``is_acquired`` signaling
        whether the process has finished or not. If set to ``False``, :py:meth:`update_snapshot` call will be
        scheduled by Artemis core, to check and update the progress.

        :param guest_request: guest request to provision for.
        :param snapshot_request: snapshot request to update.
        """
        raise NotImplementedError()

    def remove_snapshot(
        self,
        snapshot_request: SnapshotRequest,
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
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
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
        capabilities = PoolCapabilities(
            supported_architectures=AnyArchitecture,
            supports_snapshots=False
        )

        capabilities_config = self.pool_config.get('capabilities')

        if not capabilities_config:
            return Ok(capabilities)

        if 'supported-architectures' in capabilities_config:
            supported_architectures = capabilities_config['supported-architectures']

            if isinstance(supported_architectures, str) and supported_architectures.strip().lower() == 'any':
                # Already set by initialization
                pass

            elif isinstance(supported_architectures, list):
                capabilities.supported_architectures = [
                    str(arch) for arch in capabilities_config['supported-architectures']
                ]

            else:
                return Error(Failure(
                    'cannot parse supported architectures',
                    # converting to string because at this point, we don't know what's the type, and the failure
                    # might land in db, causing troubles to serialization.
                    supported_architectures=repr(supported_architectures)
                ))

        if 'supports-snapshots' in capabilities_config:
            capabilities.supports_snapshots = gluetool.utils.normalize_bool_option(
                cast(str, capabilities_config['supports-snapshots'])
            )

        return Result.Ok(capabilities)

    def get_guest_tags(
        self,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[GuestTagsType, Failure]:
        """
        Get all tags applicable for a given guest request.

        Collects all system, pool, and guest-level tags.
        """

        system_tags = GuestTag.fetch_system_tags(session)

        if system_tags.is_error:
            return Error(system_tags.unwrap_error())

        pool_tags = GuestTag.fetch_pool_tags(session, self.poolname)

        if pool_tags.is_error:
            return Error(pool_tags.unwrap_error())

        tags: GuestTagsType = {
            **{r.tag: r.value for r in system_tags.unwrap()},
            **{r.tag: r.value for r in pool_tags.unwrap()}
        }

        tags['ArtemisGuestName'] = guest_request.guestname

        return Ok(tags)

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

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfoType], Failure]:
        """
        Responsible for fetching the most up-to-date image info..

        This is the only method common driver needs to reimplement. The default
        implementation yields "no images" default as it has no actual pool to query.
        The real driver would probably to query its pool's API, and retrieve actual data.
        """

        return Ok([])

    def refresh_pool_image_info(self) -> Result[None, Failure]:
        """
        Responsible for updating the cache with the most up-to-date image info. For that purpose, it calls
        :py:meth:`fetch_pool_image_info` to retrieve the actual data - this part is driver-specific, while
        the cache operations are not.

        Since :py:meth:`fetch_pool_image_info` is presumably going to talk to pool API, we cannot allow it
        to be part of the critical paths like routing, therefore we exchange metrics through the cache.

        Data are stored as a mapping between image name and a containers serialized into JSON blobs.
        """

        r_image_info = self.fetch_pool_image_info()

        if r_image_info.is_error:
            return Error(r_image_info.unwrap_error())

        image_info = r_image_info.unwrap()

        # When we get an empty list, we should remove the key entirely, to make queries looking for any image
        # return `None` aka "not found". It's the same as if we'd try to remove all entries, just with one
        # action.
        if not image_info:
            r_action = safe_call(
                cast(Callable[[str], None], CACHE.get().delete),
                self.image_info_cache_key
            )

        else:
            # Two steps: create new structure, and replace the old one. We cannot check the old one
            # and remove entries that are no longer valid.
            actual_key = self.image_info_cache_key
            new_key = '{}.new'.format(self.image_info_cache_key)

            r_action = safe_call(
                cast(Callable[[str, str, Dict[str, str]], None], CACHE.get().hmset),
                new_key,
                {
                    ii.name: json.dumps(dataclasses.asdict(ii))
                    for ii in r_image_info.unwrap()
                    if ii.name
                }
            )

            if r_action.is_error:
                return Error(r_action.unwrap_error())

            r_action = safe_call(
                cast(Callable[[str, str], None], CACHE.get().rename),
                new_key,
                actual_key
            )

        if r_action.is_error:
            return Error(r_action.unwrap_error())

        return Ok(None)

    def get_pool_image_info(self, imagename: str) -> Result[Optional[PoolImageInfoType], Failure]:
        """
        Retrieve "current" image info metrics, as stored in the cache. Given how the information is acquired,
        it will **always** be slightly outdated.

        .. note::

           There is a small window opened to race conditions: if provisioning gets to this method *before*
           pool's image info has been fetched and stored in the cache, after the cache was emptied (e.g. by
           a caching service restart), then this method will return ``None``, falsely pretending the image
           is unknown.
        """

        r_fetch = safe_call(
            cast(Callable[[str, str], Optional[bytes]], CACHE.get().hget),
            self.image_info_cache_key,
            imagename
        )

        if r_fetch.is_error:
            return Error(r_fetch.unwrap_error())

        serialized = r_fetch.unwrap()

        if serialized is None:
            return Ok(None)

        r_unserialize = safe_call(PoolImageInfoType, **json.loads(serialized.decode('utf-8')))

        if r_unserialize.is_error:
            return Error(r_unserialize.unwrap_error())

        return Ok(r_unserialize.unwrap())


def vm_info_to_ip(output: Any, key: str, regex: str) -> Result[Optional[str], Failure]:
    if not output[key]:
        # It's ok! That means the instance is not ready yet. We need to wait a bit for ip address.
        return Ok(None)

    match_obj = re.match(regex, output[key])
    if not match_obj:
        return Error(Failure('Failed to get an ip'))

    return Ok(match_obj.group(1))


def run_cli_tool(
    logger: gluetool.log.ContextAdapter,
    command: List[str],
    json_output: bool = False,
    command_scrubber: Optional[Callable[[List[str]], List[str]]] = None,
    allow_empty: bool = True,
    env: Optional[Dict[str, str]] = None
) -> Result[Tuple[Any, gluetool.utils.ProcessOutput], Failure]:
    """
    Run a given command, and return its output.

    This helper is designed for pool drivers that require a common functionality:

    * run a CLI tool, with options
    * capture its standard output
    * optionally, convert the standard output to JSON.

    This function does exactly this, and tries to make life easier for drivers that need to do some
    processing of this output. Returns the original command output as well.

    :param command: command to execute, plus its options.
    :param json_output: if set, command's standard output will be parsed as JSON.
    :param command_strubber: a callback for converting the command to its "scrubbed" version, without any
        credentials or otherwise sensitive items. If unset, a default 1:1 no-op scrubbing is used.
    :param allow_empty: under some conditions, the standard output, as returned by Python libraries,
        may be ``None``. If this parameter is unset, such an output would be reported as a failure,
        if set, ``None`` would be converted to an empty string, and processed as any other output.
    :returns: either a valid result, a tuple of two items, or an error with a :py:class:`Failure` describing
        the problem. The first item of the tuple is either command's standard output, or, if ``json_output``
        was set, a datastructure representing command's output after parsing it as JSON structure. The second
        pair of the tuple is always :py:class:`gluetool.utils.ProcessOutput`.
    """

    # We have our own no-op scrubber, preserving the command.
    def _noop_scrubber(_command: List[str]) -> List[str]:
        return _command

    command_scrubber = command_scrubber or _noop_scrubber

    try:
        output = gluetool.utils.Command(command).run(env=env)

    except gluetool.glue.GlueCommandError as exc:
        return Error(Failure.from_exc(
            'error running CLI command',
            exc,
            command_output=exc.output,
            scrubbed_command=command_scrubber(command)
        ))

    if output.stdout is None:
        if not allow_empty:
            return Error(Failure(
                'CLI did not emit any output',
                command_output=output,
                scrubbed_command=command_scrubber(command)
            ))

        output_stdout = ''

    else:
        # We *know* for sure that `output.stdout` is not `None`, therefore `process_output_to_str` can never return
        # `None`. Type checking can't infere this information, therefore it believes the return value may be `None`,
        # and complains about type collision with variable set in the `if` branch above (which is *not* `Optional`).
        output_stdout = cast(
            str,
            process_output_to_str(output, stream='stdout')
        )

    if json_output:
        if not output_stdout:
            return Error(Failure(
                'CLI did not emit any output, cannot treat as JSON',
                command_output=output,
                scrubbed_command=command_scrubber(command)
            ))

        try:
            return Ok((json.loads(output_stdout), output))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to convert string to JSON',
                exc=exc,
                command_output=output,
                scrubbed_command=command_scrubber(command)
            ))

    return Ok((output_stdout, output))


@contextlib.contextmanager
def create_tempfile(file_contents: Optional[str] = None, **kwargs: Any) -> Iterator[str]:
    """Returns a path to the temporary file with given contents."""
    with tempfile.NamedTemporaryFile(delete=False, **kwargs) as temp_file:
        if file_contents:
            temp_file.write(file_contents.encode('utf-8'))
            # Make sure all changes are committed to the OS
            temp_file.flush()
    try:
        yield temp_file.name
    finally:
        os.unlink(temp_file.name)
