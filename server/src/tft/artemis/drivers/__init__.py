import contextlib
import dataclasses
import datetime
import enum
import json
import os
import re
import shlex
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Pattern, Tuple, Type, TypeVar, Union, cast

import gluetool
import gluetool.log
import gluetool.utils
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from pint import Quantity
from typing_extensions import Protocol

from .. import Failure, JSONType, Knob, SerializableContainer, get_cached_item, get_cached_items_as_list, \
    process_output_to_str, refresh_cached_set, safe_call
from ..context import CACHE, LOGGER
from ..db import GuestLog, GuestLogState, GuestRequest, GuestTag, SnapshotRequest, SSHKey
from ..environment import UNITS, Environment, Flavor
from ..metrics import PoolCostsMetrics, PoolMetrics, PoolResourcesMetrics, ResourceType

T = TypeVar('T')


GuestTagsType = Dict[str, str]


PatchFlavorsSpecType = List[
    Dict[
        str,
        Union[
            str,
            Dict[str, Union[str, int]]
        ]
    ]
]


IP_ADDRESS_PATTERN = re.compile(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3})')  # noqa: FS003


KNOB_DISPATCH_RESOURCE_CLEANUP_DELAY: Knob[int] = Knob(
    'pool.dispatch-resource-cleanup',
    """
    A delay, in seconds, to schedule pool resources release with. This may be useful for post mortem investigation
    of crashed resources.
    """,
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_DISPATCH_RESOURCE_CLEANUP_DELAY',
    cast_from_str=int,
    default=0
)

KNOB_LOGGING_SLOW_CLI_COMMANDS: Knob[bool] = Knob(
    'logging.cli.slow-commands',
    """
    When enabled, Artemis would log "slow" CLI commands - commands whose execution took longer than
    ARTEMIS_LOG_SLOW_CLI_COMMAND_THRESHOLD seconds.
    """,
    has_db=False,
    envvar='ARTEMIS_LOG_SLOW_CLI_COMMANDS',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_SLOW_CLI_COMMAND_THRESHOLD: Knob[float] = Knob(
    'logging.cli.slow-command-threshold',
    'Minimal time, in seconds, spent executing a CLI command for it to be reported as "slow".',
    has_db=False,
    envvar='ARTEMIS_LOG_SLOW_CLI_COMMAND_THRESHOLD',
    cast_from_str=float,
    default=10.0
)

KNOB_LOGGING_SLOW_CLI_COMMAND_PATTERN: Knob[str] = Knob(
    'logging.cli.slow-command-pattern',
    'Log only slow commands matching the pattern.',
    has_db=False,
    envvar='ARTEMIS_LOG_SLOW_CLI_COMMAND_PATTERN',
    cast_from_str=str,
    default=r'.*'
)

# Precompile the slow command pattern
try:
    SLOW_CLI_COMMAND_PATTERN = re.compile(KNOB_LOGGING_SLOW_CLI_COMMAND_PATTERN.value)

except Exception as exc:
    Failure.from_exc(
        'failed to compile ARTEMIS_LOG_SLOW_CLI_COMMAND_PATTERN pattern',
        exc,
        pattern=KNOB_LOGGING_SLOW_CLI_COMMAND_PATTERN.value
    ).handle(LOGGER.get())

    sys.exit(1)


if hasattr(shlex, 'join'):
    command_join = shlex.join  # type: ignore

else:
    def command_join(command: List[str]) -> str:
        return ' '.join(shlex.quote(arg) for arg in command)


class _AnyArchitecture:
    pass

    def __repr__(self) -> str:
        return '<Any>'


AnyArchitecture = _AnyArchitecture()


@dataclasses.dataclass
class CLIOutput:
    #: CLI tool output.
    process_output: gluetool.utils.ProcessOutput

    #: Shortcut to :py:attr:`output`.stdout
    stdout: str

    #: If JSON output was expected by CLI caller, this attribute carries tool output converted to a data structure.
    json: Optional[JSONType] = None


class PoolLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str) -> None:
        super(PoolLogger, self).__init__(logger, {
            'ctx_pool_name': (10, poolname)
        })


@dataclasses.dataclass(repr=False)
class PoolImageInfo(SerializableContainer):
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
        return f'<PoolImageInfo: name={self.name} id={self.id}>'


class FlavorKeyGetterType(Protocol):
    def __call__(
        self,
        flavor: Flavor
    ) -> Tuple[int, Union[int, Quantity], Union[int, Quantity]]:
        pass


def flavor_to_key(
    flavor: Flavor
) -> Tuple[int, Union[int, Quantity], Union[int, Quantity]]:
    # All are optional, meaning "don't care", and in this sorting it doesn't matter (possible?)
    # TODO: better algorithm would be better, one aware of optional values (first? last?)
    return (
        flavor.cpu.cores or 0,
        flavor.memory or 0,
        flavor.disk.space or 0
    )


@dataclasses.dataclass
class PoolCapabilities:
    supported_architectures: Union[List[str], _AnyArchitecture] = AnyArchitecture

    #: If set, the pool driver can handle snapshots.
    supports_snapshots: bool = False
    supports_console_url: bool = False

    #: If set, the pool provides spot instances. Otherwise, only regular instances are supported.
    supports_spot_instances: bool = False

    #: If set, the driver can handle the post-installation script on its own. Otherwise, Artemis core will
    #: execute it in the preparation stage.
    supports_native_post_install_script: bool = False

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
class ConsoleUrlData:
    """
    Base class for guest console data.
    """
    type: str
    url: str
    expires: datetime.datetime


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
    def unserialize(cls: Type[T], guest_request: GuestRequest) -> T:
        return cls(**json.loads(guest_request.pool_data))  # type: ignore


class ProvisioningState(enum.Enum):
    """
    State of the provisioning. Used by drivers to notify the core workflow about the progress.
    """

    #: Provisioning is still incomplete, yet progressing without issues.
    PENDING = 'pending'

    #: Provisioning is complete.
    COMPLETE = 'complete'

    #: For some driver-specirfic reasons, the provisioning should be cancelled.
    CANCEL = 'cancel'


@dataclasses.dataclass
class ProvisioningProgress:
    """
    Container for reporting provisioning progress by drivers.
    """

    #: State of the provisioning.
    state: ProvisioningState

    #: Pool-specific data drivers wishes to store for the guest request in question.
    pool_data: PoolData

    #: If the provisioning is complete - ``is_acquired`` is set to ``True``, driver is expected
    #: to set this property to guest's IP address.
    address: Optional[str] = None

    #: If set, it represents a suggestion from the pool driver: it does not make much sense
    #: to run :py:meth:`PoolDriver.update_guest` sooner than this second in the future. If
    #: left unset, Artemis core will probably run the update as soon as possible.
    delay_update: Optional[int] = None

    #: If pool driver encountered errors that were not critical enough to be returned immediately, causing
    #: reschedule of the provisioning step, then to make them visible and logged, such failures should
    #: be stored in this list.
    pool_failures: List[Failure] = dataclasses.field(default_factory=list)


SerializedPoolResourcesIDs = str

#: Used to serialize ``datetime`` instances that are part of ``PoolResourcesIDs``.
RESOURCE_CTIME_FMT: str = '%Y-%m-%dT%H:%M:%S.%f'


@dataclasses.dataclass
class PoolResourcesIDs:
    """
    Container for various pool resource IDs, used for scheduling their removal.

    Serves as a base class for pool-specific implementations that add the actual fields for resources and IDs.
    """

    ctime: Optional[datetime.datetime] = None

    def is_empty(self) -> bool:
        return all([value is None for key, value in dataclasses.asdict(self).items() if key != 'ctime'])

    def serialize(self) -> SerializedPoolResourcesIDs:
        # Convert datetime object to string first
        data = dataclasses.asdict(self)
        data['ctime'] = data['ctime'].strftime(RESOURCE_CTIME_FMT) if data['ctime'] else None

        return json.dumps(data)

    @classmethod
    def unserialize(cls: Type[T], raw_resource_ids: SerializedPoolResourcesIDs) -> T:
        # Convert ctime string to datetime object
        data = json.loads(raw_resource_ids)
        data['ctime'] = datetime.datetime.strptime(data['ctime'], RESOURCE_CTIME_FMT) if data['ctime'] else None

        return cls(**data)  # type: ignore


@dataclasses.dataclass
class GuestLogUpdateProgress:
    state: GuestLogState

    url: Optional[str] = None
    blob: Optional[str] = None
    expires: Optional[datetime.datetime] = None

    #: If set, it represents a suggestion from the pool driver: it does not make much sense
    #: to run :py:meth:`PoolDriver.update_guest` sooner than this second in the future. If
    #: left unset, Artemis core will probably run the update as soon as possible.
    delay_update: Optional[int] = None


class PoolDriver(gluetool.log.LoggerMixin):
    image_info_class: Type[PoolImageInfo] = PoolImageInfo

    #: Template for a cache key holding pool image info.
    POOL_IMAGE_INFO_CACHE_KEY = 'pool.{}.image-info'

    #: Template for a cache key holding flavor image info.
    POOL_FLAVOR_INFO_CACHE_KEY = 'pool.{}.flavor-info'

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
        self._pool_costs_metrics: Optional[PoolCostsMetrics] = None

        self.image_info_cache_key = self.POOL_IMAGE_INFO_CACHE_KEY.format(self.poolname)  # noqa: FS002
        self.flavor_info_cache_key = self.POOL_FLAVOR_INFO_CACHE_KEY.format(self.poolname)  # noqa: FS002

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.poolname}>'

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

    def dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_ids: PoolResourcesIDs,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        """
        Schedule removal of given resources. Resources are identified by keys and values which are passed
        to :py:meth:`release_pool_resource` method. The actual keys are completely under control of the
        driver.
        """

        if resource_ids.is_empty():
            return Ok(None)

        r_delay = KNOB_DISPATCH_RESOURCE_CLEANUP_DELAY.get_value(pool=self)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        resource_ids.ctime = guest_request.ctime if guest_request else None

        # Local import, to avoid circular imports
        from ..tasks import dispatch_task, release_pool_resources

        return dispatch_task(
            logger,
            release_pool_resources,
            self.poolname,
            resource_ids.serialize(),
            guest_request.guestname if guest_request else None,
            delay=r_delay.unwrap()
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resources_ids: SerializedPoolResourcesIDs
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
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy the given environment.

        By default, the driver base class tries to run tests that are common for majority - if not all - of drivers:

        * make sure the requested architecture is supported by the driver.

        :param Environment environment: environment to check
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """

        r_capabilities = self.capabilities()

        if r_capabilities.is_error:
            return Error(r_capabilities.unwrap_error())

        capabilities = r_capabilities.unwrap()

        if not capabilities.supports_arch(environment.hw.arch):
            return Ok(False)

        return Ok(True)

    def _map_image_name_to_image_info_by_cache(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        """
        Retrieve pool-specific information for a given image name from pool image info cache.
        """

        r_ii = self.get_cached_pool_image_info(imagename)

        if r_ii.is_error:
            return Error(r_ii.unwrap_error())

        ii = r_ii.unwrap()

        if ii is None:
            return Error(Failure(
                'cannot find image by name',
                imagename=imagename
            ))

        return Ok(ii)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        """
        Search pool resources, and find a pool-specific information for an image identified by the given name.
        """

        raise NotImplementedError()

    def _map_environment_to_flavor_info_by_cache_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        flavorname: str
    ) -> Result[Flavor, Failure]:
        """
        Find a flavor matching the given name.

        :returns: a flavor info.
        """

        r_flavor = get_cached_item(
            CACHE.get(),
            self.flavor_info_cache_key,
            flavorname,
            Flavor
        )

        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        picked_flavor = r_flavor.unwrap()

        if picked_flavor is None:
            return Error(Failure(
                'no such flavor',
                flavorname=flavorname
            ))

        return Ok(picked_flavor)

    def _map_environment_to_flavor_info_by_cache_by_constraints(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment,
        sort_key_getter: FlavorKeyGetterType = flavor_to_key
    ) -> Result[List[Flavor], Failure]:
        """
        Evaluate the given environment, and return flavors suitable for the environment given its HW constraints.

        :returns: list of two-item tuples consisting of a pool flavor info paired with a corresponding
            :py:class:`environment.Flavor` instance.
        """

        # Fetch available flavor infos and pool capabilities first.
        r_flavors = self.get_cached_pool_flavor_infos()

        if r_flavors.is_error:
            return Error(r_flavors.unwrap_error())

        r_capabilities = self.capabilities()

        if r_capabilities.is_error:
            return Error(r_capabilities.unwrap_error())

        pool_flavors = r_flavors.unwrap()
        capabilities = r_capabilities.unwrap()

        # For each flavor info and arch, create a Flavor description we can then match against the HW constraints.
        # TODO: what if some flavors are not supported on all arches?
        flavors: List[Flavor] = []

        for flavor in pool_flavors:
            if capabilities.supported_architectures is AnyArchitecture:
                flavors.append(flavor)

            else:
                assert isinstance(capabilities.supported_architectures, list)

                for arch in capabilities.supported_architectures:
                    arch_flavor = dataclasses.replace(flavor, arch=arch)

                    flavors.append(arch_flavor)

        gluetool.log.log_dict(logger.debug, 'available flavors', flavors)

        # Extract HW constraints specified by the environment.
        r_constraints = environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()

        if constraints is None:
            return Ok(flavors)

        gluetool.log.log_blob(logger.debug, 'constraint', constraints.format())  # noqa: FS002

        # The actual filter: pick flavors that pass the test and match the requirements.
        suitable_flavors = [
            flavor
            for flavor in flavors
            if constraints.eval_flavor(logger, flavor) is True
        ]

        gluetool.log.log_dict(logger.debug, 'suitable flavors', suitable_flavors)

        if not suitable_flavors:
            return Ok([])

        # Sort suitable flavors, the "smaller" ones first. The less cores, memory and diskpace the flavor has,
        # the smaller it is in eyes of this ordering.
        sorted_suitable_flavors = sorted(suitable_flavors, key=sort_key_getter)

        gluetool.log.log_dict(logger.debug, 'sorted suitable flavors', sorted_suitable_flavors)

        gluetool.log.log_dict(logger.debug, 'environment', environment.serialize_to_json())
        gluetool.log.log_blob(logger.debug, 'constraints', constraints.format())  # noqa: FS002

        return Ok(sorted_suitable_flavors)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
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
        :param cancelled: if provided, and set, method is expected to cancel its work, and release
            resources it already allocated.
        """

        raise NotImplementedError()

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
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

    def acquire_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest: GuestRequest
    ) -> Result[ConsoleUrlData, Failure]:
        """
        Acquire a guest console url.
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

    def update_guest_log(
        self,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        # TODO logs: add a list of supported logs to capabilities
        # cannot provide guest log: functionality not supported for this cloud driver
        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.ERROR
        ))

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        capabilities = PoolCapabilities()

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

        if 'supports-spot-instances' in capabilities_config:
            capabilities.supports_spot_instances = gluetool.utils.normalize_bool_option(
                cast(str, capabilities_config['supports-spot-instances'])
            )

        return Result.Ok(capabilities)

    def get_guest_tags(
        self,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[GuestTagsType, Failure]:
        """
        Get all tags applicable for a given guest request.

        Collects all system, pool, guest-level tags, and guest user data.

        Currently provided guest-level tags:

        * ``ArtemisGuestName``: guestname as known to Artemis, identifying the guest request. This tag does not change
          over time.
        * ``ArtemisGuestLabel``: nice, human-readable label assigned to the guest, usable e.g. for naming instances.
          This label **does** change over time.
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

        if guest_request.user_data:
            tags.update(json.loads(guest_request.user_data) or {})

        tags['ArtemisGuestName'] = guest_request.guestname
        # TODO: drivers could accept a template for the name, to allow custom naming schemes
        tags['ArtemisGuestLabel'] = f'artemis-guest-{datetime.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%S")}'

        return Ok(tags)

    def _fetch_pool_resources_metrics_from_config(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        """
        Initialize resource metrics with data specified by the pool configuration - purely optional, but this
        gives maintainers a chance to enforce limits where pool lacks the necessary functionality or when
        they decide other than existing limits are needed.
        """

        metrics = PoolResourcesMetrics(self.poolname)

        resources = self.pool_config.get('resources', None)
        if not resources:
            return Ok(metrics)

        configured_limits = resources.get('limits', {})

        for field_name in metrics.limits._TRIVIAL_FIELDS:
            if field_name not in configured_limits:
                continue

            try:
                setattr(metrics.limits, field_name, int(configured_limits[field_name]))

            except ValueError as exc:
                return Error(Failure.from_exc(
                    'failed to parse configured pool limit',
                    exc,
                    field_name=field_name,
                    field_value=configured_limits[field_name]
                ))

        return Ok(metrics)

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

        return self._fetch_pool_resources_metrics_from_config(logger)

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
            PoolMetrics(self.poolname).inc_error(self.poolname, 'resource-metrics-refresh-failed')

            return Error(r_resource_metrics.unwrap_error())

        resources = r_resource_metrics.unwrap()

        gluetool.log.log_dict(logger.debug, 'resources metrics refresh', dataclasses.asdict(resources))

        resources.limits.store()
        resources.usage.store()

        return Ok(None)

    def inc_costs(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_type: ResourceType,
        ctime: Optional[datetime.datetime],
    ) -> Result[None, Failure]:
        if not ctime:
            return Ok(None)

        duration = (datetime.datetime.utcnow() - ctime).total_seconds()

        costs_metrics = PoolCostsMetrics(self.poolname)

        resource_cost = self.pool_config.get('cost', {}).get(resource_type.value, 0)
        costs_metrics.inc_costs(resource_type, round(resource_cost * duration))

        return Ok(None)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        """
        Responsible for fetching the most up-to-date image info..

        This is the only method common driver needs to reimplement. The default
        implementation yields "no images" default as it has no actual pool to query.
        The real driver would probably to query its pool's API, and retrieve actual data.
        """

        return Ok([])

    def refresh_cached_pool_image_info(self) -> Result[None, Failure]:
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
            PoolMetrics(self.poolname).inc_error(self.poolname, 'image-info-refresh-failed')

            return Error(r_image_info.unwrap_error())

        r_refresh = refresh_cached_set(
            CACHE.get(),
            self.image_info_cache_key,
            {
                ii.name: ii
                for ii in r_image_info.unwrap()
                if ii.name
            }
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        PoolMetrics(self.poolname).refresh_image_info_updated_timestamp(self.poolname)

        return Ok(None)

    def get_cached_pool_image_info(self, imagename: str) -> Result[Optional[PoolImageInfo], Failure]:
        """
        Retrieve pool image info for an image of a given name.
        """

        return get_cached_item(CACHE.get(), self.image_info_cache_key, imagename, self.image_info_class)

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
        """
        Responsible for fetching the most up-to-date flavor info..

        This is the only method common driver needs to reimplement. The default
        implementation yields "no flavors" default as it has no actual pool to query.
        The real driver would probably to query its pool's API, and retrieve actual data.
        """

        return Ok([])

    def _fetch_custom_pool_flavor_info_from_config(
        self,
        logger: gluetool.log.ContextAdapter,
        flavors: Dict[str, Flavor]
    ) -> Result[List[Flavor], Failure]:
        """
        "Fetch" custom flavors specified in driver configuration. These are clones of existing flavors, but with
        some of the original properties changed in the clone.

        :param flavors: actual existing flavors that serve as basis for custom flavors.
        """

        custom_flavor_specs = cast(List[Dict[str, str]], self.pool_config.get('custom-flavors', []))

        if not custom_flavor_specs:
            return Ok([])

        custom_flavors = []

        gluetool.log.log_dict(logger.debug, 'base flavors', flavors)

        for custom_flavor_spec in custom_flavor_specs:
            customname = custom_flavor_spec['name']
            basename = custom_flavor_spec['base']

            if basename not in flavors:
                return Error(Failure(
                    'unknown base flavor',
                    customname=customname,
                    basename=basename
                ))

            base_flavor = flavors[basename]

            custom_flavor = base_flavor.clone()
            custom_flavor.name = customname

            custom_flavors.append(custom_flavor)

            if 'disk' in custom_flavor_spec:
                disk_patch = cast(Dict[str, Union[str, int]], custom_flavor_spec['disk'])

                if 'space' in disk_patch:
                    r_space = safe_call(UNITS, disk_patch['space'])

                    if r_space.is_error:
                        return Error(Failure.from_failure(
                            'failed to parse custom flavor disk.space',
                            r_space.unwrap_error(),
                            customname=customname,
                            basename=basename,
                            space=disk_patch['space']
                        ))

                    custom_flavor.disk.space = r_space.unwrap()

        gluetool.log.log_dict(logger.debug, 'custom flavors', custom_flavors)

        return Ok(custom_flavors)

    def _fetch_patched_pool_flavor_info_from_config(
        self,
        logger: gluetool.log.ContextAdapter,
        flavors: Dict[str, Flavor]
    ) -> Result[None, Failure]:
        """
        "Patch" existing flavors as specified by configuration. Some information may not be available via API,
        therefore maintainers can use ``patch-flavors`` to modify flavors as needed.

        :param flavors: actual existing flavors that serve as basis for custom flavors.
        """

        patch_flavor_specs = cast(PatchFlavorsSpecType, self.pool_config.get('patch-flavors', []))

        if not patch_flavor_specs:
            return Ok(None)

        gluetool.log.log_dict(logger.debug, 'base flavors', flavors)

        for patch_flavor_spec in patch_flavor_specs:
            flavorname = cast(str, patch_flavor_spec['name'])

            if flavorname not in flavors:
                return Error(Failure(
                    'unknown patched flavor',
                    flavorname=flavorname
                ))

            flavor = flavors[flavorname]

            # Don't worry about types, config schema makes sure the types are correct.
            if 'cpu' in patch_flavor_spec:
                cpu_patch = cast(Dict[str, Union[str, int]], patch_flavor_spec['cpu'])

                flavor.cpu.family = cast(
                    Optional[int],
                    cpu_patch.get('family', None)
                )
                flavor.cpu.family_name = cast(
                    Optional[str],
                    cpu_patch.get('family-name', None)
                )
                flavor.cpu.model = cast(
                    Optional[int],
                    cpu_patch.get('model', None)
                )
                flavor.cpu.model_name = cast(
                    Optional[str],
                    cpu_patch.get('model-name', None)
                )

            if 'disk' in patch_flavor_spec:
                disk_patch = cast(Dict[str, Union[str, int]], patch_flavor_spec['disk'])

                if 'space' in disk_patch:
                    r_space = safe_call(UNITS, disk_patch['space'])

                    if r_space.is_error:
                        return Error(Failure.from_failure(
                            'failed to parse patched flavor disk.space',
                            r_space.unwrap_error(),
                            flavorname=flavorname,
                            space=disk_patch['space']
                        ))

                    flavor.disk.space = r_space.unwrap()

        return Ok(None)

    def _fetch_pool_flavor_info_from_config(
        self,
        logger: gluetool.log.ContextAdapter,
        flavors: List[Flavor]
    ) -> Result[List[Flavor], Failure]:
        """
        "Fetch" flavor infos from the driver configuration. This includes both custom flavors and patch information.

        :param flavors: actual existing flavors that serve as basis for custom flavors.
        """

        flavors_map = {
            flavor.name: flavor
            for flavor in flavors
        }

        if 'custom-flavors' in self.pool_config:
            r_custom_flavors = self._fetch_custom_pool_flavor_info_from_config(
                logger,
                flavors_map
            )

            if r_custom_flavors.is_error:
                return Error(r_custom_flavors.unwrap_error())

            for flavor in r_custom_flavors.unwrap():
                flavors_map[flavor.name] = flavor

        if 'patch-flavors' in self.pool_config:
            r_patched_flavors = self._fetch_patched_pool_flavor_info_from_config(
                logger,
                flavors_map
            )

            if r_patched_flavors.is_error:
                return Error(r_patched_flavors.unwrap_error())

        return Ok(list(flavors_map.values()))

    def refresh_cached_pool_flavor_info(self) -> Result[None, Failure]:
        """
        Responsible for updating the cache with the most up-to-date flavor info. For that purpose, it calls
        :py:meth:`fetch_pool_flavor_info` to retrieve the actual data - this part is driver-specific, while
        the cache operations are not.

        Since :py:meth:`fetch_pool_flavor_info` is presumably going to talk to pool API, we cannot allow it
        to be part of the critical paths like routing, therefore we exchange metrics through the cache.

        Data are stored as a mapping between image name and a containers serialized into JSON blobs.
        """

        r_flavor_info = self.fetch_pool_flavor_info()

        if r_flavor_info.is_error:
            PoolMetrics(self.poolname).inc_error(self.poolname, 'flavor-info-refresh-failed')

            return Error(r_flavor_info.unwrap_error())

        real_flavors = r_flavor_info.unwrap()

        r_config_flavors = self._fetch_pool_flavor_info_from_config(LOGGER.get(), real_flavors)

        if r_config_flavors.is_error:
            return Error(r_config_flavors.unwrap_error())

        r_refresh = refresh_cached_set(
            CACHE.get(),
            self.flavor_info_cache_key,
            {
                fi.name: fi
                for fi in (real_flavors + r_config_flavors.unwrap())
                if fi.name
            }
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        PoolMetrics(self.poolname).refresh_image_info_updated_timestamp(self.poolname)

        return Ok(None)

    def get_cached_pool_flavor_info(self, flavorname: str) -> Result[Optional[Flavor], Failure]:
        """
        Retrieve "current" flavor info metrics, as stored in the cache. Given how the information is acquired,
        it will **always** be slightly outdated.

        .. note::

           There is a small window opened to race conditions: if provisioning gets to this method *before*
           pool's flavor info has been fetched and stored in the cache, after the cache was emptied (e.g. by
           a caching service restart), then this method will return ``None``, falsely pretending the flavor
           is unknown.
        """

        return get_cached_item(CACHE.get(), self.flavor_info_cache_key, flavorname, Flavor)

    def get_cached_pool_image_infos(self) -> Result[List[PoolImageInfo], Failure]:
        """
        Retrieve pool image info for all known images.
        """

        return get_cached_items_as_list(CACHE.get(), self.image_info_cache_key, self.image_info_class)

    def get_cached_pool_flavor_infos(self) -> Result[List[Flavor], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return get_cached_items_as_list(CACHE.get(), self.flavor_info_cache_key, Flavor)


def vm_info_to_ip(output: Any, key: str, regex: Optional[Pattern[str]] = None) -> Result[Optional[str], Failure]:
    if not output[key]:
        # It's ok! That means the instance is not ready yet. We need to wait a bit for ip address.
        return Ok(None)

    regex = regex or IP_ADDRESS_PATTERN

    match_obj = regex.search(output[key])

    if not match_obj:
        return Error(Failure(
            'failed to parse an IP address',
            input=output[key]
        ))

    return Ok(match_obj.group(1))


def run_cli_tool(
    logger: gluetool.log.ContextAdapter,
    command: List[str],
    json_output: bool = False,
    command_scrubber: Optional[Callable[[List[str]], List[str]]] = None,
    allow_empty: bool = True,
    env: Optional[Dict[str, str]] = None,
    # for CLI calls metrics
    poolname: Optional[str] = None,
    commandname: Optional[str] = None
) -> Result[CLIOutput, Failure]:
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
    :returns: either a valid result, :py:class:`CLIOutput` instance, or an error with a :py:class:`Failure` describing
        the problem.
    """

    # We have our own no-op scrubber, preserving the command.
    def _noop_scrubber(_command: List[str]) -> List[str]:
        return _command

    command_scrubber = command_scrubber or _noop_scrubber

    start_time = time.monotonic()

    def _log_command(output: gluetool.utils.ProcessOutput) -> None:
        command_time = time.monotonic() - start_time

        if poolname is not None and commandname is not None:
            PoolMetrics.inc_cli_call(
                poolname,
                commandname,
                command_time
            )

        if KNOB_LOGGING_SLOW_CLI_COMMANDS.value is not True:
            return

        if SLOW_CLI_COMMAND_PATTERN.match(command_join(command)) is None:
            return

        if command_time < KNOB_LOGGING_SLOW_CLI_COMMAND_THRESHOLD.value:
            return

        assert command_scrubber is not None

        Failure(
            'detected a slow CLI command',
            command_output=output,
            scrubbed_command=command_scrubber(command),
            time=command_time
        ).handle(logger)

    try:
        output = gluetool.utils.Command(command, logger=logger).run(env=env)

    except gluetool.glue.GlueCommandError as exc:
        _log_command(exc.output)

        return Error(Failure.from_exc(
            'error running CLI command',
            exc,
            command_output=exc.output,
            scrubbed_command=command_scrubber(command)
        ))

    else:
        _log_command(output)

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
            return Ok(CLIOutput(output, output_stdout, json=json.loads(output_stdout)))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to convert string to JSON',
                exc=exc,
                command_output=output,
                scrubbed_command=command_scrubber(command)
            ))

    return Ok(CLIOutput(output, output_stdout))


def test_cli_error(failure: Failure, error_pattern: Pattern[str]) -> bool:
    if 'command_output' not in failure.details:
        return False

    os_output = cast(gluetool.utils.ProcessOutput, failure.details['command_output'])

    if not os_output.stderr:
        return False

    stderr = cast(bytes, os_output.stderr).decode('utf-8')

    if error_pattern.match(stderr):
        return True

    return False


def run_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    command: List[str],
    *,
    key: SSHKey,
    ssh_timeout: int
) -> Result[CLIOutput, Failure]:
    if guest_request.address is None:
        return Error(Failure('cannot connect to unknown remote address'))

    with create_tempfile(file_contents=key.private) as private_key_filepath:
        return run_cli_tool(
            logger,
            [
                'ssh',
                '-i', private_key_filepath,
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'StrictHostKeyChecking=no',
                '-o', f'ConnectTimeout={ssh_timeout}',
                '-l', 'root',
                guest_request.address,
                # To stay consistent, command is given as a list of strings, but we pass it down to SSH as one of its
                # parameters. Therefore joining it into a single string here, instead of bothering the caller.
                command_join(command)
            ]
        )


def copy_to_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    src: str,
    dst: str,
    *,
    key: SSHKey,
    ssh_timeout: int
) -> Result[CLIOutput, Failure]:
    if guest_request.address is None:
        return Error(Failure('cannot connect to unknown remote address'))

    with create_tempfile(file_contents=key.private) as private_key_filepath:
        return run_cli_tool(
            logger,
            [
                'scp',
                '-i', private_key_filepath,
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'StrictHostKeyChecking=no',
                '-o', f'ConnectTimeout={ssh_timeout}',
                src,
                f'root@{guest_request.address}:{dst}',
            ]
        )


def copy_from_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    src: str,
    dst: str,
    *,
    key: SSHKey,
    ssh_timeout: int
) -> Result[CLIOutput, Failure]:
    if guest_request.address is None:
        return Error(Failure('cannot connect to unknown remote address'))

    with create_tempfile(file_contents=key.private) as private_key_filepath:
        return run_cli_tool(
            logger,
            [
                'scp',
                '-i', private_key_filepath,
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'StrictHostKeyChecking=no',
                '-o', f'ConnectTimeout={ssh_timeout}',
                f'root@{guest_request.address}:{src}',
                dst
            ]
        )


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
