# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

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
from typing import Any, Callable, Dict, Generic, Iterable, Iterator, List, Optional, Pattern, Tuple, Type, TypeVar, \
    Union, cast

import gluetool
import gluetool.log
import gluetool.utils
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from pint import Quantity
from typing_extensions import Literal, Protocol, TypedDict

from .. import Failure, JSONType, SerializableContainer, log_dict_yaml, process_output_to_str, render_template, \
    safe_call
from ..cache import get_cached_set_as_list, get_cached_set_item, refresh_cached_set
from ..context import CACHE, LOGGER
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest, GuestTag, Pool, SafeQuery, \
    SnapshotRequest, SSHKey
from ..environment import UNITS, Environment, Flavor, FlavorBoot, FlavorDisk, FlavorDisks, MeasurableConstraintValueType
from ..knobs import KNOB_POOL_ENABLED, Knob
from ..metrics import PoolCostsMetrics, PoolMetrics, PoolResourcesMetrics, ResourceType
from ..script import hook_engine

T = TypeVar('T')


GuestTagsType = Dict[str, str]


# Types for configuration of custom/patched flavors
#
# NOTE: sometimes we cannot use class-based approach to TypedDict because some keys contain dashes.

#: pools[].parameters.{custom-flavors,patch-flavors}[].cpu
ConfigFlavorCPUSpecType = TypedDict(
    'ConfigFlavorCPUSpecType',
    {
        'family': Optional[int],
        'family-name': Optional[str],
        'model': Optional[int],
        'model-name': Optional[str]
    }
)


#: pools[].parameters.{custom-flavors,patch-flavors}[].disk (static disk)
class ConfigFlavorDiskSpecificSpecType(TypedDict):
    size: Optional[Union[int, str]]


#: pools[].parameters.{custom-flavors,patch-flavors}[].disk (expansion)
ConfigFlavorDiskExpansionSpecType = TypedDict(
    'ConfigFlavorDiskExpansionSpecType',
    {
        'max-count': int,
        'min-size': Optional[Union[int, str]],
        'max-size': Optional[Union[int, str]],
    }
)

ConfigFlavorDiskExpandedSpecType = TypedDict(
    'ConfigFlavorDiskExpandedSpecType',
    {
        'additional-disks': ConfigFlavorDiskExpansionSpecType
    }
)

ConfigFlavorDiskSpecType = Union[ConfigFlavorDiskSpecificSpecType, ConfigFlavorDiskExpandedSpecType]

#: pools[].parameters.{custom-flavors,patch-flavors}[].virtualization
ConfigFlavorVirtualizationSpecType = TypedDict(
    'ConfigFlavorVirtualizationSpecType',
    {
        'is-supported': Optional[bool],
        'is-virtualized': Optional[bool],
        'hypervisor': Optional[str]
    }
)


#: pools[].parameters.patch-flavors[]
ConfigPatchFlavorSpecType = TypedDict(
    'ConfigPatchFlavorSpecType',
    {
        'name': str,
        'name-regex': str,
        'arch': str,
        'cpu': ConfigFlavorCPUSpecType,
        'disk': List[ConfigFlavorDiskSpecType],
        'virtualization': ConfigFlavorVirtualizationSpecType
    }
)


#: pools[].parameters.custom-flavors[]
class ConfigCustomFlavorSpecType(TypedDict):
    name: str
    base: str
    arch: str
    cpu: ConfigFlavorCPUSpecType
    disk: List[ConfigFlavorDiskSpecType]
    virtualization: ConfigFlavorVirtualizationSpecType


ConfigFlavorSpecType = Union[ConfigPatchFlavorSpecType, ConfigCustomFlavorSpecType]


#: pools[].parameters.patch-images[].ssh
class ConfigImageSSHSpecType(TypedDict, total=False):
    username: str
    port: int


ConfigImageSpecType = TypedDict(
    'ConfigImageSpecType',
    {
        'name': str,
        'name-regex': str,
        'ssh': ConfigImageSSHSpecType
    }
)


#: pools[].capabilities.disable-guest-logs
ConfigCapabilitiesDisableGuestLogType = TypedDict(
    'ConfigCapabilitiesDisableGuestLogType',
    {
        'log-name': str,
        'content-type': str
    }
)


#: pools[].capabilities
ConfigCapabilitiesType = TypedDict(
    'ConfigCapabilitiesType',
    {
        'supported-architectures': Union[Literal['any'], List[str]],
        'supports-snapshots': Union[str, bool],
        'supports-spot-instances': Union[str, bool],
        'disable-guest-logs': List[ConfigCapabilitiesDisableGuestLogType]
    }
)


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

KNOB_UPDATE_GUEST_REQUEST_TICK: Knob[int] = Knob(
    'pool.update-guest-request-tick',
    'A delay, in seconds, between two calls of `update-guest-request` task checking provisioning progress.',
    # TODO: enable DB backing, but that will require more handling in drivers if fetching this value fails.
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_UPDATE_GUEST_REQUEST_TICK',
    cast_from_str=int,
    default=30
)

KNOB_LOGGING_CLI_OUTPUT: Knob[bool] = Knob(
    'logging.cli.commands',
    """
    When enabled, Artemis would log CLI commands.
    """,
    has_db=False,
    envvar='ARTEMIS_LOG_CLI_COMMANDS',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_CLI_COMMAND_PATTERN: Knob[str] = Knob(
    'logging.cli.command-pattern',
    'Log only commands matching the pattern.',
    has_db=False,
    envvar='ARTEMIS_LOG_CLI_COMMAND_PATTERN',
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


# Precompile the command pattern
try:
    CLI_COMMAND_PATTERN = re.compile(KNOB_LOGGING_CLI_COMMAND_PATTERN.value)

except Exception as exc:
    Failure.from_exc(
        'failed to compile ARTEMIS_LOG_CLI_COMMAND_PATTERN pattern',
        exc,
        pattern=KNOB_LOGGING_CLI_COMMAND_PATTERN.value
    ).handle(LOGGER.get())

    sys.exit(1)


if hasattr(shlex, 'join'):
    # We cannot use `type: ignore` comment here, because it applies to Python 3.7 only, where `shlex.join`
    # does not exist. In newer Python versions, is does and therefore the ignore hint is reported as unused.
    # And there is no way to disable *that* report :/ See https://github.com/python/mypy/issues/8823
    # Trying to work around this with a bit of `getattr()` - we *know* the attribute exists, and the types
    # are a match, we just need to fool mypy a bit.
    command_join = getattr(shlex, 'join')

else:
    def command_join(split_command: Iterable[str]) -> str:
        return ' '.join(shlex.quote(arg) for arg in split_command)


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
        super().__init__(logger, {
            'ctx_pool_name': (10, poolname)
        })

    @property
    def poolname(self) -> str:
        return cast(str, self._contexts['pool_name'][1])


class CLIErrorCauses(enum.Enum):
    """
    A base class for enums listing various error causes recognized by pools for their CLI tools.
    """

    pass


#: A type for callables extracting CLI error cause from process output.
CLIErrorCauseExtractor = Callable[
    [gluetool.utils.ProcessOutput],
    CLIErrorCauses
]


@dataclasses.dataclass(repr=False)
class PoolImageSSHInfo(SerializableContainer):
    username: str = 'root'
    port: int = 22


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

    arch: Optional[str]
    boot: FlavorBoot
    ssh: PoolImageSSHInfo

    def serialize_scrubbed(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON while scrubbing sensitive information.

        :returns: serialized form of flavor properties.
        """

        serialized = dataclasses.asdict(self)

        del serialized['id']

        return serialized


class FlavorKeyGetterType(Protocol):
    def __call__(
        self,
        flavor: Flavor
    ) -> Tuple[int, MeasurableConstraintValueType, Tuple[MeasurableConstraintValueType, ...]]:
        pass


def flavor_to_key(
    flavor: Flavor
) -> Tuple[int, MeasurableConstraintValueType, Tuple[MeasurableConstraintValueType, ...]]:
    # All are optional, meaning "don't care", and in this sorting it doesn't matter (possible?)
    # TODO: better algorithm would be better, one aware of optional values (first? last?)
    return (
        flavor.cpu.cores or 0,
        flavor.memory or 0,
        tuple(
            disk.size or 0
            for disk in flavor.disk
        )
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

    #: List of log name/log content type pairs describing that logs are supported by the driver.
    supported_guest_logs: List[Tuple[str, GuestLogContentType]] = dataclasses.field(default_factory=list)

    #: If set, the pool can find instances by their hostnames.
    supports_hostnames: bool = False

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

    def supports_guest_log(self, logname: str, contenttype: GuestLogContentType) -> bool:
        return (logname, contenttype) in self.supported_guest_logs


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
        return cls(**json.loads(guest_request.pool_data))


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

    #: If set, update guest request SSH info to match provided values.
    #: The field is used by drivers to express SSH parameters when known.
    ssh_info: Optional[PoolImageSSHInfo] = None

    #: If set, it represents a suggestion from the pool driver: it does not make much sense
    #: to run :py:meth:`PoolDriver.update_guest` sooner than this second in the future. If
    #: left unset, Artemis core will probably run the update as soon as possible.
    delay_update: Optional[int] = None

    #: If pool driver encountered errors that were not critical enough to be returned immediately, causing
    #: reschedule of the provisioning step, then to make them visible and logged, such failures should
    #: be stored in this list.
    pool_failures: List[Failure] = dataclasses.field(default_factory=list)


class WatchdogState(enum.Enum):
    """
    State of the guest watchdog.
    """

    CONTINUE = 'continue'
    COMPLETE = 'complete'


S = TypeVar('S', bound='PoolResourcesIDs')

SerializedPoolResourcesIDs = str

#: Used to serialize ``datetime`` instances that are part of ``PoolResourcesIDs``.
RESOURCE_CTIME_FMT: str = '%Y-%m-%dT%H:%M:%S.%f'


@dataclasses.dataclass
class PoolResourcesIDs(SerializableContainer):
    """
    Container for various pool resource IDs, used for scheduling their removal.

    Serves as a base class for pool-specific implementations that add the actual fields for resources and IDs.
    """

    ctime: Optional[datetime.datetime] = None

    def is_empty(self) -> bool:
        return all([value is None for key, value in dataclasses.asdict(self).items() if key != 'ctime'])

    def serialize(self) -> Dict[str, Any]:
        serialized = super().serialize()

        # Convert datetime object to string
        serialized['ctime'] = serialized['ctime'].strftime(RESOURCE_CTIME_FMT) if serialized['ctime'] else None

        return serialized

    @classmethod
    def unserialize(cls: Type[S], serialized: Dict[str, Any]) -> S:
        # Convert ctime string to datetime object
        serialized['ctime'] = datetime.datetime.strptime(serialized['ctime'], RESOURCE_CTIME_FMT) \
            if serialized['ctime'] else None

        return cls(**serialized)

    # Overwriting (un)serialize methods because we have a dedicated serialized type.
    def serialize_to_json(self) -> SerializedPoolResourcesIDs:
        return super().serialize_to_json()

    @classmethod
    def unserialize_from_json(cls: Type[S], serialized: SerializedPoolResourcesIDs) -> S:
        return super().unserialize_from_json(serialized)


def _parse_flavor_disk_size(
    field_name: str,
    value: Optional[Union[str, int]],
    disk: FlavorDisk
) -> Result[Optional[Quantity], Failure]:
    if value is None:
        return Ok(None)

    property_name = field_name.replace('-', '_')

    r_value = safe_call(UNITS, value)

    if r_value.is_error:
        return Error(Failure.from_failure(
            f'failed to parse flavor disk.{field_name}',
            r_value.unwrap_error(),
            details={
                property_name: value
            }
        ))

    raw_value = r_value.unwrap()

    if isinstance(raw_value, int):
        real_value = UNITS.Quantity(raw_value, UNITS.bytes)

    else:
        real_value = raw_value

    setattr(disk, property_name, real_value)

    return Ok(real_value)


def _apply_flavor_specification(
    flavor: Flavor,
    flavor_spec: ConfigFlavorSpecType
) -> Result[None, Failure]:
    """
    Apply a flavor specification - originating from the configuration - to a given flavor.

    This is a helper for building custom and patching existing flavors. Both kinds use the same configuration
    fields.
    """

    if 'arch' in flavor_spec:
        flavor.arch = flavor_spec['arch']

    if 'cpu' in flavor_spec:
        cpu_patch = flavor_spec['cpu']

        if 'family' in cpu_patch:
            flavor.cpu.family = cpu_patch['family']

        if 'family-name' in cpu_patch:
            flavor.cpu.family_name = cpu_patch['family-name']

        if 'model' in cpu_patch:
            flavor.cpu.model = cpu_patch['model']

        if 'model-name' in cpu_patch:
            flavor.cpu.model_name = cpu_patch['model-name']

    if 'disk' in flavor_spec:
        # TODO: introduce way how to actually patch the list of disks, instead of recreating it. It's easier,
        # but hardly future-proof.
        patched_disks: List[FlavorDisk] = []

        for disk_patch in flavor_spec['disk']:
            disk = FlavorDisk()
            patched_disks.append(disk)

            if 'additional-disks' not in disk_patch:
                specific_disk_patch = cast(ConfigFlavorDiskSpecificSpecType, disk_patch)

                r_size = _parse_flavor_disk_size(
                    'size',
                    specific_disk_patch.get('size'),
                    disk
                )

                if r_size.is_error:
                    return Error(r_size.unwrap_error())

            else:
                expansion_disk_patch = cast(ConfigFlavorDiskExpandedSpecType, disk_patch)['additional-disks']

                disk.is_expansion = True
                disk.max_additional_items = expansion_disk_patch['max-count']

                r_size = _parse_flavor_disk_size(
                    'min-size',
                    expansion_disk_patch['min-size'],
                    disk
                )

                if r_size.is_error:
                    return Error(r_size.unwrap_error())

                r_size = _parse_flavor_disk_size(
                    'max-size',
                    expansion_disk_patch['max-size'],
                    disk
                )

                if r_size.is_error:
                    return Error(r_size.unwrap_error())

        flavor.disk = FlavorDisks(patched_disks)

    if 'virtualization' in flavor_spec:
        virtualization_patch = flavor_spec['virtualization']

        if 'is-supported' in virtualization_patch:
            flavor.virtualization.is_supported = virtualization_patch['is-supported']

        if 'is-virtualized' in virtualization_patch:
            flavor.virtualization.is_virtualized = virtualization_patch['is-virtualized']

        if 'hypervisor' in virtualization_patch:
            flavor.virtualization.hypervisor = virtualization_patch['hypervisor']

    return Ok(None)


def _patch_flavors(
    logger: gluetool.log.ContextAdapter,
    flavors: Dict[str, Flavor],
    patches: List[ConfigPatchFlavorSpecType]
) -> Result[None, Failure]:
    """
    "Patch" existing flavors as specified by configuration.

    :param logger: logger to use for logging.
    :param flavors: a set of flavors to modify.
    :param patches: list of flavor patches.
    """

    if not patches:
        return Ok(None)

    log_dict_yaml(logger.debug, 'base flavors', flavors)

    for patch_spec in patches:
        if 'name' in patch_spec:
            flavorname = patch_spec['name']

            target_flavors = [flavors[flavorname]] if flavorname in flavors else []

        elif 'name-regex' in patch_spec:
            flavorname = patch_spec['name-regex']

            try:
                flavor_name_pattern = re.compile(flavorname)

            except re.error as exc:
                return Error(Failure.from_exc(
                    'failed to compile patched flavor name-regex',
                    exc,
                    flavorname=flavorname
                ))

            target_flavors = [
                flavor
                for flavor in flavors.values()
                if flavor_name_pattern.match(flavor.name) is not None
            ]

        else:
            # guarded by schema validation, we should always have `name` or `name-regex`
            assert False, 'unreachable'

        if not target_flavors:
            return Error(Failure(
                'unknown patched flavor',
                flavorname=flavorname
            ))

        for target_flavor in target_flavors:
            r_apply_spec = _apply_flavor_specification(target_flavor, patch_spec)

            if r_apply_spec.is_error:
                return Error(r_apply_spec.unwrap_error().update(
                    flavorname=flavorname,
                    target_flavorname=target_flavor.name
                ))

    return Ok(None)


def _custom_flavors(
    logger: gluetool.log.ContextAdapter,
    flavors: Dict[str, Flavor],
    patches: List[ConfigCustomFlavorSpecType]
) -> Result[List[Flavor], Failure]:
    """
    Create custom flavors based on existing ones.

    Custom flavors are clones of existing flavors, but with some of the original properties changed in the clone.

    :param logger: logger to use for logging.
    :param flavors: actual existing flavors that serve as basis for custom flavors.
    :param patches: list of flavor patches.
    """

    if not patches:
        return Ok([])

    custom_flavors = []

    log_dict_yaml(logger.debug, 'base flavors', flavors)

    for custom_flavor_spec in patches:
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

        r_apply_spec = _apply_flavor_specification(custom_flavor, custom_flavor_spec)

        if r_apply_spec.is_error:
            failure = r_apply_spec.unwrap_error()
            failure.update(
                customname=customname,
                basename=basename
            )

            return Error(failure)

    log_dict_yaml(logger.debug, 'custom flavors', custom_flavors)

    return Ok(custom_flavors)


def _apply_image_specification(
    image: PoolImageInfo,
    image_spec: ConfigImageSpecType
) -> Result[None, Failure]:
    """
    Apply an image specification - originating from the configuration - to a given image.

    This is a helper for building custom and patching existing images. Both kinds use the same configuration
    fields.
    """

    if 'ssh' in image_spec:
        ssh_patch = image_spec['ssh']

        if 'username' in ssh_patch:
            image.ssh.username = ssh_patch['username']

        if 'port' in ssh_patch:
            image.ssh.port = ssh_patch['port']

    return Ok(None)


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


#
# Mapping guest requests to images
#
_PoolImageInfoTypeVar = TypeVar('_PoolImageInfoTypeVar', bound='PoolImageInfo')
ImageInfoMapperOptionalResultType = Result[Optional[T], Failure]
ImageInfoMapperResultType = Result[T, Failure]


class ImageInfoMapper(Generic[_PoolImageInfoTypeVar]):
    """
    Base class for mappings between a guest request and image info.
    """

    def __init__(self, pool: 'PoolDriver') -> None:
        self.pool = pool

    def map_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> ImageInfoMapperOptionalResultType[_PoolImageInfoTypeVar]:
        """
        Map given guest request to an image.

        :returns: image info best fitting the given request. If no such image can be found, ``None`` is returned.
        """

        raise NotImplementedError()

    def map(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> ImageInfoMapperResultType[_PoolImageInfoTypeVar]:
        """
        Map given guest request to an image.

        :returns: image info best fitting the given request.
        """

        r_image = self.map_or_none(logger, guest_request)

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = cast(_PoolImageInfoTypeVar, r_image.unwrap())

        if image is None:
            return Error(Failure(
                'cannot map guest request to image',
                environment=guest_request.environment,
                recoverable=False
            ))

        return Ok(image)


class HookImageInfoMapper(ImageInfoMapper[_PoolImageInfoTypeVar]):
    """
    Mapper between a guest request and image info with the use of pool-specific hook script.
    """

    def __init__(self, pool: 'PoolDriver', hook_name: str) -> None:
        super().__init__(pool)

        self.hook_name = hook_name

    def map_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> ImageInfoMapperOptionalResultType[_PoolImageInfoTypeVar]:
        r_engine = hook_engine(self.hook_name)

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image = cast(
            Result[Optional[_PoolImageInfoTypeVar], Failure],
            engine.run_hook(
                self.hook_name,
                logger=logger,
                pool=self.pool,
                environment=guest_request.environment
            )
        )

        if r_image.is_error:
            r_image.unwrap_error().update(environment=guest_request.environment)

        return r_image


class GuestLogUpdaterType(Protocol):
    __name__: str

    def __call__(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        pass


def guest_log_updater(
    drivername: str,
    logname: str,
    contenttype: GuestLogContentType
) -> Callable[[GuestLogUpdaterType], GuestLogUpdaterType]:
    def wrapper(func: GuestLogUpdaterType) -> GuestLogUpdaterType:
        PoolDriver.guest_log_updaters[(drivername, logname, contenttype)] = func.__name__

        return func

    return wrapper


def render_tags(
    logger: gluetool.log.ContextAdapter,
    tags: GuestTagsType,
    vars: Dict[str, Any]
) -> Result[GuestTagsType, Failure]:
    for name, tag_template in tags.items():
        r_rendered = render_template(tag_template, **vars)

        if r_rendered.is_error:
            return Error(Failure.from_failure(
                'failed to render guest tags',
                r_rendered.unwrap_error(),
                tag_template=tag_template
            ))

        tags[name] = r_rendered.unwrap()

    return Ok(tags)


class PoolDriver(gluetool.log.LoggerMixin):
    drivername: str

    image_info_class: Type[PoolImageInfo] = PoolImageInfo
    flavor_info_class: Type[Flavor] = Flavor
    pool_data_class: Type[PoolData] = PoolData
    cli_error_cause_extractor: Optional[CLIErrorCauseExtractor] = None

    #: Template for a cache key holding pool image info.
    POOL_IMAGE_INFO_CACHE_KEY = 'pool.{}.image-info'

    #: Template for a cache key holding flavor image info.
    POOL_FLAVOR_INFO_CACHE_KEY = 'pool.{}.flavor-info'

    #: Hold all known guest log updaters, with key being driver name, log name and its content type.
    guest_log_updaters: Dict[Tuple[str, str, GuestLogContentType], str] = {}

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super().__init__(logger)

        self.poolname = poolname
        self.pool_config = pool_config

        self._pool_resources_metrics: Optional[PoolResourcesMetrics] = None
        self._pool_costs_metrics: Optional[PoolCostsMetrics] = None

        self.image_info_cache_key = self.POOL_IMAGE_INFO_CACHE_KEY.format(self.poolname)  # noqa: FS002
        self.flavor_info_cache_key = self.POOL_FLAVOR_INFO_CACHE_KEY.format(self.poolname)  # noqa: FS002

    _drivers_registry: Dict[str, Type['PoolDriver']] = {}

    @staticmethod
    def _instantiate(
        logger: gluetool.log.ContextAdapter,
        driver_name: str,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> Result['PoolDriver', Failure]:
        pool_driver_class = PoolDriver._drivers_registry.get(driver_name)

        if pool_driver_class is None:
            return Error(Failure('cannot find pool driver', drivername=driver_name))

        pool = pool_driver_class(logger, poolname, pool_config)

        r_sanity = pool.sanity()

        if r_sanity.is_error:
            return Error(r_sanity.unwrap_error())

        return Ok(pool)

    # Because sometimes we just don't know whether the given pool actually exists or not...
    @staticmethod
    def load_or_none(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> Result[Optional['PoolDriver'], Failure]:
        r_pool_record = SafeQuery.from_session(session, Pool) \
            .filter(Pool.poolname == poolname) \
            .one_or_none()

        if r_pool_record.is_error:
            return Error(r_pool_record.unwrap_error())

        pool_record = r_pool_record.unwrap()

        if pool_record is None:
            return Ok(None)

        r_pool = PoolDriver._instantiate(logger, pool_record.driver, poolname, pool_record.parameters)

        if r_pool.is_error:
            return Error(r_pool.unwrap_error())

        return Ok(r_pool.unwrap())

        # And when .map()/.map_error() become available, the code above would become much less spaghetti-ish...
        #
        # TODO: switch to when map/map_error become available
        #
        # def instantiate(pool_record: Optional[Pool]) -> Result[Optional['PoolDriver'], Failure]:
        #     if pool_record is None:
        #         return Ok(None)
        #
        #     # `_instantiate()`` return either a pool or failure, never `None`. That is nice, but it isn't matching
        #     # the expected return value of `load_or_none()`, therefore we need a cast.
        #     return cast(
        #         Result[Optional['PoolDriver'], Failure],
        #         PoolDriver._instantiate(pool_record.driver, logger, poolname, pool_record.parameters)
        #     )
        #
        # return SafeQuery.from_session(session, Pool) \
        #     .filter(Pool.poolname == poolname) \
        #     .one_or_none() \
        #     .map(instantiate)

    # ... and sometimes, we are pretty sure the pool does exist, and it's a hard error if we can't find it.
    @staticmethod
    def load(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> Result['PoolDriver', Failure]:
        r_pool = PoolDriver.load_or_none(logger, session, poolname)

        if r_pool.is_error:
            return Error(r_pool.unwrap_error())

        pool = r_pool.unwrap()

        if pool is None:
            return Error(Failure(
                'no such pool',
                poolname=poolname
            ))

        return Ok(pool)

        # TODO: switch to when map/map_error become available
        #
        # return PoolDriver.load_or_none(logger, session, poolname) \
        #     .map(lambda pool: Error(Failure('no such pool', poolname=poolname)) if pool is None else Ok(pool))

    @staticmethod
    def load_all(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        enabled_only: bool = True
    ) -> Result[List['PoolDriver'], Failure]:
        r_pools = SafeQuery.from_session(session, Pool).all()

        if r_pools.is_error:
            return Error(r_pools.unwrap_error())

        pools: List[PoolDriver] = []

        for pool_record in r_pools.unwrap():
            if enabled_only is True:
                r_enabled = KNOB_POOL_ENABLED.get_value(session=session, poolname=pool_record.poolname)

                if r_enabled.is_error:
                    return Error(r_enabled.unwrap_error())

                if r_enabled.unwrap() is not True:
                    continue

            r_pool = PoolDriver._instantiate(logger, pool_record.driver, pool_record.poolname, pool_record.parameters)

            if r_pool.is_error:
                return Error(r_pool.unwrap_error())

            pools.append(r_pool.unwrap())

        return Ok(pools)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: {self.poolname}>'

    @property
    def image_info_mapper(self) -> ImageInfoMapper[PoolImageInfo]:
        """
        Returns a guest request to image info mapper for this pool.
        """

        raise NotImplementedError()

    @property
    def use_only_when_addressed(self) -> bool:
        return self.pool_config.get('use-only-when-addressed', False)

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

    def dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        *resource_ids: PoolResourcesIDs,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        """
        Schedule removal of given resources. Resources are identified by keys and values which are passed
        to :py:meth:`release_pool_resource` method. The actual keys are completely under control of the
        driver.
        """

        if all(resource_id.is_empty() for resource_id in resource_ids):
            return Ok(None)

        r_delay = KNOB_DISPATCH_RESOURCE_CLEANUP_DELAY.get_value(pool=self)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        for resource_id in resource_ids:
            resource_id.ctime = guest_request.ctime if guest_request else None

        # Local import, to avoid circular imports
        from ..tasks import dispatch_sequence, release_pool_resources

        return dispatch_sequence(
            logger,
            [
                (
                    release_pool_resources,
                    (self.poolname, resource_id.serialize_to_json(), guest_request.guestname if guest_request else None)
                )
                for resource_id in resource_ids
            ],
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
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy the given environment.

        By default, the driver base class tries to run tests that are common for majority - if not all - of drivers:

        * make sure the requested architecture is supported by the driver.

        :param guest_request: guest_request to check.
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """

        r_capabilities = self.capabilities()

        if r_capabilities.is_error:
            return Error(r_capabilities.unwrap_error())

        capabilities = r_capabilities.unwrap()

        if not capabilities.supports_arch(guest_request.environment.hw.arch):
            return Ok(False)

        # Check whether given HW constraints do not go against what pool can deliver.
        #
        # There may be more checks implemented by the driver, but some conflicts we
        # can identify right away.
        if guest_request.environment.has_hw_constraints:
            r_constraints = guest_request.environment.get_hw_constraints()

            if r_constraints.is_error:
                return Error(r_constraints.unwrap_error())

            constraints = r_constraints.unwrap()

            assert constraints is not None

            # If request may depend on particular machine hostname to be available
            # (or not available), pool must support hostnames first.
            if not capabilities.supports_hostnames:
                r_uses_hostname = constraints.uses_constraint(logger, 'hostname')

                if r_uses_hostname.is_error:
                    return Error(r_uses_hostname.unwrap_error())

                if r_uses_hostname.unwrap() is True:
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

    # TODO: I dislike the naming scheme here very much...
    def _map_environment_to_flavor_info_by_cache_by_name_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        flavorname: str
    ) -> Result[Optional[Flavor], Failure]:
        """
        Find a flavor matching the given name.

        :returns: a flavor info or ``None`` if such a name does not exist.
        """

        r_flavor = get_cached_set_item(
            CACHE.get(),
            self.flavor_info_cache_key,
            flavorname,
            self.flavor_info_class
        )

        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        return r_flavor

    def _map_environment_to_flavor_info_by_cache_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        flavorname: str
    ) -> Result[Flavor, Failure]:
        """
        Find a flavor matching the given name.

        :returns: a flavor info.
        """

        r_flavor = self._map_environment_to_flavor_info_by_cache_by_name_or_none(logger, flavorname)

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

        flavors = r_flavors.unwrap()

        gluetool.log.log_dict(logger.debug, 'available flavors', flavors)

        # Extract HW constraints specified by the environment.
        r_constraints = environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()

        if constraints is None:
            return Ok(flavors)

        log_dict_yaml(logger.debug, 'constraint', constraints.serialize())

        # The actual filter: pick flavors that pass the test and match the requirements.
        suitable_flavors = []

        for flavor in flavors:
            r_suitable = constraints.eval_flavor(logger, flavor)

            if r_suitable.is_error:
                return Error(r_suitable.unwrap_error())

            if r_suitable.unwrap() is True:
                suitable_flavors.append(flavor)

        gluetool.log.log_dict(logger.debug, 'suitable flavors', suitable_flavors)

        if not suitable_flavors:
            return Ok([])

        # Sort suitable flavors, the "smaller" ones first. The less cores, memory and diskpace the flavor has,
        # the smaller it is in eyes of this ordering.
        sorted_suitable_flavors = sorted(suitable_flavors, key=sort_key_getter)

        gluetool.log.log_dict(logger.debug, 'sorted suitable flavors', sorted_suitable_flavors)

        gluetool.log.log_dict(logger.debug, 'environment', environment.serialize())
        log_dict_yaml(logger.debug, 'constraints', constraints.serialize())

        return Ok(sorted_suitable_flavors)

    def log_acquisition_attempt(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        flavor: Optional[Flavor] = None,
        image: Optional[PoolImageInfo] = None
    ) -> Result[None, Failure]:
        details: Any = {}
        scrubbed_details: Any = {}

        if flavor is not None:
            details['flavor'] = flavor.serialize()
            scrubbed_details['flavor'] = flavor.serialize_scrubbed()

        if image is not None:
            details['image'] = image.serialize()
            scrubbed_details['image'] = image.serialize_scrubbed()

        log_dict_yaml(logger.info, 'provisioning from', details)

        guest_request.log_event(
            logger,
            session,
            'acquisition-attempt',
            **scrubbed_details
        )

        return Ok(None)

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

    def guest_watchdog(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[WatchdogState, Failure]:
        """
        Perform any periodic tasks the driver might need to apply while the request is in use.

        :param logger: logger to use for logging.
        :param guest_request: guest request to provision for.
        """

        return Ok(WatchdogState.COMPLETE)

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

    def get_guest_log_updater(self, guest_log: GuestLog) -> Optional[GuestLogUpdaterType]:
        updater_name = self.guest_log_updaters.get((
            self.drivername,
            guest_log.logname,
            GuestLogContentType(guest_log.contenttype)
        ))

        if updater_name is None:
            return None

        return cast(GuestLogUpdaterType, getattr(self, updater_name, None))

    def update_guest_log(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Call driver-specific code to update a given guest log.

        Guest log updater can be any method accepting guest request and log objcts and decorated
        with :py:attr:`PoolDriver.guest_log_updater`:

        .. code-block:: python

           @PoolDriver.guest_log_updater('driver name', 'console', GuestLogContentType.BLOB)
           def _update_guest_log_console_blob(
               self,
               guest_request: GuestRequest,
               guest_log: GuestLog
           ) -> Result[GuestLogUpdateProgress, Failure]:
               ...
        """

        updater = self.get_guest_log_updater(guest_log)

        if updater is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.ERROR
            ))

        return updater(logger, guest_request, guest_log)

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        """
        Allows pool drivers to modify pool capabilities extracted from configuration.

        This method is for drivers to override, to provide driver-specific and update known capabilities
        to match what the driver can actually deliver.
        """

        return Ok(capabilities)

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        capabilities = PoolCapabilities()

        capabilities_config = cast(ConfigCapabilitiesType, self.pool_config.get('capabilities'))

        if not capabilities_config:
            return self.adjust_capabilities(capabilities)

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
                capabilities_config['supports-snapshots']
            )

        if 'supports-spot-instances' in capabilities_config:
            capabilities.supports_spot_instances = gluetool.utils.normalize_bool_option(
                capabilities_config['supports-spot-instances']
            )

        r_adjusted_capabilities = self.adjust_capabilities(capabilities)

        if r_adjusted_capabilities.is_error:
            return r_adjusted_capabilities

        capabilities = r_adjusted_capabilities.unwrap()

        if 'disable-guest-logs' in capabilities_config:
            for log_spec in capabilities_config['disable-guest-logs']:
                disabled_log = (log_spec['log-name'], GuestLogContentType(log_spec['content-type']))

                capabilities.supported_guest_logs = [
                    guest_log
                    for guest_log in capabilities.supported_guest_logs
                    if guest_log != disabled_log
                ]

        return Result.Ok(capabilities)

    def get_guest_tags(
        self,
        logger: gluetool.log.ContextAdapter,
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
            tags.update({
                key: value if value is not None else 'null'
                for key, value in (guest_request.user_data or {}).items()
            })

        tags['ArtemisGuestName'] = guest_request.guestname
        # TODO: drivers could accept a template for the name, to allow custom naming schemes
        tags['ArtemisGuestLabel'] = f'artemis-guest-{datetime.datetime.utcnow().strftime("%Y-%m-%d-%H-%M-%S")}'

        r_rendered_tags = render_tags(logger, tags, {
            'GUESTNAME': guest_request.guestname,
            'ENVIRONMENT': guest_request.environment
        })

        if r_rendered_tags.is_error:
            return Error(r_rendered_tags.unwrap_error())

        return Ok(r_rendered_tags.unwrap())

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

    def _fetch_patched_pool_image_info_from_config(
        self,
        logger: gluetool.log.ContextAdapter,
        images: Dict[str, PoolImageInfo]
    ) -> Result[None, Failure]:
        """
        "Patch" existing images as specified by configuration. Some information may not be available via API,
        therefore maintainers can use ``patch-images`` to modify images as needed.

        :param images: actual existing images.
        """

        patch_image_specs = cast(List[ConfigImageSpecType], self.pool_config.get('patch-images', []))

        if not patch_image_specs:
            return Ok(None)

        gluetool.log.log_dict(logger.debug, 'base images', images)

        for patch_image_spec in patch_image_specs:
            if 'name' in patch_image_spec:
                imagename = patch_image_spec['name']

                target_images = [images[imagename]] if imagename in images else []

            elif 'name-regex' in patch_image_spec:
                imagename = patch_image_spec['name-regex']

                try:
                    image_name_pattern = re.compile(imagename)

                except re.error as exc:
                    return Error(Failure.from_exc(
                        'failed to compile patched image name-regex',
                        exc,
                        imagename=imagename
                    ))

                target_images = [
                    image
                    for image in images.values()
                    if image_name_pattern.match(image.name) is not None
                ]

            else:
                assert False, 'unreachable'

            if not target_images:
                return Error(Failure(
                    'unknown patched image',
                    imagename=imagename
                ))

            for target_image in target_images:
                r_apply_spec = _apply_image_specification(target_image, patch_image_spec)

                if r_apply_spec.is_error:
                    return Error(r_apply_spec.unwrap_error().update(
                        imagename=imagename,
                        target_imagename=target_image.name
                    ))

        return Ok(None)

    def _fetch_pool_image_info_from_config(
        self,
        logger: gluetool.log.ContextAdapter,
        images: List[PoolImageInfo]
    ) -> Result[List[PoolImageInfo], Failure]:
        """
        "Fetch" image infos from the driver configuration. This includes both custom image and patch information.

        :param images: actual existing images that serve as basis for custom images.
        """

        image_map = {
            image.name: image
            for image in images
        }

        if 'patch-images' in self.pool_config:
            r_patched_images = self._fetch_patched_pool_image_info_from_config(
                logger,
                image_map
            )

            if r_patched_images.is_error:
                return Error(r_patched_images.unwrap_error())

        return Ok(list(image_map.values()))

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

        real_images = r_image_info.unwrap()

        r_config_images = self._fetch_pool_image_info_from_config(LOGGER.get(), real_images)

        if r_config_images.is_error:
            return Error(r_config_images.unwrap_error())

        all_images = real_images + r_config_images.unwrap()

        r_refresh = refresh_cached_set(
            CACHE.get(),
            self.image_info_cache_key,
            {
                ii.name: ii
                for ii in all_images
                if ii.name
            }
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        PoolMetrics(self.poolname).refresh_image_info_metrics(self.poolname, len(all_images))

        return Ok(None)

    def get_cached_pool_image_info(self, imagename: str) -> Result[Optional[PoolImageInfo], Failure]:
        """
        Retrieve pool image info for an image of a given name.
        """

        return get_cached_set_item(CACHE.get(), self.image_info_cache_key, imagename, self.image_info_class)

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

        return _custom_flavors(
            logger,
            flavors,
            cast(List[ConfigCustomFlavorSpecType], self.pool_config.get('custom-flavors', []))
        )

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

        return _patch_flavors(
            logger,
            flavors,
            cast(List[ConfigPatchFlavorSpecType], self.pool_config.get('patch-flavors', []))
        )

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

        all_flavors = real_flavors + r_config_flavors.unwrap()

        r_refresh = refresh_cached_set(
            CACHE.get(),
            self.flavor_info_cache_key,
            {
                fi.name: fi
                for fi in all_flavors
                if fi.name
            }
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        PoolMetrics(self.poolname).refresh_flavor_info_metrics(self.poolname, len(all_flavors))

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

        return get_cached_set_item(CACHE.get(), self.flavor_info_cache_key, flavorname, self.flavor_info_class)

    def get_cached_pool_image_infos(self) -> Result[List[PoolImageInfo], Failure]:
        """
        Retrieve pool image info for all known images.
        """

        return get_cached_set_as_list(CACHE.get(), self.image_info_cache_key, self.image_info_class)

    def get_cached_pool_flavor_infos(self) -> Result[List[Flavor], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return get_cached_set_as_list(CACHE.get(), self.flavor_info_cache_key, self.flavor_info_class)


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
    commandname: Optional[str] = None,
    cause_extractor: Optional[CLIErrorCauseExtractor] = None
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
                output.exit_code,
                command_time,
                cause=cause_extractor(output) if cause_extractor is not None else None
            )

        joined_command = command_join(command)

        # We are expected to log the command when either one of these conditions is true:
        #
        # * CLI logging is enabled, and command matches given pattern, or
        # * logging of *slow* commands is enabled, and the command matches given pattern *and* it took long enough.

        def _log() -> None:
            assert command_scrubber is not None

            Failure(
                'detected a slow CLI command',
                command_output=output,
                scrubbed_command=command_scrubber(command),
                poolname=poolname,
                commandname=commandname,
                time=command_time
            ).handle(logger, label='CLI output')

        if KNOB_LOGGING_CLI_OUTPUT.value \
           and CLI_COMMAND_PATTERN.match(joined_command):
            _log()
            return

        if KNOB_LOGGING_SLOW_CLI_COMMANDS.value \
           and SLOW_CLI_COMMAND_PATTERN.match(joined_command) \
           and command_time < KNOB_LOGGING_SLOW_CLI_COMMAND_THRESHOLD.value:
            _log()
            return

    try:
        output = gluetool.utils.Command(command, logger=logger).run(env=env)

    except gluetool.glue.GlueCommandError as exc:
        _log_command(exc.output)

        return Error(Failure.from_exc(
            'error running CLI command',
            exc,
            command_output=exc.output,
            scrubbed_command=command_scrubber(command),
            poolname=poolname,
            commandname=commandname
        ))

    else:
        _log_command(output)

    if output.stdout is None:
        if not allow_empty:
            return Error(Failure(
                'CLI did not emit any output',
                command_output=output,
                scrubbed_command=command_scrubber(command),
                poolname=poolname,
                commandname=commandname
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
                scrubbed_command=command_scrubber(command),
                poolname=poolname,
                commandname=commandname
            ))

        try:
            return Ok(CLIOutput(output, output_stdout, json=json.loads(output_stdout)))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to convert string to JSON',
                exc=exc,
                command_output=output,
                scrubbed_command=command_scrubber(command),
                poolname=poolname,
                commandname=commandname
            ))

    return Ok(CLIOutput(output, output_stdout))


def run_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    command: List[str],
    *,
    key: SSHKey,
    ssh_timeout: int,
    # for CLI calls metrics
    poolname: Optional[str] = None,
    commandname: Optional[str] = None,
    cause_extractor: Optional[CLIErrorCauseExtractor] = None
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
                '-l', guest_request.ssh_username,
                '-p', str(guest_request.ssh_port),
                guest_request.address,
                # To stay consistent, command is given as a list of strings, but we pass it down to SSH as one of its
                # parameters. Therefore joining it into a single string here, instead of bothering the caller.
                command_join(command)
            ],
            poolname=poolname,
            commandname=commandname,
            cause_extractor=cause_extractor
        )


def copy_to_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    src: str,
    dst: str,
    *,
    key: SSHKey,
    ssh_timeout: int,
    # for CLI calls metrics
    poolname: Optional[str] = None,
    commandname: Optional[str] = None,
    cause_extractor: Optional[CLIErrorCauseExtractor] = None
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
                '-P', str(guest_request.ssh_port),
                src,
                f'{guest_request.ssh_username}@{guest_request.address}:{dst}',
            ],
            poolname=poolname,
            commandname=commandname,
            cause_extractor=cause_extractor
        )


def copy_from_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    src: str,
    dst: str,
    *,
    key: SSHKey,
    ssh_timeout: int,
    # for CLI calls metrics
    poolname: Optional[str] = None,
    commandname: Optional[str] = None,
    cause_extractor: Optional[CLIErrorCauseExtractor] = None
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
                '-P', str(guest_request.ssh_port),
                f'{guest_request.ssh_username}@{guest_request.address}:{src}',
                dst
            ],
            poolname=poolname,
            commandname=commandname,
            cause_extractor=cause_extractor
        )


def ping_shell_remote(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    *,
    key: SSHKey,
    ssh_timeout: int,
    # for CLI calls metrics
    poolname: Optional[str] = None,
    commandname: Optional[str] = None,
    cause_extractor: Optional[CLIErrorCauseExtractor] = None
) -> Result[bool, Failure]:
    """
    Try to run a simple ``echo`` command on a given guest, and verify its output.

    :param logger: logger to use for logging.
    :param guest_request: guest requst to connect to.
    :param key: SSH key to use for authentication.
    :param ssh_timeout: SSH connection timeout, in seconds.
    """

    commandname = commandname or 'shell-ping'

    r_ssh = run_remote(
        logger,
        guest_request,
        ['bash', '-c', 'echo ping'],
        key=key,
        ssh_timeout=ssh_timeout,
        poolname=poolname,
        commandname=commandname,
        cause_extractor=cause_extractor
    )

    if r_ssh.is_error:
        return Error(r_ssh.unwrap_error())

    ssh_output = r_ssh.unwrap()

    if ssh_output.stdout.strip() != 'ping':
        return Error(Failure(
            'did not receive expected response',
            command_output=ssh_output.process_output
        ))

    return Ok(True)


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
