# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import base64
import dataclasses
import datetime
import ipaddress
import json
import operator
import os
import re
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterator,
    List,
    MutableSequence,
    Optional,
    Pattern,
    Tuple,
    Union,
    cast,
)

import gluetool.log
import gluetool.utils
import jq
import sqlalchemy.orm.session
from gluetool.log import ContextAdapter, log_dict
from gluetool.result import Error, Ok, Result
from gluetool.utils import normalize_bool_option
from jinja2 import Template
from typing_extensions import Literal, TypedDict

from .. import (
    Failure,
    JSONType,
    SerializableContainer,
    log_dict_yaml,
    logging_filter,
    process_output_to_str,
    render_template,
)
from ..cache import get_cached_mapping_item, get_cached_mapping_values
from ..context import CACHE
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..environment import (
    UNITS,
    Constraint,
    Flavor,
    FlavorBoot,
    FlavorBootMethodType,
    FlavorCpu,
    FlavorNetwork,
    FlavorNetworks,
    FlavorVirtualization,
    Operator,
    SizeType,
)
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from ..security_group_rules import SecurityGroupRule, SecurityGroupRules
from . import (
    KNOB_UPDATE_GUEST_REQUEST_TICK,
    CanAcquire,
    GuestLogUpdateProgress,
    GuestTagsType,
    HookImageInfoMapper,
    ImageInfoMapperResultType,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolErrorCauses,
    PoolImageInfo,
    PoolImageSSHInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
    WatchdogState,
    guest_log_updater,
    run_cli_tool,
)

#
# Custom typing types
#
InstanceOwnerType = Tuple[Dict[str, Any], str]

# EBS volume types.
#
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html
#
# Note: not using enum which would wrap the values with a Python class - these are being passed directly
# in and out of AWS EC2 API, therefore sticking with plain strings.
EBSVolumeTypeType = Literal['gp2', 'gp3', 'io1', 'io2', 'sc1', 'st1', 'standard']


# Type of container holding EBS properties of a block device mapping.
#
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-template.html
class APIBlockDeviceMappingEbsType(TypedDict, total=False):
    DeleteOnTermination: bool
    Encrypted: bool
    Iops: int
    KmsKeyId: str
    SnapshotId: str
    VolumeSize: int
    VolumeType: EBSVolumeTypeType


# Type of container holding block device mapping.
#
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-mapping.html
class APIBlockDeviceMappingType(TypedDict, total=True):
    DeviceName: str
    Ebs: APIBlockDeviceMappingEbsType


# Type of container holding processor info of an instance type
#
# https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-types.html
# https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ProcessorInfo.html
class APIInstanceTypeProcessorInfo(TypedDict):
    SupportedArchitectures: List[str]
    SustainedClockSpeedInGhz: float


DEFAULT_VOLUME_DELETE_ON_TERMINATION = True
DEFAULT_VOLUME_ENCRYPTED = False
DEFAULT_VOLUME_TYPE: EBSVolumeTypeType = 'gp3'


# Type of container holding block device mappings.
#
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html
APIBlockDeviceMappingsType = List[APIBlockDeviceMappingType]


#: Device names allowed or recommended by AWS EC2.
#:
#: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html#available-ec2-device-names
EBS_DEVICE_NAMES = [
    f'/dev/sd{letter}'
    for letter in 'fghijklmnop'
]


# Type of container holding network interface info.
class APINetworkInterfaceType(TypedDict, total=True):
    DeviceIndex: int
    SubnetId: str
    DeleteOnTermination: bool
    Groups: List[str]
    AssociatePublicIpAddress: bool


APINetworkInterfacesType = List[APINetworkInterfaceType]


class APINetworkInfo(TypedDict, total=False):
    MaximumNetworkInterfaces: int
    MaximumNetworkCards: int
    DefaultNetworkCardIndex: int


class APIImageType(TypedDict):
    Name: Optional[str]
    ImageId: str
    Architecture: str
    PlatformDetails: str
    BlockDeviceMappings: APIBlockDeviceMappingsType
    EnaSupport: Optional[bool]
    CreationDate: str


ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'name-wildcard': str,
        'name-regex': str,
        'creation-date-regex': str,
        'owner': str,
        'max-age': int
    },
    total=False
)


AWS_VM_HYPERVISORS = ('nitro', 'xen')


class AWSErrorCauses(PoolErrorCauses):
    NONE = 'none'
    RESOURCE_METRICS_REFRESH_FAILED = 'resource-metrics-refresh-failed'
    FLAVOR_INFO_REFRESH_FAILED = 'flavor-info-refresh-failed'
    IMAGE_INFO_REFRESH_FAILED = 'image-info-refresh-failed'
    MISSING_INSTANCE = 'missing-instance'
    MISSING_SPOT_INSTANCE_REQUEST = 'missing-spot-instance-request'
    REQUEST_LIMIT_EXCEEDED = 'request-limit-exceeded'
    SPOT_PRICE_NOT_DETECTED = 'spot-price-not-detected'
    INSTANCE_BUILDING_TOO_LONG = 'instance-building-too-long'
    INSTANCE_TERMINATED_PREMATURELY = 'instance-terminated-prematurely'
    SPOT_INSTANCE_TERMINATED_PREMATURELY = 'spot-instance-terminated-prematurely'
    SPOT_INSTANCE_TERMINATED_NO_CAPACITY = 'spot-instance-terminated-no-capacity'
    SPOT_INSTANCE_TERMINATED_UNEXPECTEDLY = 'spot-instance-terminated-unexpectedly'


CLI_ERROR_PATTERNS = {
    AWSErrorCauses.MISSING_INSTANCE: re.compile(
        r'.+\(InvalidInstanceID\.NotFound\).+The instance ID \'.+\' does not exist'
    ),
    AWSErrorCauses.MISSING_SPOT_INSTANCE_REQUEST: re.compile(
        r'.+\(InvalidSpotInstanceRequestID\.NotFound\).+The spot instance request ID \'.+\' does not exist'
    ),
    AWSErrorCauses.REQUEST_LIMIT_EXCEEDED: re.compile(
        r'.+\(RequestLimitExceeded\).+Request limit exceeded'
    )
}


def awscli_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> AWSErrorCauses:
    if output.exit_code == 0:
        return AWSErrorCauses.NONE

    stderr = process_output_to_str(output, stream='stderr')
    stderr = stderr.strip() if stderr is not None else None

    if stderr is None:
        return AWSErrorCauses.NONE

    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if not pattern.match(stderr):
            continue

        return cause

    return AWSErrorCauses.NONE


AWS_INSTANCE_SPECIFICATION = Template("""
{
  "ImageId": "{{ ami_id }}",
  "KeyName": "{{ key_name }}",
  "InstanceType": "{{ instance_type.id }}",
  "Placement": {
    "AvailabilityZone": "{{ availability_zone }}"
  },
  {% if network_interfaces -%}
  "NetworkInterfaces": {{ network_interfaces | to_json }},
  {% endif -%}
  {% if block_device_mappings -%}
  "BlockDeviceMappings": {{ block_device_mappings | to_json }},
  {% endif -%}
  "UserData": "{{ user_data }}"
}
""")


#: Flatten the output of ``describe-instances`` to a simple list of instances.
JQ_QUERY_POOL_INSTANCES = jq.compile('.Reservations | .[] | .Instances | .[]')

#: Extract CIDR block of a subnet, as available from ``describe-subnets``.
JQ_QUERY_SUBNET_CIDR = jq.compile('.Subnets | .[] | .CidrBlock')

#: Extract number of available IPs of a subnet, as available from ``describe-subnets``.
JQ_QUERY_SUBNET_AVAILABLE_IPS = jq.compile('.Subnets | .[] | .AvailableIpAddressCount')

#: Extract console output from ``get-console-output`` output.
JQ_QUERY_CONSOLE_OUTPUT = jq.compile('.Output')

#: Extract IDs of EBS volumes attached to instance, as available from ``describe-instances``.
#: Note the missing leading `.Reservations | ...` - this query is applied to one instance
#: only, after its description has been acquired from API.
JQ_QUERY_EBS_VOLUME_IDS = jq.compile('.BlockDeviceMappings | .[] | .Ebs.VolumeId')

#: Extract supported boot modes of an instance type, as available from ``describe-instance-types``.
JQ_QUERY_FLAVOR_SUPPORTED_BOOT_MODES = jq.compile('.SupportedBootModes | .[]')
#: Extract supported boot mode of an instance, as available from ``describe-images``.
JQ_QUERY_IMAGE_SUPPORTED_BOOT_MODE = jq.compile('.BootMode')

JQ_QUERY_SECURITY_GROUP_IDS = jq.compile('.SecurityGroups | .[] | .GroupId')


KNOB_SPOT_OPEN_TIMEOUT: Knob[int] = Knob(
    'aws.spot-open-timeout',
    """
    How long, in seconds, is an spot instance request allowed to stay in `open` state
    until cancelled and reprovisioned.
    """,
    has_db=False,
    envvar='ARTEMIS_AWS_SPOT_OPEN_TIMEOUT',
    cast_from_str=int,
    default=60
)

KNOB_PENDING_TIMEOUT: Knob[int] = Knob(
    'aws.pending-timeout',
    'How long, in seconds, is an instance allowed to stay in `pending` state until cancelled and reprovisioned.',
    has_db=False,
    envvar='ARTEMIS_AWS_PENDING_TIMEOUT',
    cast_from_str=int,
    default=600
)

KNOB_CONSOLE_DUMP_BLOB_UPDATE_TICK: Knob[int] = Knob(
    'aws.logs.console.dump.blob.update-tick',
    'How long, in seconds, to take between updating guest console log.',
    has_db=False,
    envvar='ARTEMIS_AWS_LOGS_CONSOLE_LATEST_BLOB_UPDATE_TICK',
    cast_from_str=int,
    default=300
)

KNOB_CONSOLE_INTERACTIVE_URL: Knob[str] = Knob(
    'aws.logs.console.interactive.url',
    'Templated URL of serial console of an AWS EC2 instance.',
    has_db=False,
    envvar='ARTEMIS_AWS_LOGS_CONSOLE_INTERACTIVE_URL',
    cast_from_str=str,
    default="https://console.aws.amazon.com/ec2/v2/connect/ec2-user/{instance_id}?connection-type=isc&serial-port=0"  # noqa: FS003,E501
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'aws.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AWS_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-aws.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'aws.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AWS_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

KNOB_GUEST_SECURITY_GROUP_NAME_TEMPLATE: Knob[str] = Knob(
    'aws.mapping.guest-security-group-name.template',
    'A pattern for guest security group name.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AWS_GUEST_SECURITY_GROUP_NAME_TEMPLATE',
    cast_from_str=str,
    default='artemis-guest-{{ GUESTNAME }}'
)

KNOB_REMOVE_SECURITY_GROUP_DELAY: Knob[int] = Knob(
    'aws.remove-security-group.delay',
    """
    A delay, in seconds, between scheduling the guest security group clean up
    task in aws and actual attempt to clean up the resource.
    """,
    has_db=False,
    envvar='ARTEMIS_AWS_REMOVE_SECURITY_GROUP_DELAY',
    cast_from_str=int,
    default=150
)


class FailedSpotRequest(Failure):
    def __init__(
        self,
        message: str,
        spot_instance_id: str,
        **kwargs: Any
    ):
        super().__init__(message, **kwargs)
        self.spot_instance_id = spot_instance_id


@dataclasses.dataclass
class AWSPoolData(PoolData):
    instance_id: Optional[str] = None
    spot_instance_id: Optional[str] = None
    security_group: Optional[str] = None


@dataclasses.dataclass(repr=False)
class AWSPoolImageInfo(PoolImageInfo):
    #: Carries ``PlatformDetails`` field as provided by AWS image description.
    platform_details: str

    #: Carries ``BlockDeviceMappings`` field as provided by AWS image description.
    block_device_mappings: APIBlockDeviceMappingsType

    #: Carries `EnaSupport` field as provided by AWS image description.
    ena_support: bool

    #: Carries original `BootMode` image field.
    boot_mode: Optional[str]

    def serialize_scrubbed(self) -> Dict[str, Any]:
        serialized = super().serialize_scrubbed()

        for bd_mapping in serialized['block_device_mappings']:
            if 'Ebs' in bd_mapping and 'SnapshotId' in bd_mapping['Ebs']:
                del bd_mapping['Ebs']['SnapshotId']

        return serialized


@dataclasses.dataclass(repr=False)
class AWSFlavor(Flavor):
    # TODO: when Flavor gains `network` object, move this there.
    ena_support: Literal['required', 'supported', 'unsupported'] = 'unsupported'


@dataclasses.dataclass
class AWSPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    spot_instance_id: Optional[str] = None
    security_group: Optional[str] = None


class AWSHookImageInfoMapper(HookImageInfoMapper[AWSPoolImageInfo]):
    def map_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> ImageInfoMapperResultType[AWSPoolImageInfo]:
        r_images = super().map_or_none(logger, guest_request)

        if r_images.is_error:
            return r_images

        images = r_images.unwrap()

        # console/URL logs require ENA support
        if guest_request.requests_guest_log('console:interactive', GuestLogContentType.URL):
            images = list(logging_filter(
                logger,
                images,
                'console.interactive requires image ENA support',
                lambda logger, image: image.ena_support
            ))

        return Ok(images)


def _base64_encode(data: str) -> str:
    """
    Encode a given string into Base64.

    Since standard library's :py:mod:`base64` works with bytes, we need to encode and decode
    the given string properly, therefore a helper to save us from errors by repetition.
    """

    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def is_old_enough(logger: gluetool.log.ContextAdapter, timestamp: str, threshold: int) -> bool:
    try:
        parsed_timestamp = datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')

    except Exception as exc:
        Failure.from_exc(
            'failed to parse timestamp',
            exc,
            timestamp=timestamp
        ).handle(logger)

        return False

    diff = datetime.datetime.utcnow() - parsed_timestamp

    return diff.total_seconds() >= threshold


class BlockDeviceMappings(SerializableContainer, MutableSequence[APIBlockDeviceMappingType]):
    """
    This wrapper over AWS EC2 API block device mappings. Its main purpose is to
    host helper methods we use for modifications of mappings.
    """

    def __init__(self, mappings: Optional[List[APIBlockDeviceMappingType]] = None):
        super().__init__()

        self.data = mappings[:] if mappings else []

    # Abstract methods we need to define to keep types happy, since MutableSequence leaves them to us.
    def __delitem__(self, index: int) -> None:  # type: ignore[override]  # does not match supertype, but it's correct
        del self.data[index]

    def __getitem__(  # type: ignore[override]  # does not match supertype, but it's correct
        self,
        index: int
    ) -> APIBlockDeviceMappingType:
        return self.data[index]

    def __len__(self) -> int:
        return len(self.data)

    def __setitem__(  # type: ignore[override]  # does not match supertype, but it's correct
        self,
        index: int,
        value: APIBlockDeviceMappingType
    ) -> None:
        self.data[index] = value

    def insert(self, index: int, value: APIBlockDeviceMappingType) -> None:
        self[index] = value

    # Override serialization - we're fine with quite a trivial approach.
    def serialize(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self.data)

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'BlockDeviceMappings':
        cast_serialized = cast(APIBlockDeviceMappingsType, serialized)

        return BlockDeviceMappings(cast_serialized)

    @staticmethod
    def mapping_size(mapping: APIBlockDeviceMappingType) -> Optional[SizeType]:
        size = mapping.get('Ebs', {}).get('VolumeSize', None)

        if size is None:
            return None

        return UNITS.Quantity(size, UNITS.gibibytes)

    # These two methods would deserve their own class, representing a single block device mapping, but, because
    # such mapping isn't plain str/str dictionary, we would have to write so many checks and types to deal with
    # the variants. It's more readable to have them here, namespaced, rather than top-level functions.
    @staticmethod
    def create_mapping(
        device_name: str,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[SizeType] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Create block device mapping.

        All parameters except ``device_name`` are optional, and when not specified, their value in the device mapping
        will remain unset.

        :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
            If left unset, the setting would not be set for the new mapping.
        :param encrypted: whether or not the volume should be encrypted.
            If left unset, the setting would not be set for the new mapping.
        :param size: desired size of the volume.
            If left unset, the setting would not be set for the new mapping.
        :param volume_type: desired volume type.
            If left unset, the setting would not be set for the new mapping.
        :returns: newly created mapping.
        """

        mapping: APIBlockDeviceMappingType = {
            'DeviceName': device_name,
            'Ebs': {}
        }

        return BlockDeviceMappings.update_mapping(
            mapping,
            delete_on_termination=delete_on_termination,
            encrypted=encrypted,
            size=size,
            volume_type=volume_type
        )

    @staticmethod
    def update_mapping(
        mapping: APIBlockDeviceMappingType,
        device_name: Optional[str] = None,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[SizeType] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Update given block device mapping.

        All parameters are optional, and when not specified, the value currently set in the block device mapping
        will remain unchanged.

        :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
            If left unset, the existing setting would not be modified.
        :param encrypted: whether or not the volume should be encrypted.
            If left unset, the existing setting would not be modified.
        :param size: desired size of the volume.
            If left unset, the existing setting would not be modified.
        :param volume_type: desired volume type.
            If left unset, the existing setting would not be modified.
        :returns: updated mapping.
        """

        if device_name is not None:
            mapping['DeviceName'] = device_name

        if delete_on_termination is not None:
            mapping['Ebs']['DeleteOnTermination'] = delete_on_termination

        if encrypted is not None:
            mapping['Ebs']['Encrypted'] = encrypted

        if size is not None:
            mapping['Ebs']['VolumeSize'] = int(size.to('GiB').magnitude)

        if volume_type is not None:
            mapping['Ebs']['VolumeType'] = volume_type

        return Ok(mapping)

    def _get_mapping(
        self,
        index: int
    ) -> Optional[APIBlockDeviceMappingType]:
        """
        Return block device mapping with a given index if it exists.

        :returns: block device mapping on the given index in the list of block device mappings,
            or ``None`` if the position is undefined.
        """

        try:
            return self.data[index]

        except IndexError:
            return None

    def find_free_device_name(self) -> Result[str, Failure]:
        """
        Find a first free device name, a name not used by any mapping so far.
        """

        used_names = [mapping['DeviceName'] for mapping in self.data if 'DeviceName' in mapping]

        for name in EBS_DEVICE_NAMES:
            if name in used_names:
                continue

            return Ok(name)

        return Error(Failure('cannot find any free EBS device name'))

    def enlarge(
        self,
        count: int,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[SizeType] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[None, Failure]:
        """
        Make sure mappings contain at least ``count`` items.

        :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
            If left unset, the setting would not be set for the new mappings.
        :param encrypted: whether or not the volume should be encrypted.
            If left unset, the setting would not be set for the new mappings.
        :param size: desired size of the volume.
            If left unset, the setting would not be set for the new mappings.
        :param volume_type: desired volume type.
            If left unset, the setting would not be set for the new mappings.
        """

        current_count = len(self)

        if current_count >= count:
            return Ok(None)

        for _ in range(count - current_count):
            r_name = self.find_free_device_name()

            if r_name.is_error:
                return Error(r_name.unwrap_error())

            r_append = self.append_mapping(
                r_name.unwrap(),
                delete_on_termination=delete_on_termination,
                encrypted=encrypted,
                size=size,
                volume_type=volume_type
            )

            if r_append.is_error:
                return Error(r_append.unwrap_error())

        return Ok(None)

    def append_mapping(
        self,
        device_name: str,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[SizeType] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Append new block device mapping.

        All parameters except ``device_name`` are optional, and when not specified, their value in the device mapping
        will remain unset.

        :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
            If left unset, the setting would not be set for the new mapping.
        :param encrypted: whether or not the volume should be encrypted.
            If left unset, the setting would not be set for the new mapping.
        :param size: desired size of the volume.
            If left unset, the setting would not be set for the new mapping.
        :param volume_type: desired volume type.
            If left unset, the setting would not be set for the new mapping.
        :returns: newly created mapping.
        """

        r_create = BlockDeviceMappings.create_mapping(
            device_name,
            delete_on_termination=delete_on_termination,
            encrypted=encrypted,
            size=size,
            volume_type=volume_type
        )

        if r_create.is_ok:
            self.data.append(r_create.unwrap())

        return r_create

    def update_root_volume(
        self,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[SizeType] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
            If left unset, the existing setting would not be modified.
        :param encrypted: whether or not the volume should be encrypted.
            If left unset, the existing setting would not be modified.
        :param size: desired size of the volume.
            If left unset, the existing setting would not be modified.
        :param volume_type: desired volume type.
            If left unset, the existing setting would not be modified.
        """

        mapping = self._get_mapping(0)

        if mapping is None:
            return Error(Failure(
                'block device mapping does not exist',
                block_device_mappings=self.data,
                block_device_mapping_index=0
            ))

        return self.update_mapping(
            mapping,
            delete_on_termination=delete_on_termination,
            encrypted=encrypted,
            size=size,
            volume_type=volume_type
        )


def _honor_constraint_disk(
    logger: ContextAdapter,
    constraint: Constraint,
    mappings: BlockDeviceMappings,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
) -> Result[bool, Failure]:
    logger.debug(f'honor-constraint-disk: {constraint}')

    property_name, index, child_property_name, _ = constraint.expand_name()

    if child_property_name == 'size':
        log_dict_yaml(logger.debug, '  mappings before', mappings.serialize())

        assert index is not None

        r_enlarge = mappings.enlarge(
            index + 1,
            delete_on_termination=DEFAULT_VOLUME_DELETE_ON_TERMINATION,
            encrypted=DEFAULT_VOLUME_ENCRYPTED,
            volume_type=DEFAULT_VOLUME_TYPE
        )

        if r_enlarge.is_error:
            return Error(r_enlarge.unwrap_error())

        mapping = mappings[index]

        current_size = mappings.mapping_size(mapping)
        desired_size = cast(SizeType, constraint.value)

        def _check_and_set(
            op: Callable[[float, float], bool],
            actual_desired_size: SizeType
        ) -> Result[bool, Failure]:
            # Either the current size is undefined, or it does not pass the test. In such cases, force the desired size.
            if current_size is None or not op(current_size.to('GiB').magnitude, desired_size.to('GiB').magnitude):
                r_update = mappings.update_mapping(
                    mapping,
                    size=actual_desired_size
                )

                if r_update.is_error:
                    return Error(r_update.unwrap_error())

            # At this point, the size has been either already fine, or it's forced to be.
            return Ok(True)

        if constraint.operator is Operator.EQ:
            r_update = _check_and_set(operator.eq, desired_size)

        elif constraint.operator is Operator.GTE:
            r_update = _check_and_set(operator.ge, desired_size)

        elif constraint.operator is Operator.LTE:
            r_update = _check_and_set(operator.le, desired_size)

        elif constraint.operator is Operator.GT:
            r_update = _check_and_set(
                operator.gt,
                UNITS.Quantity(desired_size.to('GiB').magnitude + 1, UNITS.gibibytes)
            )

        elif constraint.operator is Operator.LT:
            r_update = _check_and_set(
                operator.lt,
                UNITS.Quantity(desired_size.to('GiB').magnitude - 1, UNITS.gibibytes)
            )

        else:
            return Error(Failure('cannot honor disk.size constraint', constraint=repr(constraint)))

        if r_update.is_error:
            Error(Failure.from_failure(
                'cannot honor disk.size constraint',
                r_update.unwrap_error(),
                constraint=repr(constraint)
            ))

        log_dict_yaml(logger.debug, '  mappings after', mappings.serialize())

        return Ok(True)

    return Ok(False)


def _get_constraint_spans(
    logger: ContextAdapter,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor
) -> Result[List[List[Constraint]], Failure]:
    if not guest_request.environment.has_hw_constraints:
        return Ok([])

    r_constraints = guest_request.environment.get_hw_constraints()

    if r_constraints.is_error:
        return Error(r_constraints.unwrap_error())

    constraints = r_constraints.unwrap()

    logger.debug(f'constraints: {constraints}')

    assert constraints is not None

    r_pruned_constraints = constraints.prune_on_flavor(logger, flavor)

    if r_pruned_constraints.is_error:
        return Error(r_pruned_constraints.unwrap_error())

    pruned_constraints = r_pruned_constraints.unwrap()

    logger.debug(f'pruned constraints: {pruned_constraints}')

    if pruned_constraints is None:
        return Ok([])

    spans = list(pruned_constraints.spans(logger))

    for i, span in enumerate(spans):
        log_dict_yaml(logger.debug, f'span #{i}', [str(constraint) for constraint in span])

    return Ok(spans)


def _get_constraint_span(
    logger: ContextAdapter,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor
) -> Result[List[Constraint], Failure]:
    r_spans = _get_constraint_spans(logger, guest_request, image, flavor)

    if r_spans.is_error:
        return Error(r_spans.unwrap_error())

    spans = r_spans.unwrap()

    if not spans:
        return Ok([])

    # TODO: this could be a nice algorithm, picking the best span instead of the first one.
    span = spans[0]

    log_dict_yaml(logger.debug, 'selected span', [str(constraint) for constraint in span])

    return Ok(span)


def setup_extra_volumes(
    logger: ContextAdapter,
    mappings: BlockDeviceMappings,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor
) -> Result[BlockDeviceMappings, Failure]:
    """
    Setup additional volumes, if required by HW constraints.

    :param logger: logger to use for logging.
    :param mappings: mappings to update.
    :param guest_request: a request the mappings belong to.
    :param image: an image that would be used to spin up the provisioned instance.
    :param flavor: a flavor that would serve as a basis for the provisioned instance.
    """

    r_span = _get_constraint_span(logger, guest_request, image, flavor)

    if r_span.is_error:
        return Error(r_span.unwrap_error())

    span = r_span.unwrap()

    if not span:
        return Ok(mappings)

    for constraint in span:
        logger.debug(f'  {constraint}')

        property_name, _, _, _ = (constraint.original_constraint or constraint).expand_name()

        if property_name != 'disk':
            logger.debug('    ignored')
            continue

        r_consumed = _honor_constraint_disk(
            logger,
            constraint.original_constraint or constraint,
            mappings,
            guest_request,
            image,
            flavor
        )

        if r_consumed.is_error:
            return Error(r_consumed.unwrap_error())

        if r_consumed.unwrap() is True:
            continue

        return Error(Failure(
            'cannot honor disk constraint',
            constraint=repr(constraint)
        ))

    return Ok(mappings)


def setup_root_volume(
    logger: ContextAdapter,
    mappings: BlockDeviceMappings,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
    default_root_disk_size: Optional[SizeType] = None,
    # common volume properties
    delete_on_termination: Optional[bool] = None,
    encrypted: Optional[bool] = None,
    size: Optional[SizeType] = None,
    volume_type: Optional[EBSVolumeTypeType] = None
) -> Result[BlockDeviceMappings, Failure]:
    """
    Setup a root disk of given set of mappings.

    :param logger: logger to use for logging.
    :param mappings: mappings to update.
    :param guest_request: a request the mappings belong to.
    :param image: an image that would be used to spin up the provisioned instance.
    :param flavor: a flavor that would serve as a basis for the provisioned instance.
    :param default_root_disk_size: a default root disk size, if known. It would be used unless there's a better
        value.
    :param delete_on_termination: whether or not the volume should be removed automatically with the instance.
        If left unset, the existing setting would not be modified.
    :param encrypted: whether or not the volume should be encrypted.
        If left unset, the existing setting would not be modified.
    :param size: desired size of the volume.
        If left unset, the existing setting would not be modified.
    :param volume_type: desired volume type.
        If left unset, the existing setting would not be modified.
    """

    if size is None:
        if flavor.disk and flavor.disk[0].size is not None:
            size = flavor.disk[0].size

        elif default_root_disk_size is not None:
            size = default_root_disk_size

    r_bdms = mappings.update_root_volume(
        delete_on_termination=delete_on_termination,
        encrypted=encrypted,
        size=size,
        volume_type=volume_type
    )

    if r_bdms.is_error:
        return Error(r_bdms.unwrap_error())

    return Ok(mappings)


def create_block_device_mappings(
    logger: ContextAdapter,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
    default_root_disk_size: Optional[SizeType] = None
) -> Result[BlockDeviceMappings, Failure]:
    """
    Prepare block device mapping according to match requested environment, image and flavor.

    .. note::

        If the flavor does not specify a desired disk space, then fall back to ``default-root-disk-size``
        configuration option. This will serve us until all flavors get their disk space.

    :param image: image that will be used to create the instance. It serves as a source of block device
        mapping data.
    :param flavor: flavor providing the disk space information.
    """

    mappings = BlockDeviceMappings(image.block_device_mappings)

    r_mappings = setup_root_volume(
        logger,
        mappings,
        guest_request,
        image,
        flavor,
        default_root_disk_size=default_root_disk_size
    )

    if r_mappings.is_error:
        return r_mappings

    mappings = r_mappings.unwrap()

    r_mappings = setup_extra_volumes(
        logger,
        mappings,
        guest_request,
        image,
        flavor,
    )

    if r_mappings.is_error:
        return r_mappings

    return Ok(r_mappings.unwrap())


class NetworkInterfaces(SerializableContainer, MutableSequence[APINetworkInterfaceType]):
    """
    This wrapper over AWS EC2 API network interfaces. Its main purpose is to
    host helper methods we use for modifications of network interface list.
    """

    def __init__(self, interfaces: Optional[List[APINetworkInterfaceType]] = None):
        super().__init__()

        self.data = interfaces[:] if interfaces else []

    # Abstract methods we need to define to keep types happy, since MutableSequence leaves them to us.
    def __delitem__(self, index: int) -> None:  # type: ignore[override]  # does not match supertype, but it's correct
        del self.data[index]

    def __getitem__(  # type: ignore[override]  # does not match supertype, but it's correct
        self,
        index: int
    ) -> APINetworkInterfaceType:
        return self.data[index]

    def __len__(self) -> int:
        return len(self.data)

    def __setitem__(  # type: ignore[override]  # does not match supertype, but it's correct
        self,
        index: int,
        value: APINetworkInterfaceType
    ) -> None:
        self.data[index] = value

    def insert(self, index: int, value: APINetworkInterfaceType) -> None:
        self[index] = value

    # Override serialization - we're fine with quite a trivial approach.
    def serialize(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self.data)

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'NetworkInterfaces':
        cast_serialized = cast(APINetworkInterfacesType, serialized)

        return NetworkInterfaces(cast_serialized)

    # These two methods would deserve their own class, representing a single block device mapping, but, because
    # such mapping isn't plain str/str dictionary, we would have to write so many checks and types to deal with
    # the variants. It's more readable to have them here, namespaced, rather than top-level functions.
    @staticmethod
    def create_nic(
        device_index: int,
        subnet_id: str,
        security_groups: List[str],
        delete_on_termination: bool = True,
        associate_public_ip_address: bool = False
    ) -> Result[APINetworkInterfaceType, Failure]:
        nic: APINetworkInterfaceType = {
            'DeviceIndex': device_index,
            'SubnetId': subnet_id,
            'DeleteOnTermination': delete_on_termination,
            'Groups': security_groups,
            'AssociatePublicIpAddress': associate_public_ip_address
        }

        return Ok(nic)

    @staticmethod
    def update_nic(
        nic: APINetworkInterfaceType,
        device_index: Optional[int] = None,
        subnet_id: Optional[str] = None,
        security_groups: Optional[List[str]] = None,
        delete_on_termination: Optional[bool] = None,
        associate_public_ip_address: Optional[bool] = None
    ) -> Result[APINetworkInterfaceType, Failure]:
        if device_index is not None:
            nic['DeviceIndex'] = device_index

        if subnet_id is not None:
            nic['SubnetId'] = subnet_id

        if delete_on_termination is not None:
            nic['DeleteOnTermination'] = delete_on_termination

        if security_groups is not None:
            nic['Groups'] = security_groups

        if associate_public_ip_address is not None:
            nic['AssociatePublicIpAddress'] = associate_public_ip_address

        return Ok(nic)

    def _get_nic(
        self,
        index: int
    ) -> Optional[APINetworkInterfaceType]:
        try:
            return self.data[index]

        except IndexError:
            return None

    def find_free_device_index(self) -> int:
        indices = [i for i in range(len(self.data) + 1)]

        for nic in self.data:
            if nic['DeviceIndex'] in indices:
                indices.remove(nic['DeviceIndex'])

        return indices[0]

    def enlarge(
        self,
        count: int,
        subnet_id: str,
        security_groups: List[str],
        delete_on_termination: bool,
        associate_public_ip_address: bool
    ) -> Result[None, Failure]:
        current_count = len(self)

        for _ in range(count - current_count):
            device_index = self.find_free_device_index()

            r_append = self.append_nic(
                device_index,
                subnet_id,
                security_groups,
                delete_on_termination=delete_on_termination,
                associate_public_ip_address=associate_public_ip_address
            )

            if r_append.is_error:
                return Error(r_append.unwrap_error())

        return Ok(None)

    def append_nic(
        self,
        device_index: int,
        subnet_id: str,
        security_groups: List[str],
        delete_on_termination: bool = True,
        associate_public_ip_address: bool = False
    ) -> Result[APINetworkInterfaceType, Failure]:
        r_create = NetworkInterfaces.create_nic(
            device_index,
            subnet_id,
            security_groups,
            delete_on_termination=delete_on_termination,
            associate_public_ip_address=associate_public_ip_address
        )

        if r_create.is_ok:
            self.data.append(r_create.unwrap())

        return r_create


def _honor_constraint_network(
    logger: ContextAdapter,
    pool: 'AWSDriver',
    constraint: Constraint,
    nics: NetworkInterfaces,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
    security_groups: List[str]
) -> Result[bool, Failure]:
    _, index, child_property_name, _ = constraint.expand_name()

    if child_property_name == 'type':
        assert index is not None

        r_enlarge = nics.enlarge(
            index + 1,
            pool.pool_config['subnet-id'],
            security_groups,
            delete_on_termination=True,
            associate_public_ip_address=pool.use_public_ip
        )

        if r_enlarge.is_error:
            return Error(r_enlarge.unwrap_error())

        return Ok(True)

    return Ok(False)


def setup_extra_network_interfaces(
    logger: ContextAdapter,
    pool: 'AWSDriver',
    nics: NetworkInterfaces,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
    security_groups: List[str]
) -> Result[NetworkInterfaces, Failure]:
    r_spans = _get_constraint_spans(logger, guest_request, image, flavor)

    if r_spans.is_error:
        return Error(r_spans.unwrap_error())

    spans = r_spans.unwrap()

    if not spans:
        return Ok(nics)

    # TODO: this could be a nice algorithm, picking the best span instead of the first one.
    span = spans[0]

    log_dict_yaml(logger.debug, 'selected span', [str(constraint) for constraint in span])

    for constraint in span:
        logger.debug(f'  {constraint}')

        property_name, _, _, _ = (constraint.original_constraint or constraint).expand_name()

        if property_name != 'network':
            logger.debug('    ignored')
            continue

        r_consumed = _honor_constraint_network(
            logger,
            pool,
            constraint.original_constraint or constraint,
            nics,
            guest_request,
            image,
            flavor,
            security_groups
        )

        if r_consumed.is_error:
            return Error(r_consumed.unwrap_error())

        if r_consumed.unwrap() is True:
            continue

        return Error(Failure(
            'cannot honor network constraint',
            constraint=repr(constraint)
        ))

    return Ok(nics)


def create_network_interfaces(
    logger: ContextAdapter,
    pool: 'AWSDriver',
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: AWSFlavor,
    security_groups: List[str]
) -> Result[NetworkInterfaces, Failure]:
    nics = NetworkInterfaces()

    nics.append_nic(
        0,
        pool.pool_config['subnet-id'],
        security_groups,
        delete_on_termination=True,
        associate_public_ip_address=pool.use_public_ip
    )

    r_nics = setup_extra_network_interfaces(
        logger,
        pool,
        nics,
        guest_request,
        image,
        flavor,
        security_groups
    )

    if r_nics.is_error:
        return r_nics

    return Ok(r_nics.unwrap())


def _sanitize_tags(tags: GuestTagsType) -> Generator[Tuple[str, str], None, None]:
    """
    Sanitize tags to make their values acceptable for AWS API and CLI.

    Namely characters like a space (`` ``) and quotation marks (``"``) are rewritten.
    """

    for name, value in tags.items():
        # Get rid of quotes and singlequotes, AWS won't accept those.
        value = (value or '').replace('"', '<quote>').replace('\'', '<singlequote>')

        # Replace an empty string with double quotes representing an empty string. AWS won't
        # accept `Value=`, but is willing to accept `Value=""`.
        yield name, value or '""'


def _serialize_tags(tags: GuestTagsType) -> List[str]:
    """
    Serialize tags to make them acceptable for AWS CLI.

    AWS accepts tags in form of key/value lists, with field explicitly named:

    .. code-block:: python

       Key=foo,Value=bar Key=baz,Value=

    See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#create-tag-examples for more details.
    """

    return [
        f'Key={name},Value={value}'
        for name, value in _sanitize_tags(tags)
    ]


def _tags_to_tag_specifications(tags: GuestTagsType, *resource_types: str) -> List[str]:
    """
    Serialize tags to make them acceptable for ``--tag-specifications`` CLI option.

    AWS accepts tags in form of a resource type plus a key/value list, with field explicitly named.

    .. code-block:: python

       ResourceType=foo,Tags=[{Key=foo,Value=bar},...]

    See https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html#tag-on-create-examples for more details.
    """

    serialized_tags = ','.join([
        f'{{{tag}}}' for tag in _serialize_tags(tags)
    ])

    return [
        f'ResourceType={resource_type},Tags=[{serialized_tags}]'
        for resource_type in resource_types
    ]


def _aws_arch_to_arch(arch: str) -> str:
    """
    Convert processors architecture as known to AWS EC2 API to architecture as tracked by Artemis.

    There is at least one difference, AWS' ``arm64`` is usually called ``aarch64`` by other drivers
    supported by Artemis. This function serves as a small compatibility layer.

    :param str: architecture as known to AWS EC2. Usually retrieved from ``ProcessorInfo`` structure
        as described at https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ProcessorInfo.html.
    :returns: architecture name, or ``None`` when architecture is unsupported or unknown.
    """

    if arch == 'x86_64':
        return 'x86_64'

    if arch == 'arm64':
        return 'aarch64'

    return arch


def _aws_boot_to_boot(boot_method: str) -> FlavorBootMethodType:
    """
    Convert image/instance type boot method as known to AWS EC2 API to boot method as tracked by Artemis.

    There is at least one difference, AWS' ``legacy-bios`` is usually called just ``bios`` by other
    drivers supported by Artemis. This function serves as a small compatibility layer.

    :param str: boot method as known to AWS EC2.
    :returns: boot method as known to Artemis.
    """

    if boot_method == 'legacy-bios':
        return 'bios'

    if boot_method == 'uefi':
        return 'uefi'

    if boot_method == 'uefi-preffered':
        return 'uefi-preferred'

    return cast(FlavorBootMethodType, boot_method)


class AWSDriver(PoolDriver):
    drivername = 'aws'

    image_info_class = AWSPoolImageInfo
    flavor_info_class = AWSFlavor
    pool_data_class = AWSPoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super().__init__(logger, poolname, pool_config)
        self.environ = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": self.pool_config['access-key-id'],
            "AWS_SECRET_ACCESS_KEY": self.pool_config['secret-access-key'],
            "AWS_DEFAULT_REGION": self.pool_config['default-region'],
            "AWS_DEFAULT_OUTPUT": 'json'
        }

    # TODO: return value does not match supertype - it should, it does, but mypy ain't happy: why?
    @property
    def image_info_mapper(self) -> AWSHookImageInfoMapper:  # type: ignore[override]  # does not match supertype
        return AWSHookImageInfoMapper(self, 'AWS_ENVIRONMENT_TO_IMAGE')

    @property
    def _image_owners(self) -> List[str]:
        return cast(
            List[str],
            self.pool_config.get('image-owners', ['self'])
        )

    @property
    def _pool_security_groups(self) -> List[str]:
        """Get security groups from pool config as a list."""
        security_group_config = self.pool_config.get('security-group', [])

        if isinstance(security_group_config, list):
            return security_group_config

        return [security_group_config]

    @property
    def use_public_ip(self) -> bool:
        return normalize_bool_option(self.pool_config.get('use-public-ip', False))

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = False
        capabilities.supports_native_post_install_script = True
        capabilities.supported_guest_logs = [
            ('console:dump', GuestLogContentType.BLOB),
            ('console:interactive', GuestLogContentType.URL)
        ]

        return Ok(capabilities)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = AWSPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.spot_instance_id is not None:
            r_output = self._aws_command([
                'ec2', 'cancel-spot-instance-requests',
                f'--spot-instance-request-ids={resource_ids.spot_instance_id}'
            ], commandname='aws.ec2-cancel-spot-instance-requests')

            if r_output.is_error:
                return Error(Failure.from_failure(
                    'failed to cancel spot instance request',
                    r_output.unwrap_error()
                ))

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        if resource_ids.instance_id is not None:
            r_output = self._aws_command([
                'ec2', 'terminate-instances',
                f'--instance-ids={resource_ids.instance_id}'
            ], commandname='aws.ec2-terminate-instances')

            if r_output.is_error:
                return Error(Failure.from_failure(
                    'failed to terminate instance',
                    r_output.unwrap_error()
                ))

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        if resource_ids.security_group is not None:
            r_check = self._aws_command(
                [
                    'ec2', 'describe-network-interfaces',
                    '--filter', f'Name=group-id,Values={resource_ids.security_group}',
                    '--query', 'NetworkInterfaces[*].[NetworkInterfaceId]'
                ],
                commandname='aws.ec2-check-security-group-attached'
            )

            if r_check.is_error:
                return Error(Failure.from_failure(
                    'failed to check if security group is attached to a NIC',
                    r_check.unwrap_error()
                ))

            if cast(List[Any], r_check.unwrap()):
                # We have a VNIC still attached to the security group and have to wait for the VM to terminate fully
                return Ok(ReleasePoolResourcesState.BLOCKED)

            r_output = self._aws_command(
                [
                    'ec2', 'delete-security-group',
                    '--group-id', resource_ids.security_group
                ],
                json_output=False,
                commandname='aws.ec2-delete-security-group')

            if r_output.is_error:
                return Error(Failure.from_failure(
                    'failed to delete a guest security group',
                    r_output.unwrap_error()
                ))

            self.inc_costs(logger, ResourceType.SECURITY_GROUP, resource_ids.ctime)

        return Ok(ReleasePoolResourcesState.RELEASED)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        # Disallow HW constraints the driver does not implement yet
        if guest_request.environment.has_hw_constraints:
            r_constraints = guest_request.environment.get_hw_constraints()

            if r_constraints.is_error:
                return Error(r_constraints.unwrap_error())

        r_images = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if not images:
            return Ok(CanAcquire.cannot('compose not supported'))

        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

            if not images:
                return Ok(CanAcquire.cannot('compose does not support kickstart'))

        pairs: List[Tuple[AWSPoolImageInfo, Flavor]] = []

        for image in images:
            r_type = self._env_to_instance_type_or_none(logger, session, guest_request, image)

            if r_type.is_error:
                return Error(r_type.unwrap_error())

            flavor = r_type.unwrap()

            if flavor is None:
                continue

            pairs.append((image, flavor))

        if not pairs:
            return Ok(CanAcquire.cannot('no suitable image/flavor combination found'))

        log_dict_yaml(logger.info, 'available image/flavor combinations', [
            {
                'flavor': flavor.serialize(),
                'image': image.serialize()
            } for image, flavor in pairs
        ])

        return Ok(CanAcquire())

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _filter_flavors_console_url_support(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        suitable_flavors: List[AWSFlavor]
    ) -> List[AWSFlavor]:
        """
        Console/URL logs require ENA support
        """

        if not guest_request.requests_guest_log('console:interactive', GuestLogContentType.URL):
            return suitable_flavors

        return list(logging_filter(
            logger,
            suitable_flavors,
            'console requires flavor ENA support',
            lambda logger, flavor: flavor.ena_support in ('required', 'supported')
        ))

    def _filter_flavors_image_ena_support(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        suitable_flavors: List[AWSFlavor]
    ) -> List[AWSFlavor]:
        """
        Make sure that, if image does not support ENA, we drop all flavors that require the support
        """

        if image.ena_support is True:
            return suitable_flavors

        return list(logging_filter(
            logger,
            suitable_flavors,
            'image and flavor ENA compatibility',
            lambda logger, flavor: flavor.ena_support != 'required'
        ))

    def _filter_flavors_image_boot_method(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        suitable_flavors: List[AWSFlavor]
    ) -> List[AWSFlavor]:
        """
        Make sure that, if image supports a particular boot method only, we drop all flavors that do not support it
        """

        if not image.boot.method:
            return suitable_flavors

        return list(logging_filter(
            logger,
            suitable_flavors,
            'image boot method is supported',
            lambda logger, flavor: any(method in flavor.boot.method for method in image.boot.method)
        ))

    def _filter_flavors_hw_constraints(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        suitable_flavors: List[AWSFlavor]
    ) -> List[AWSFlavor]:
        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            r_constraints.unwrap_error().handle(logger)

            return []

        constraints = r_constraints.unwrap()

        if constraints is None:
            return suitable_flavors

        def _boot_method_requested(logger: ContextAdapter, flavor: AWSFlavor) -> bool:
            r_span = _get_constraint_span(logger, guest_request, image, flavor)

            if r_span.is_error:
                r_span.unwrap_error().handle(logger)

                return False

            span = r_span.unwrap()

            if not span:
                return False

            for constraint in span:
                property_name, _, child_property, _ = constraint.expand_name()

                if property_name == 'boot' and child_property == 'method':
                    if constraint.operator == Operator.CONTAINS:
                        return constraint.value in (image.boot.method + flavor.boot.method)

                    if constraint.operator == Operator.NOTCONTAINS:
                        return constraint.value not in (image.boot.method + flavor.boot.method)

                    return False

            # There was no constraint related to boot method, otherwise we wouldn't be at this point. Which means,
            # boot method has not been requested, and therefore it does not matter.
            return True

        return list(logging_filter(
            logger,
            suitable_flavors,
            'requested boot method is supported by image and flavor',
            _boot_method_requested
        ))

    def _env_to_instance_type_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo
    ) -> Result[Optional[AWSFlavor], Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = cast(List[AWSFlavor], r_suitable_flavors.unwrap())

        suitable_flavors = self.filter_flavors_image_arch(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        suitable_flavors = self._filter_flavors_console_url_support(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        suitable_flavors = self._filter_flavors_image_ena_support(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        suitable_flavors = self._filter_flavors_image_boot_method(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        # Make sure the image and flavor support requested HW
        if guest_request.environment.has_hw_constraints:
            suitable_flavors = self._filter_flavors_hw_constraints(
                logger,
                session,
                guest_request,
                image,
                suitable_flavors
            )

        if not suitable_flavors:
            if self.pool_config.get('use-default-flavor-when-no-suitable', True):
                guest_request.log_warning_event(
                    logger,
                    session,
                    'no suitable flavors, using default',
                    poolname=self.poolname
                )

                r_default_flavor = self._map_environment_to_flavor_info_by_cache_by_name_or_none(
                    logger,
                    self.pool_config['default-instance-type']
                )

                if r_default_flavor.is_error:
                    return Error(r_default_flavor.unwrap_error())

                return Ok(cast(AWSFlavor, r_default_flavor.unwrap()))

            guest_request.log_warning_event(
                logger,
                session,
                'no suitable flavors',
                poolname=self.poolname
            )

            return Ok(None)

        if self.pool_config['default-instance-type'] in [flavor.name for flavor in suitable_flavors]:
            logger.info('default flavor among suitable ones, using it')

            return Ok([
                flavor
                for flavor in suitable_flavors
                if flavor.name == self.pool_config['default-instance-type']
            ][0])

        return Ok(suitable_flavors[0])

    def _env_to_instance_type(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo
    ) -> Result[AWSFlavor, Failure]:
        r_flavor = self._env_to_instance_type_or_none(logger, session, guest_request, image)

        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor = r_flavor.unwrap()

        if flavor is None:
            return Error(Failure('no suitable flavor'))

        return Ok(flavor)

    def _describe_instance(
        self,
        guest_request: GuestRequest
    ) -> Result[InstanceOwnerType, Failure]:

        aws_options = [
            'ec2',
            'describe-instances',
            f'--instance-id={guest_request.pool_data.mine(self, AWSPoolData).instance_id}'
        ]

        r_output = self._aws_command(aws_options, key='Reservations', commandname='aws.ec2-describe-instances')

        # command returned an unxpected result
        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to fetch instance information',
                r_output.unwrap_error()
            ))

            return Error(r_output.unwrap_error())

        output = cast(List[Dict[str, Any]], r_output.unwrap())

        # get instance info from command output
        try:
            instance = output[0]['Instances'][0]
            owner = output[0]['OwnerId']
        except (KeyError, IndexError) as error:
            return Error(
                Failure.from_exc(
                    'Failed to parse instance from output',
                    error,
                    output=output
                )
            )

        return Ok((instance, owner))

    def _describe_spot_instance(
        self,
        guest_request: GuestRequest
    ) -> Result[Dict[str, Any], Failure]:
        aws_options = [
            'ec2',
            'describe-spot-instance-requests',
            f'--spot-instance-request-ids={guest_request.pool_data.mine(self, AWSPoolData).spot_instance_id}'
        ]

        r_output = self._aws_command(
            aws_options,
            key='SpotInstanceRequests',
            commandname='aws.ec2-describe-spot-instance-requests'
        )

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to fetch spot instance request information',
                r_output.unwrap_error()
            ))

        return Ok(cast(List[Dict[str, Any]], r_output.unwrap())[0])

    def _aws_command(
        self,
        args: List[str],
        json_output: bool = True,
        key: Optional[str] = None,
        commandname: Optional[str] = None
    ) -> Result[JSONType, Failure]:
        """
        Runs command via aws cli and returns a dictionary with command reply.

        :param list(str) args: Arguments for aws.
        :param str key: Optional key to return.
        """

        command = [self.pool_config['command']] + args

        r_run = run_cli_tool(
            self.logger,
            command,
            json_output=json_output,
            env=self.environ,
            poolname=self.poolname,
            commandname=commandname,
            cause_extractor=awscli_error_cause_extractor
        )

        if r_run.is_error:
            failure = r_run.unwrap_error()

            # Detect "instance does not exist" - these errors are clearly irrecoverable. No matter how often we would
            # run these CLI commands, we would never ever made them work with instances that don't exist.
            if failure.command_output:
                cause = awscli_error_cause_extractor(failure.command_output)

                if cause in (AWSErrorCauses.MISSING_INSTANCE, AWSErrorCauses.MISSING_SPOT_INSTANCE_REQUEST):
                    failure.recoverable = False

                    PoolMetrics.inc_error(self.poolname, cause)

            return Error(failure)

        output = r_run.unwrap()

        if json_output is False:
            return Ok(output.stdout)

        if key is None:
            return Ok(output.json)

        try:
            return Ok(cast(Dict[str, Any], output.json)[key])

        except KeyError:
            return Error(Failure(
                f"key '{key}' not found in CLI output",
                command_output=output.process_output,
                scrubbed_command=command
            ))

    def _get_spot_price(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: Flavor,
        image: AWSPoolImageInfo
    ) -> Result[float, Failure]:

        availability_zone = self.pool_config['availability-zone']

        r_spot_price = self._aws_command([
            'ec2', 'describe-spot-price-history',
            f'--instance-types={instance_type.id}',
            f'--availability-zone={availability_zone}',
            f'--product-descriptions={image.platform_details}',
            '--max-items=1'
        ], key='SpotPriceHistory', commandname='aws.ec2-describe-spot-price-history')

        if r_spot_price.is_error:
            return Error(Failure.from_failure(
                'failed to fetch spot price history',
                r_spot_price.unwrap_error()
            ))

        prices = cast(List[Dict[str, str]], r_spot_price.unwrap())

        log_dict(logger.debug, 'spot prices', prices)

        try:
            current_price = float(prices[0]['SpotPrice'])

        except (KeyError, IndexError):
            PoolMetrics.inc_error(self.poolname, AWSErrorCauses.SPOT_PRICE_NOT_DETECTED)

            return Error(Failure('failed to detect spot price'))

        # we bid some % to the price
        price = current_price + current_price * (float(self.pool_config['spot-price-bid-percentage']) / 100.0)

        spot_price_bid_percentage = self.pool_config['spot-price-bid-percentage']

        log_dict_yaml(logger.info, 'using spot price', {
            'availability zone': self.pool_config['availability-zone'],
            'current price': current_price,
            'instance type': instance_type.serialize(),
            'product description': image.platform_details,
            'bid': f'{spot_price_bid_percentage}%',
            'print': price
        })

        return Ok(price)

    def _create_block_device_mappings(
        self,
        logger: ContextAdapter,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        flavor: Flavor
    ) -> Result[BlockDeviceMappings, Failure]:
        """
        Prepare block device mapping according to given flavor.

        .. note::

           If the flavor does not specify a desired disk space, then fall back to ``default-root-disk-size``
           configuration option. This will serve us until all flavors get their disk space.

        :param image: image that will be used to create the instance. It serves as a source of block device
            mapping data.
        :param flavor: flavor providing the disk space information.
        """

        default_root_disk_size: Optional[SizeType] = None

        if 'default-root-disk-size' in self.pool_config:
            default_root_disk_size = UNITS.Quantity(self.pool_config["default-root-disk-size"], UNITS.gibibytes)

        return create_block_device_mappings(
            logger,
            guest_request,
            image,
            flavor,
            default_root_disk_size=default_root_disk_size
        )

    def _create_network_interfaces(
        self,
        logger: ContextAdapter,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo,
        flavor: AWSFlavor,
        security_groups: List[str]
    ) -> Result[NetworkInterfaces, Failure]:
        return create_network_interfaces(
            logger,
            self,
            guest_request,
            image,
            flavor,
            security_groups
        )

    def _create_user_data(
        self,
        logger: ContextAdapter,
        guest_request: GuestRequest,
    ) -> Optional[str]:
        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return None

        return r_post_install_script.unwrap()

    def _assign_security_group_rules(
        self,
        logger: ContextAdapter,
        guest_request: GuestRequest,
        guest_security_group_id: str
    ) -> Result[List[str], Failure]:
        """
        Ideally there should be a dedicated stage in the artemis lifecycle, when upon startup the artemis config's
        security-group-rules are matched against existing rules in the security-group (with correction
        applied if something doesn't match). Then this security group is attached to the guest and another one
        is created to hold any custom rules from the guest request.

        At the moment we are not there yet, so this dynamic rules adjustment is out of the picture.
        For the interim period let's have it the following way:

        * if there is a security-group defined in the config, then it will be attached as is to the guest instance.
          All custom rules go to a separate security group that is precreated for each guest. The guest will have 2
          security groups attached to it. In the event of cancellation only custom security group will be cleaned up.

        * if there is security-group-rules section defined, then all the rules from it together with any custom ones
          from guest request will go into a created-per-guest security group. The guest will end up with just 1
          custom security group. In the event of cancellation this group will be cleaned up.

        This helper performs all the necessary setting of the security groups involved and returns a list of security
        group ids to be used during actual instance creation. The created-per-guest security group will be the first
        in the resulted list.
        """
        res_security_groups = [guest_security_group_id]
        guest_secgroup_rules = guest_request.security_group_rules

        if not self.pool_config.get('security-group-rules') and self.pool_config.get('security-group'):
            # 2 security groups per guest case
            res_security_groups.extend(self._pool_security_groups)

        if self.pool_config.get('security-group-rules'):
            # 1 security group per guest case, custom and pool merged into one secgroup
            r_rules_from_config = SecurityGroupRules.load_from_pool_config(self.pool_config['security-group-rules'])
            if r_rules_from_config.is_error:
                return Error(Failure.from_failure('failed to load security group rules from pool config',
                                                  r_rules_from_config.unwrap_error()))

            guest_secgroup_rules.extend(r_rules_from_config.unwrap())

        def _create_ip_permissions_payload(rules: List[SecurityGroupRule]) -> str:
            ip_permissions = []
            for rule in rules:
                ip_permissions.append({'IpProtocol': rule.protocol,
                                       'FromPort': rule.port_min,
                                       'ToPort': rule.port_max,
                                       'Ipv6Ranges' if rule.is_ipv6 else 'IpRanges': [
                                           {'CidrIpv6' if rule.is_ipv6 else 'CidrIp': rule.cidr}]
                                       })
            return json.dumps(ip_permissions)

        # Update new security group with a proper set of rules
        rules_map = {'ingress': guest_secgroup_rules.ingress,
                     'egress': guest_secgroup_rules.egress}

        # NOTE(ivasilev) As we have to support both ipv4 and ipv6 can't use the comfort of --cidr passing as this
        # argument supports only ipv4 addresses, need to form --ip-permissions payload manually.
        for rule_type, rules in rules_map.items():
            if not rules:
                # No rules to apply, skipping
                continue

            r_update_sg_bulk = self._aws_command([
                'ec2', f'authorize-security-group-{rule_type}',
                '--group-id', guest_security_group_id,
                '--ip-permissions', _create_ip_permissions_payload(rules)
            ])
            if r_update_sg_bulk.is_error:
                return Error(Failure.from_failure('failed to update security group', r_update_sg_bulk.unwrap_error()))

        return Ok(res_security_groups)

    def _find_security_group_id(
        self,
        logger: ContextAdapter,
        security_group: str,
        vpc: str
    ) -> Result[Optional[str], Failure]:
        r_security_group_info = self._aws_command(
            [
                'ec2', 'describe-security-groups',
                '--filters',
                f'Name=group-name,Values={security_group}',
                f'Name=vpc-id,Values={vpc}'
            ],
            commandname='aws.ec2-describe-security-groups'
        )

        if r_security_group_info.is_error:
            return Error(r_security_group_info.unwrap_error())

        security_group_ids: List[str] = list(JQ_QUERY_SECURITY_GROUP_IDS.input(r_security_group_info.unwrap()).all())

        if not security_group_ids:
            return Ok(None)

        return Ok(security_group_ids[0])

    def _acquire_guest_security_group(
        self,
        logger: ContextAdapter,
        guest_request: GuestRequest,
        tags: Dict[str, str],
    ) -> Result[List[str], Failure]:
        # Get the name of the new group from the template
        r_security_group_template = KNOB_GUEST_SECURITY_GROUP_NAME_TEMPLATE.get_value(entityname=self.poolname)
        if r_security_group_template.is_error:
            return Error(Failure('Could not get guest security group name template'))

        r_rendered = render_template(
            r_security_group_template.unwrap(),
            GUESTNAME=guest_request.guestname,
            ENVIRONMENT=guest_request.environment,
            TAGS=tags
        )
        if r_security_group_template.is_error:
            return Error(Failure('Could not render guest security group name template'))

        security_group_name = r_rendered.unwrap()

        # Get the VPC id from the subnet-id, otherwise subsequent instance creation may fail with SG and subnet
        # not belonging to the same network
        r_subnet_details = self._aws_command(
            [
                'ec2', 'describe-subnets',
                '--filters', f'Name=subnet-id,Values={self.pool_config["subnet-id"]}'
            ],
            key="Subnets", commandname='aws.ec2-describe-subnets'
        )

        if r_subnet_details.is_error:
            return Error(Failure.from_failure(
                'failed to list subnet details, cannot retrieve VPC id',
                r_subnet_details.unwrap_error()
            ))

        subnet_details = cast(List[Dict[str, str]], r_subnet_details.unwrap())
        vpc_id = subnet_details[0]['VpcId']

        r_security_group_id = self._find_security_group_id(logger, security_group_name, vpc_id)

        if r_security_group_id.is_error:
            return Error(r_security_group_id.unwrap_error())

        if r_security_group_id.unwrap():
            security_group_id = r_security_group_id.unwrap()

            assert security_group_id is not None

        else:
            command = [
                'ec2', 'create-security-group',
                '--group-name', security_group_name,
                '--description', 'Autocreated artemis guest security group',
                '--vpc-id', vpc_id
            ]

            if tags:
                command += [
                    '--tag-specifications'
                ] + _tags_to_tag_specifications(tags, 'security-group')

            # Create a new security group and retrieve it's id
            r_create_sg = self._aws_command(command, key='GroupId', commandname='aws.ec2-create-security-group')

            if r_create_sg.is_error:
                return Error(Failure.from_failure(
                    'failed to create a security group',
                    r_create_sg.unwrap_error()
                ))

            security_group_id = cast(str, r_create_sg.unwrap())

        r_get_secgroups = self._assign_security_group_rules(logger, guest_request, security_group_id)
        if r_get_secgroups.is_error:
            return Error(Failure.from_failure(
                'failed to setup guest security group rules properly',
                r_get_secgroups.unwrap_error()
            ))

        # Finally return the ids of the future instance secgroups
        return Ok(r_get_secgroups.unwrap())

    def _request_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_type: AWSFlavor,
        image: AWSPoolImageInfo
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        tags = r_base_tags.unwrap()

        # If create-security-group-per-guest is defined in the config then precreate a security group for each guest,
        # otherwise use the one from the security-group pool configuration
        if normalize_bool_option(self.pool_config.get('create-security-group-per-guest', False)):
            r_create_guest_sg = self._acquire_guest_security_group(
                logger=logger,
                guest_request=guest_request,
                tags=tags
            )
            if r_create_guest_sg.is_error:
                return Error(r_create_guest_sg.unwrap_error())

            security_group_ids = r_create_guest_sg.unwrap()

        else:
            security_group_ids = self._pool_security_groups

        logger.info(f'Using security groups {security_group_ids}')

        command = [
            'ec2', 'run-instances',
            '--image-id', image.id,
            '--key-name', self.pool_config['master-key-name'],
            '--instance-type', instance_type.id
        ]

        if self.pool_config.get('expose-instance-tags-in-metadata', False):
            command += ['--metadata-options', 'InstanceMetadataTags=enabled']

        if 'subnet-id' in self.pool_config:
            command.extend(['--subnet-id', self.pool_config['subnet-id']])

        r_block_device_mappings = self._create_block_device_mappings(logger, guest_request, image, instance_type)

        if r_block_device_mappings.is_error:
            return Error(r_block_device_mappings.unwrap_error())

        command.extend([
            '--block-device-mappings',
            r_block_device_mappings.unwrap().serialize_to_json()
        ])

        r_network_interfaces = self._create_network_interfaces(logger, guest_request, image, instance_type,
                                                               security_group_ids)

        if r_network_interfaces.is_error:
            return Error(r_network_interfaces.unwrap_error())

        command.extend([
            '--network-interfaces',
            r_network_interfaces.unwrap().serialize_to_json()
        ])

        user_data = self._create_user_data(logger, guest_request)

        if user_data:
            command.extend([
                '--user-data',
                user_data
            ])

        if 'additional-options' in self.pool_config:
            command.extend(self.pool_config['additional-options'])

        if tags:
            command += [
                '--tag-specifications'
            ] + _tags_to_tag_specifications(tags, 'instance', 'volume')

        # Note: this is actually not used for anything but logging alone. We re-use the spot template, the fields are
        # pretty much the same.
        specification = AWS_INSTANCE_SPECIFICATION.render(
            ami_id=image.id,
            key_name=self.pool_config['master-key-name'],
            instance_type=instance_type,
            availability_zone=self.pool_config['availability-zone'],
            subnet_id=self.pool_config['subnet-id'],
            security_groups=security_group_ids,
            user_data=_base64_encode(user_data) if user_data else '',
            network_interfaces=r_network_interfaces.unwrap().serialize(),
            block_device_mappings=r_block_device_mappings.unwrap().serialize()
        )

        log_dict_yaml(logger.info, 'non-spot request launch specification', json.loads(specification))

        r_instance_request = self._aws_command(command, key='Instances', commandname='aws.ec2-run-instances')

        if r_instance_request.is_error:
            return Error(Failure.from_failure(
                'failed to start instance',
                r_instance_request.unwrap_error()
            ))

        instance_request = cast(List[Dict[str, str]], r_instance_request.unwrap())

        try:
            instance_id = instance_request[0]['InstanceId']
        except (KeyError, IndexError):
            return Error(Failure('Failed to find InstanceID in aws output', output=instance_request))

        # instance state is "pending" after launch
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html
        logger.info(f'current instance state {instance_id}:pending')

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=AWSPoolData(
                instance_id=instance_id,
                security_group=(security_group_ids[0]
                                if security_group_ids[0] not in self._pool_security_groups else None)),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _request_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_type: AWSFlavor,
        image: AWSPoolImageInfo
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        tags = r_base_tags.unwrap()

        # If create-security-group-per-guest is defined in the config then precreate a security group for each guest,
        # otherwise use the one from the security-group pool configuration
        if normalize_bool_option(self.pool_config.get('create-security-group-per-guest', False)):
            r_create_guest_sg = self._acquire_guest_security_group(
                logger=logger,
                guest_request=guest_request,
                tags=tags
            )
            if r_create_guest_sg.is_error:
                return Error(r_create_guest_sg.unwrap_error())

            security_group_ids = r_create_guest_sg.unwrap()

        else:
            security_group_ids = self._pool_security_groups

        logger.info(f'Using security groups {security_group_ids}')

        # find our spot instance prices for the instance_type in our availability zone
        r_price = self._get_spot_price(logger, instance_type, image)
        if r_price.is_error:
            # _get_spot_price has different return value, we cannot return it as it is
            return Error(r_price.unwrap_error())

        spot_price = r_price.unwrap()

        r_block_device_mappings = self._create_block_device_mappings(logger, guest_request, image, instance_type)

        if r_block_device_mappings.is_error:
            return Error(r_block_device_mappings.unwrap_error())

        r_network_interfaces = self._create_network_interfaces(logger, guest_request, image, instance_type,
                                                               security_group_ids)

        if r_network_interfaces.is_error:
            return Error(r_network_interfaces.unwrap_error())

        user_data = self._create_user_data(logger, guest_request)

        specification = AWS_INSTANCE_SPECIFICATION.render(
            ami_id=image.id,
            key_name=self.pool_config['master-key-name'],
            instance_type=instance_type,
            availability_zone=self.pool_config['availability-zone'],
            subnet_id=self.pool_config['subnet-id'],
            security_group=security_group_ids,
            user_data=_base64_encode(user_data) if user_data else '',
            network_interfaces=r_network_interfaces.unwrap().serialize(),
            block_device_mappings=r_block_device_mappings.unwrap().serialize()
        )

        log_dict_yaml(logger.info, 'spot request launch specification', json.loads(specification))

        command = [
            'ec2', 'request-spot-instances',
            f'--spot-price={spot_price}',
            f'--launch-specification={" ".join(specification.split())}'
        ]

        if tags:
            command += [
                '--tag-specifications'
            ] + _tags_to_tag_specifications(tags, 'spot-instances-request')

        r_spot_request = self._aws_command(
            command,
            key='SpotInstanceRequests',
            commandname='aws.ec2-request-spot-instances'
        )

        if r_spot_request.is_error:
            return Error(Failure.from_failure(
                'failed to request spot instance',
                r_spot_request.unwrap_error()
            ))

        spot_instance_id = cast(List[Dict[str, str]], r_spot_request.unwrap())[0]['SpotInstanceRequestId']

        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-request-status.html
        logger.info(f'current spot instance request state {spot_instance_id}:open:pending-evaluation')

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=AWSPoolData(
                spot_instance_id=spot_instance_id,
                security_group=(security_group_ids[0]
                                if security_group_ids[0] not in self._pool_security_groups else None)),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _do_update_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        pool_data = guest_request.pool_data.mine(self, AWSPoolData)

        assert pool_data.spot_instance_id is not None

        r_spot_instance = self._describe_spot_instance(guest_request)

        if r_spot_instance.is_error:
            return Error(r_spot_instance.unwrap_error())

        spot_instance = r_spot_instance.unwrap()

        state = spot_instance['State']
        status = spot_instance['Status']['Code']

        logger.info(f'current spot instance request state {pool_data.spot_instance_id}:{state}:{status}')

        if status == 'fulfilled' and state == 'active':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=AWSPoolData(
                    instance_id=spot_instance['InstanceId'],
                    spot_instance_id=pool_data.spot_instance_id,
                    security_group=pool_data.security_group
                ),
                delay_update=r_delay.unwrap()
            ))

        if state == 'open':  # noqa: SIM102
            if is_old_enough(logger, spot_instance['CreateTime'], KNOB_SPOT_OPEN_TIMEOUT.value):
                PoolMetrics.inc_error(self.poolname, AWSErrorCauses.INSTANCE_BUILDING_TOO_LONG)

                return Ok(ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=guest_request.pool_data.mine(self, AWSPoolData),
                    pool_failures=[Failure('spot instance stuck in "open" for too long')]
                ))

        if state in ('cancelled', 'failed', 'closed', 'disabled'):
            PoolMetrics.inc_error(self.poolname, AWSErrorCauses.SPOT_INSTANCE_TERMINATED_PREMATURELY)

            spot_instance_fault = spot_instance.get('Fault', {})

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=guest_request.pool_data.mine(self, AWSPoolData),
                pool_failures=[Failure(
                    'spot instance terminated prematurely',
                    spot_instance_state=state,
                    spot_instance_status=status,
                    spot_instance_error=spot_instance['Status']['Message'],
                    spot_instance_error_code=spot_instance_fault.get('Code'),
                    spot_instance_error_detail=spot_instance_fault.get('Message')
                )]
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=pool_data,
            delay_update=r_delay.unwrap()
        ))

    def _do_update_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_output = self._describe_instance(guest_request)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        instance, owner = r_output.unwrap()

        state = instance['State']['Name']

        pool_data = guest_request.pool_data.mine(self, AWSPoolData)

        assert pool_data.instance_id is not None

        logger.info(f'current instance state {pool_data.instance_id}:{state}')

        # EC2 instance lifecycle documentation
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html

        if state == 'terminated' or state == 'shutting-down':
            PoolMetrics.inc_error(self.poolname, AWSErrorCauses.INSTANCE_TERMINATED_PREMATURELY)

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=guest_request.pool_data.mine(self, AWSPoolData),
                pool_failures=[Failure('instance terminated prematurely')]
            ))

        if state == 'pending':
            if is_old_enough(logger, instance['LaunchTime'], KNOB_PENDING_TIMEOUT.value):
                PoolMetrics.inc_error(self.poolname, AWSErrorCauses.INSTANCE_BUILDING_TOO_LONG)

                return Ok(ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=guest_request.pool_data.mine(self, AWSPoolData),
                    pool_failures=[Failure('instance stuck in "pending" for too long')]
                ))

            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=pool_data,
                delay_update=r_delay.unwrap()
            ))

        # Once we have a working instance, we need to apply tags, because:
        #
        # * tags applied to spot request are not propagated to instance, and
        # * tags applied to instance are not applied to volumes and other attached resources.
        #
        # Therefore we need to apply tags explicitly here, even for non-spot instances - those
        # are already tagged, but let's make sure their volumes are tagged as well.
        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        tags = r_base_tags.unwrap()

        if pool_data.spot_instance_id is not None:
            tags['SpotRequestId'] = pool_data.spot_instance_id

        try:
            volume_ids = JQ_QUERY_EBS_VOLUME_IDS.input(instance).all()

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse AWS output',
                exc
            ))

        taggable_resource_ids = [pool_data.instance_id] + volume_ids

        r_tag = self._tag_resources(taggable_resource_ids, tags)

        if r_tag.is_error:
            return Error(Failure.from_failure(
                'failed to tag resource',
                r_tag.unwrap_error().update(
                    tags=tags,
                    resource_ids=taggable_resource_ids
                )
            ))

        if self.pool_config.get('expose-instance-tags-in-metadata', False):
            r_enable_metadata = self._aws_command([
                'ec2',
                'modify-instance-metadata-options',
                '--instance-id', pool_data.instance_id,
                '--instance-metadata-tags', 'enabled'
            ], json_output=False, commandname='aws.enable-instance-tags-in-metadata')

            if r_enable_metadata.is_error:
                return Error(Failure.from_failure(
                    'failed to enable instance tags in metadata',
                    r_enable_metadata.unwrap_error()
                ))

        address = instance['PrivateIpAddress']
        if self.use_public_ip:
            address = instance['PublicIpAddress']

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=pool_data,
            address=address
        ))

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        pool_data = guest_request.pool_data.mine(self, AWSPoolData)

        # If there is a spot instance request, check its state. If it's complete, the pool data would be updated
        # with freshly known instance ID - next time we're asked for update, we would proceed to check the state
        # of this instance, no longer checking the spot request since `pool_data.instance_id` would be set by then.

        if pool_data.instance_id is None:
            return self._do_update_spot_instance(logger, guest_request)

        return self._do_update_instance(logger, session, guest_request)

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
        spot_instance_id = guest_request.pool_data.mine(self, AWSPoolData).spot_instance_id
        if spot_instance_id is None:
            # We are dealing with a non-spot instance that can't be terminated on demand by AWS
            return Ok(WatchdogState.COMPLETE)

        # Query specifically the state of the spot instance request to get more detailed data
        r_spot_instance = self._describe_spot_instance(guest_request)
        if r_spot_instance.is_error:
            return Error(r_spot_instance.unwrap_error())

        spot_instance = r_spot_instance.unwrap()
        status = spot_instance['Status']['Code']
        state = spot_instance['State']

        if state in ('open', 'active'):
            # Guest is fine, nothing to report (yet?)
            return Ok(WatchdogState.CONTINUE)

        if state == 'cancelled' and status in ('instance-terminated-by-user',):
            # This should be the expected final state of normal provisioning.
            return Ok(WatchdogState.COMPLETE)

        if status == 'instance-terminated-no-capacity':
            PoolMetrics.inc_error(self.poolname, AWSErrorCauses.SPOT_INSTANCE_TERMINATED_NO_CAPACITY)
        else:
            # All other transitions go here, including weird unexpected ones like
            # cancelled / request-canceled-and-instance-running)
            PoolMetrics.inc_error(self.poolname, AWSErrorCauses.SPOT_INSTANCE_TERMINATED_UNEXPECTEDLY)

        msg = 'spot instance terminated prematurely'
        guest_request.log_error_event(
            logger,
            session,
            msg,
            Failure(
                msg,
                guestname=guest_request.guestname,
                spot_instance_id=spot_instance_id,
                spot_instance_state=state,
                spot_instance_status=status,
                spot_instance_error=spot_instance['Status']['Message'],
            )
        )

        # Nothing else to watch here, termination reported, we're done
        return Ok(WatchdogState.COMPLETE)

    def _tag_resources(
        self,
        resource_ids: List[str],
        tags: GuestTagsType
    ) -> Result[JSONType, Failure]:
        return self._aws_command([
            'ec2',
            'create-tags',
            '--resources'
        ] + resource_ids + [
            '--tags'
        ] + _serialize_tags(tags), json_output=False, commandname='aws.tag-resources')

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key to upload to the guest.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """
        return self._do_acquire_guest(
            logger,
            session,
            guest_request
        )

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        # find out image from enviroment
        r_images = self.image_info_mapper.map(logger, guest_request)

        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

        pairs: List[Tuple[AWSPoolImageInfo, AWSFlavor]] = []

        for image in images:
            r_instance_type = self._env_to_instance_type(logger, session, guest_request, image)
            if r_instance_type.is_error:
                return Error(r_instance_type.unwrap_error())

            pairs.append((image, r_instance_type.unwrap()))

        if not pairs:
            return Error(Failure('no suitable image/flavor combination found'))

        log_dict_yaml(logger.info, 'available image/flavor combinations', [
            {
                'flavor': flavor.serialize(),
                'image': image.serialize()
            } for image, flavor in pairs
        ])

        image, instance_type = pairs[0]

        # If this pool provides spot instances, we start the provisioning by submitting a spot instance request.
        # After that, we request an update to be scheduled, to check progress of this spot request. If successfull,
        # we extract instance ID, and proceed just like we do with non-spot instances.
        #
        # There is only one request in both cases: either we submit a spot instance request, and the instance gets
        # created implicitly, or, when this pool don't provide spot instances, we submit an instance request. There
        # is no explicit request to transition from spot instance request to instance updates - once spot request is
        # fulfilled, we're given instance ID to work with.

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
            flavor=instance_type,
            image=image
        )

        if normalize_bool_option(self.pool_config.get('use-spot-request', False)):
            return self._request_spot_instance(logger, session, guest_request, instance_type, image)

        return self._request_instance(logger, session, guest_request, instance_type, image)

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, AWSPoolData)

        if not pool_data:
            return Ok(None)

        resource_ids: List[AWSPoolResourcesIDs] = []

        # Prevent "double free" error by using a sequence: if we succeed freeing the instance,
        # we no longer try to free it in the case of retries, we'd focus on spot request only.
        if pool_data.instance_id is not None:
            resource_ids.append(AWSPoolResourcesIDs(instance_id=pool_data.instance_id))

        if pool_data.spot_instance_id is not None:
            resource_ids.append(AWSPoolResourcesIDs(spot_instance_id=pool_data.spot_instance_id))

        if pool_data.security_group is not None:
            resource_ids.append(AWSPoolResourcesIDs(security_group=pool_data.security_group))

        return self.dispatch_resource_cleanup(logger, session, *resource_ids, guest_request=guest_request)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[List[PoolImageInfo], Failure]:
            name_patern: Optional[Pattern[str]] = None
            creation_date_patern: Optional[Pattern[str]] = None
            max_age: Optional[int] = None

            if filters:
                if 'name-regex' in filters:
                    name_patern = re.compile(filters['name-regex'])

                if 'creation-date-regex' in filters:
                    creation_date_patern = re.compile(filters['creation-date-regex'])

                if 'max-age' in filters:
                    max_age = filters.get('max-age')

            cli_options = [
                'ec2',
                'describe-images'
            ]

            if filters and 'owner' in filters:
                cli_options += [
                    '--owners',
                    filters['owner']
                ]

            else:
                cli_options += [
                    '--owners',
                    'self'
                ]

            if filters and 'name-wildcard' in filters:
                cli_options += [
                    '--filter', f'Name=name,Values={filters["name-wildcard"]}'
                ]

            r_images = self._aws_command(
                cli_options,
                key='Images',
                commandname='aws.ec2-describe-images'
            )

            if r_images.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch image information',
                    r_images.unwrap_error()
                ))

            images: List[PoolImageInfo] = []

            for image in cast(List[APIImageType], r_images.unwrap()):
                if name_patern is not None \
                   and not name_patern.match(image.get('Name') or image['ImageId']):
                    continue

                if creation_date_patern is not None \
                   and not creation_date_patern.match(image['CreationDate']):
                    continue

                if max_age is not None and is_old_enough(self.logger, image['CreationDate'], max_age):
                    continue

                try:
                    aws_boot_mode = cast(Optional[str], JQ_QUERY_IMAGE_SUPPORTED_BOOT_MODE.input(image).first())

                except Exception as exc:
                    return Error(Failure.from_exc(
                        'failed to parse AWS output',
                        exc
                    ))

                if aws_boot_mode:
                    boot_method = _aws_boot_to_boot(aws_boot_mode)

                    if boot_method == 'uefi-preferred':
                        image_boot = FlavorBoot(method=['bios', 'uefi'])
                    else:
                        image_boot = FlavorBoot(method=[boot_method])

                else:
                    image_boot = FlavorBoot()

                try:
                    images.append(AWSPoolImageInfo(
                        # .Name is optional and may be undefined or missing - use .ImageId in such a case
                        name=image.get('Name') or image['ImageId'],
                        id=image['ImageId'],
                        arch=_aws_arch_to_arch(image['Architecture']),
                        boot=image_boot,
                        ssh=PoolImageSSHInfo(),
                        supports_kickstart=False,
                        platform_details=image['PlatformDetails'],
                        block_device_mappings=image['BlockDeviceMappings'],
                        # some AMI lack this field, and we need to make sure it's really a boolean, not `null` or `None`
                        ena_support=image.get('EnaSupport', False) or False,
                        boot_mode=aws_boot_mode
                    ))

                except KeyError as exc:
                    return Error(Failure.from_exc(
                        'malformed image description',
                        exc,
                        image_info=r_images.unwrap()
                    ))

            log_dict_yaml(self.logger.debug, 'image filters', filters)
            log_dict_yaml(self.logger.debug, 'found images', [image.name for image in images])

            return Ok(images)

        images: List[PoolImageInfo] = []
        image_filters = cast(List[ConfigImageFilter], self.pool_config.get('image-filters', []))

        if image_filters:
            for filters in image_filters:
                r_images = _fetch_images(filters)

                if r_images.is_error:
                    return r_images

                images += r_images.unwrap()

        else:
            r_images = _fetch_images()

            if r_images.is_error:
                return r_images

            images += r_images.unwrap()

        return Ok(images)

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
        # See AWS docs: https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-types.html

        r_capabilities = self.capabilities()

        if r_capabilities.is_error:
            return Error(r_capabilities.unwrap_error())

        capabilities = r_capabilities.unwrap()

        def _fetch(logger: gluetool.log.ContextAdapter) -> Result[List[Dict[str, Any]], Failure]:
            r_raw_flavors = self._aws_command(
                ['ec2', 'describe-instance-types'],
                key='InstanceTypes',
                commandname='aws.ec2-describe-instance-types'
            )

            if r_raw_flavors.is_error:
                return Error(r_raw_flavors.unwrap_error())

            return Ok(cast(List[Dict[str, Any]], r_raw_flavors.unwrap()))

        # Here we covert instance types retrieved from API into flavors. We take a look at architectures
        # supported by instance type, and create distinct flavors for each architecture. That way, we can
        # have pools supporting more than one architecture, and let Artemis match flavors and requestes
        # based on their attributes, not because maintainers "hide" the instance types with wrong parameters.
        def _constructor(
            logger: gluetool.log.ContextAdapter,
            raw_flavor: Dict[str, Any]
        ) -> Iterator[Result[Flavor, Failure]]:
            for arch in cast(APIInstanceTypeProcessorInfo, raw_flavor['ProcessorInfo'])['SupportedArchitectures']:
                artemis_arch = _aws_arch_to_arch(arch)

                if not capabilities.supports_arch(artemis_arch):
                    continue

                try:
                    boot_methods: List[FlavorBootMethodType] = [
                        _aws_boot_to_boot(boot_method)
                        for boot_method in JQ_QUERY_FLAVOR_SUPPORTED_BOOT_MODES.input(raw_flavor).all()
                    ]

                except Exception as exc:
                    return Error(Failure.from_exc(
                        'malformed flavor description',
                        exc
                    ))

                vcpus = int(raw_flavor['VCpuInfo']['DefaultVCpus'])
                cores = int(raw_flavor['VCpuInfo']['DefaultCores'])
                threads_per_core = int(raw_flavor['VCpuInfo']['DefaultThreadsPerCore'])

                network = FlavorNetworks([FlavorNetwork(type='eth')])

                nic_limit = raw_flavor['NetworkInfo']['MaximumNetworkInterfaces']

                if nic_limit > 1:
                    network.items += [
                        FlavorNetwork(type='eth', is_expansion=True, max_additional_items=nic_limit - 1)
                    ]

                yield Ok(AWSFlavor(
                    name=raw_flavor['InstanceType'],
                    id=raw_flavor['InstanceType'],
                    arch=artemis_arch,
                    boot=FlavorBoot(method=boot_methods),
                    cpu=FlavorCpu(
                        cores=cores,
                        threads=cores * threads_per_core,
                        processors=vcpus,
                        threads_per_core=threads_per_core
                    ),
                    network=network,
                    # memory is reported in MB
                    memory=UNITS.Quantity(int(raw_flavor['MemoryInfo']['SizeInMiB']), UNITS.mebibytes),
                    virtualization=FlavorVirtualization(
                        hypervisor=raw_flavor.get('Hypervisor'),
                        is_virtualized=bool(raw_flavor.get('Hypervisor', '').lower() in AWS_VM_HYPERVISORS)
                    ),
                    ena_support=raw_flavor.get('NetworkInfo', {}).get('EnaSupport', 'unsupported')
                ))

        return self.do_fetch_pool_flavor_info(
            self.logger,
            _fetch,
            # ignore[index]: for some reason, mypy does not detect the type correctly
            lambda raw_flavor: cast(str, raw_flavor['InstanceType']),  # type: ignore[index]
            _constructor
        )

    def get_cached_pool_flavor_info(self, flavorname: str) -> Result[Optional[Flavor], Failure]:
        return get_cached_mapping_item(CACHE.get(), self.flavor_info_cache_key, flavorname, AWSFlavor)

    def get_cached_pool_flavor_infos(self) -> Result[List[Flavor], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return get_cached_mapping_values(CACHE.get(), self.flavor_info_cache_key, AWSFlavor)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        subnet_id = self.pool_config['subnet-id']

        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        # Resource usage - instances and flavors
        def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[List[Dict[str, Any]], Failure]:
            # Count only instance using our subnet
            r = self._aws_command([
                'ec2', 'describe-instances',
                '--filter', f'Name=subnet-id,Values={subnet_id}'
            ], commandname='aws.ec2-describe-instances')

            if r.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch instance information',
                    r.unwrap_error()
                ))

            return Ok(list(JQ_QUERY_POOL_INSTANCES.input(r.unwrap()).all()))

        def _update_instance_usage(
            logger: gluetool.log.ContextAdapter,
            usage: PoolResourcesUsage,
            raw_instance: Dict[str, Any],
            flavor: Optional[Flavor]
        ) -> Result[None, Failure]:
            assert usage.instances is not None  # narrow type
            assert usage.cores is not None  # narrow type
            assert usage.memory is not None  # narrow type

            usage.instances += 1

            if flavor is not None:
                usage.cores += flavor.cpu.cores or 0
                usage.memory += flavor.memory.to('bytes').magnitude if flavor.memory is not None else 0

                if flavor.name not in usage.flavors:
                    usage.flavors[flavor.name] = 0

                usage.flavors[flavor.name] += 1

            return Ok(None)

        r_instances_usage = self.do_fetch_pool_resources_metrics_flavor_usage(
            logger,
            resources.usage,
            _fetch_instances,
            lambda raw_instance: raw_instance['InstanceType'],  # type: ignore[index,no-any-return]
            _update_instance_usage
        )

        if r_instances_usage.is_error:
            return Error(r_instances_usage.unwrap_error())

        # Inspect the subnet
        r_subnet = self._aws_command([
            'ec2', 'describe-subnets',
            '--filter', f'Name=subnet-id,Values={subnet_id}'
        ], commandname='aws.ec2-describe-subnets')

        if r_subnet.is_error:
            return Error(Failure.from_failure(
                'failed to fetch subnet information',
                r_subnet.unwrap_error()
            ))

        # Extract the total number of IPs...
        cidr = JQ_QUERY_SUBNET_CIDR.input(r_subnet.unwrap()).first()
        network = ipaddress.ip_network(cidr)

        # drop network address and broadcast
        resources.limits.networks[subnet_id] = PoolNetworkResources(addresses=network.num_addresses - 2)

        # .. and usage - AWS reports "available", but we want "usage", really.
        available_ips = JQ_QUERY_SUBNET_AVAILABLE_IPS.input(r_subnet.unwrap()).first()

        resources.usage.networks[subnet_id] = PoolNetworkResources(
            addresses=resources.limits.networks[subnet_id].addresses - available_ips
        )

        return Ok(resources)

    def _fetch_guest_console_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[
            Union[Tuple[None, None], Tuple[datetime.datetime, Optional[str]]],
            Failure]:
        pool_data = guest_request.pool_data.mine(self, AWSPoolData)

        # This can actually happen, spot instances may take some time to get the instance ID.
        if pool_data.instance_id is None:
            return Ok((None, None))

        r_output = self._aws_command([
            'ec2',
            'get-console-output',
            '--instance-id', pool_data.instance_id
        ], commandname='aws.ec2-get-console-output')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to fetch console output',
                r_output.unwrap_error()
            ))

        output = cast(Dict[str, str], r_output.unwrap())

        timestamp = datetime.datetime.strptime(output['Timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
        console_output = output.get('Output')

        return Ok((timestamp, console_output))

    @guest_log_updater('aws', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_dump_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Update console.dump/blob guest log.

        See [1] for console access details.

        [1] https://docs.aws.amazon.com/cli/latest/reference/ec2/get-console-output.html
        """

        r_output = self._fetch_guest_console_blob(logger, guest_request)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        timestamp, output = r_output.unwrap()

        progress = GuestLogUpdateProgress.from_snapshot(
            logger,
            guest_log,
            timestamp,
            output,
            lambda guest_log, timestamp, content, content_hash: timestamp in guest_log.blob_timestamps
        )

        progress.delay_update = KNOB_CONSOLE_DUMP_BLOB_UPDATE_TICK.value

        return Ok(progress)

    @guest_log_updater('aws', 'console:interactive', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Update console.interactive/url guest log.
        """

        pool_data = guest_request.pool_data.mine(self, AWSPoolData)

        # This can actually happen, spot instances may take some time to get the instance ID.
        if pool_data.instance_id is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.PENDING,
                delay_update=KNOB_CONSOLE_DUMP_BLOB_UPDATE_TICK.value
            ))

        # In AWS case only logged in users can access the console (1 session a time). The url has fixed format
        # depending on instance_id only, let's just generate it for every instance.
        output = KNOB_CONSOLE_INTERACTIVE_URL.value.format(instance_id=pool_data.instance_id)  # noqa: FS002

        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.COMPLETE,
            url=output
        ))

    def trigger_reboot(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        pool_data = guest_request.pool_data.mine_or_none(self, AWSPoolData)

        if not pool_data:
            return Ok(None)

        if pool_data.instance_id is None:
            return Error(Failure(
                'failed to trigger instance reboot without instance ID'
            ))

        r = self._aws_command([
            'ec2',
            'reboot-instances',
            '--instance-ids', pool_data.instance_id
        ], json_output=False, commandname='awc.ec2-reboot-instance')

        if r.is_error:
            return Error(Failure.from_failure(
                'failed to trigger instance reboot',
                r.unwrap_error()
            ))

        return Ok(None)


PoolDriver._drivers_registry['aws'] = AWSDriver
