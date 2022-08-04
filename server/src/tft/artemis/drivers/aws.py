# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import base64
import dataclasses
import datetime
import ipaddress
import json
import os
import re
import threading
from typing import Any, Dict, Generator, List, MutableSequence, Optional, Pattern, Tuple, cast

import gluetool.log
import gluetool.utils
import jq
import pint
import sqlalchemy.orm.session
from gluetool.log import ContextAdapter, log_dict
from gluetool.result import Error, Ok, Result
from gluetool.utils import normalize_bool_option
from jinja2 import Template
from pint import Quantity
from typing_extensions import Literal, TypedDict

from .. import Failure, JSONType, SerializableContainer, log_dict_yaml, logging_filter, process_output_to_str
from ..cache import get_cached_set_as_list, get_cached_set_item
from ..context import CACHE
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..environment import UNITS, Constraint, ConstraintBase, Flavor, FlavorBoot, FlavorBootMethodType, FlavorCpu, \
    FlavorVirtualization, Operator
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, CLIErrorCauses, GuestLogUpdateProgress, GuestTagsType, \
    HookImageInfoMapper, ImageInfoMapperOptionalResultType, PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, \
    PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, ProvisioningState, SerializedPoolResourcesIDs, \
    guest_log_updater, run_cli_tool

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


class APIImageType(TypedDict):
    Name: Optional[str]
    ImageId: str
    Architecture: str
    PlatformDetails: str
    BlockDeviceMappings: APIBlockDeviceMappingsType
    EnaSupport: Optional[bool]


AWS_VM_HYPERVISORS = ('nitro', 'xen')


class AWSCLIErrorCauses(CLIErrorCauses):
    NONE = 'none'
    MISSING_INSTANCE = 'missing-instance'
    MISSING_SPOT_INSTANCE_REQUEST = 'missing-spot-instance-request'
    REQUEST_LIMIT_EXCEEDED = 'request-limit-exceeded'


CLI_ERROR_PATTERNS = {
    AWSCLIErrorCauses.MISSING_INSTANCE: re.compile(
        r'.+\(InvalidInstanceID\.NotFound\).+The instance ID \'.+\' does not exist'
    ),
    AWSCLIErrorCauses.MISSING_SPOT_INSTANCE_REQUEST: re.compile(
        r'.+\(InvalidSpotInstanceRequestID\.NotFound\).+The spot instance request ID \'.+\' does not exist'
    ),
    AWSCLIErrorCauses.REQUEST_LIMIT_EXCEEDED: re.compile(
        r'.+\(RequestLimitExceeded\).+Request limit exceeded'
    )
}


def awscli_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> AWSCLIErrorCauses:
    if output.exit_code == 0:
        return AWSCLIErrorCauses.NONE

    stderr = process_output_to_str(output, stream='stderr')

    if stderr is None:
        return AWSCLIErrorCauses.NONE

    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if not pattern.match(stderr):
            continue

        return cause

    return AWSCLIErrorCauses.NONE


AWS_INSTANCE_SPECIFICATION = Template("""
{
  "ImageId": "{{ ami_id }}",
  "KeyName": "{{ key_name }}",
  "InstanceType": "{{ instance_type.id }}",
  "Placement": {
    "AvailabilityZone": "{{ availability_zone }}"
  },
  "NetworkInterfaces": [
    {
      "DeviceIndex": 0,
      "SubnetId": "{{ subnet_id }}",
      "DeleteOnTermination": true,
      "Groups": [
        "{{ security_group }}"
      ],
      "AssociatePublicIpAddress": false
    }
  ],
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

KNOB_CONSOLE_BLOB_UPDATE_TICK: Knob[int] = Knob(
    'aws.console.blob.expires',
    'How long, in seconds, to take between updating guest console log.',
    has_db=False,
    envvar='ARTEMIS_AWS_CONSOLE_BLOB_UPDATE_TICK',
    cast_from_str=int,
    default=30
)

KNOB_CONSOLE_EC2_URL: Knob[str] = Knob(
    'aws.console.ec2.url',
    'Templated URL of serial console of an AWS EC2 instance.',
    has_db=False,
    envvar='ARTEMIS_AWS_CONSOLE_EC2_URL',
    cast_from_str=str,
    default="https://console.aws.amazon.com/ec2/v2/connect/ec2-user/{instance_id}?connection-type=isc&serial-port=0"  # noqa: FS003,E501
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'aws.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_AWS_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-aws.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'aws.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_AWS_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
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


@dataclasses.dataclass(repr=False)
class AWSPoolImageInfo(PoolImageInfo):
    #: Carries ``PlatformDetails`` field as provided by AWS image description.
    platform_details: str

    #: Carries ``BlockDeviceMappings`` field as provided by AWS image description.
    block_device_mappings: APIBlockDeviceMappingsType

    #: Carries `EnaSupport` field as provided by AWS image description.
    ena_support: bool

    def serialize_scrubbed(self) -> Dict[str, Any]:
        serialized = super().serialize_scrubbed()

        for bd_mapping in serialized['block_device_mappings']:
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


class AWSHookImageInfoMapper(HookImageInfoMapper[AWSPoolImageInfo]):
    def map_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> ImageInfoMapperOptionalResultType[AWSPoolImageInfo]:
        r_image = super().map_or_none(logger, guest_request)

        if r_image.is_error:
            return r_image

        image = r_image.unwrap()

        if image is None:
            return r_image

        # console/URL logs require ENA support
        if guest_request.requests_guest_log('console', GuestLogContentType.URL) and not image.ena_support:
            return Ok(None)

        return r_image


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

    # These two methods would deserve their own class, representing a single block device mapping, but, because
    # such mapping isn't plain str/str dictionary, we would have to write so many checks and types to deal with
    # the variants. It's more readable to have them here, namespaced, rather than top-level functions.
    @staticmethod
    def create_mapping(
        device_name: str,
        # common volume properties
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[pint.Quantity] = None,
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
        size: Optional[pint.Quantity] = None,
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
        size: Optional[pint.Quantity] = None,
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
        size: Optional[pint.Quantity] = None,
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
        size: Optional[pint.Quantity] = None,
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

    property_name, index, child_property_name = constraint.expand_name()

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

        if constraint.operator in (Operator.EQ, Operator.GTE):
            r_update = mappings.update_mapping(
                mapping,
                size=constraint.value
            )

            if r_update.is_error:
                return Error(r_update.unwrap_error())

        elif constraint.operator == Operator.GT:
            r_update = mappings.update_mapping(
                mapping,
                size=constraint.value + UNITS.Quantity(1, 'gibibyte')
            )

            if r_update.is_error:
                return Error(r_update.unwrap_error())

        else:
            return Error(Failure('cannot honor constraint', constraint=str(constraint)))

        log_dict_yaml(logger.debug, '  mappings after', mappings.serialize())

        return Ok(True)

    return Ok(False)


def _get_constraint_spans(
    logger: ContextAdapter,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor
) -> Result[List[List[ConstraintBase]], Failure]:
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

    assert pruned_constraints is not None

    spans = list(pruned_constraints.spans(logger))

    for i, span in enumerate(spans):
        log_dict_yaml(logger.debug, f'span #{i}', [str(constraint) for constraint in span])

    return Ok(spans)


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

    r_spans = _get_constraint_spans(logger, guest_request, image, flavor)

    if r_spans.is_error:
        return Error(r_spans.unwrap_error())

    spans = r_spans.unwrap()

    if not spans:
        return Ok(mappings)

    # TODO: this could be a nice algorithm, picking the best span instead of the first one.
    span = cast(List[Constraint], spans[0])

    log_dict_yaml(logger.debug, 'selected span', [str(constraint) for constraint in span])

    for constraint in span:
        logger.debug(f'  {constraint}')

        property_name, _, _ = (constraint.original_constraint or constraint).expand_name()

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
            'cannot honor constraint',
            constraint=repr(constraint)
        ))

    return Ok(mappings)


def setup_root_volume(
    logger: ContextAdapter,
    mappings: BlockDeviceMappings,
    guest_request: GuestRequest,
    image: AWSPoolImageInfo,
    flavor: Flavor,
    default_root_disk_size: Optional[pint.Quantity] = None,
    # common volume properties
    delete_on_termination: Optional[bool] = None,
    encrypted: Optional[bool] = None,
    size: Optional[pint.Quantity] = None,
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
    default_root_disk_size: Optional[Quantity] = None
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

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_native_post_install_script = True
        capabilities.supported_guest_logs = [
            ('console', GuestLogContentType.URL),
            ('console', GuestLogContentType.BLOB)
        ]

        return Ok(capabilities)

    def sanity(self) -> Result[bool, Failure]:
        required_variables = [
            'access-key-id',
            'secret-access-key',
            'default-region',
            'availability-zone',
            'command',
            'default-instance-type',
            'master-key-name',
            'security-group',
            'subnet-id'
        ]

        for variable in required_variables:
            if variable not in self.pool_config:
                return Error(Failure(f"Required variable '{variable}' not found in pool configuration"))

        return Ok(True)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
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

        return Ok(None)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        r_image = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        if image is None:
            return Ok(False)

        r_type = self._env_to_instance_type_or_none(logger, session, guest_request, image)

        if r_type.is_error:
            return Error(r_type.unwrap_error())

        if r_type.unwrap() is None:
            return Ok(False)

        return Ok(True)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _env_to_instance_type_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: AWSPoolImageInfo
    ) -> Result[Optional[Flavor], Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = cast(List[AWSFlavor], r_suitable_flavors.unwrap())

        if image.arch:
            suitable_flavors = list(logging_filter(
                logger,
                suitable_flavors,
                'image and flavor arch matches',
                lambda logger, flavor: flavor.arch == image.arch
            ))

        # console/URL logs require ENA support
        if guest_request.requests_guest_log('console', GuestLogContentType.URL):
            suitable_flavors = list(logging_filter(
                logger,
                suitable_flavors,
                'console requires ENA',
                lambda logger, flavor: flavor.ena_support in ('required', 'supported')
            ))

        # Make sure that, if image does not support ENA, we drop all flavors that require the support
        suitable_flavors = list(logging_filter(
            logger,
            suitable_flavors,
            'image and flavor ENA compatibility',
            lambda logger, flavor: not (flavor.ena_support == 'required' and image.ena_support is not True)
        ))

        # Make sure that, if image supports a particular boot method only, we drop all flavors that do not support it
        if image.boot.method:
            suitable_flavors = list(logging_filter(
                logger,
                suitable_flavors,
                'image boot method is supported',
                lambda logger, flavor: image.boot.method[0] in flavor.boot.method
            ))

        if not suitable_flavors:
            if self.pool_config.get('use-default-flavor-when-no-suitable', True):
                guest_request.log_warning_event(
                    logger,
                    session,
                    'no suitable flavors, using default',
                    poolname=self.poolname
                )

                return self._map_environment_to_flavor_info_by_cache_by_name_or_none(
                    logger,
                    self.pool_config['default-instance-type']
                )

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
    ) -> Result[Flavor, Failure]:
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
            f'--instance-id={AWSPoolData.unserialize(guest_request).instance_id}'
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
            f'--spot-instance-request-ids={AWSPoolData.unserialize(guest_request).spot_instance_id}'
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

                if cause in (AWSCLIErrorCauses.MISSING_INSTANCE, AWSCLIErrorCauses.MISSING_SPOT_INSTANCE_REQUEST):
                    failure.recoverable = False

                    PoolMetrics.inc_error(self.poolname, cause.value)

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

        except KeyError:
            PoolMetrics.inc_error(self.poolname, 'spot-price-not-detected')

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

        default_root_disk_size: Optional[Quantity] = None

        if 'default-root-disk-size' in self.pool_config:
            default_root_disk_size = UNITS.Quantity(self.pool_config["default-root-disk-size"], UNITS.gibibytes)

        return create_block_device_mappings(
            logger,
            guest_request,
            image,
            flavor,
            default_root_disk_size=default_root_disk_size
        )

    def _request_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_type: Flavor,
        image: AWSPoolImageInfo
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        command = [
            'ec2', 'run-instances',
            '--image-id', image.id,
            '--key-name', self.pool_config['master-key-name'],
            '--instance-type', instance_type.id
        ]

        if 'subnet-id' in self.pool_config:
            command.extend(['--subnet-id', self.pool_config['subnet-id']])

        if 'security-group' in self.pool_config:
            command.extend(['--security-group-ids', self.pool_config['security-group']])

        r_block_device_mappings = self._create_block_device_mappings(logger, guest_request, image, instance_type)

        if r_block_device_mappings.is_error:
            return Error(r_block_device_mappings.unwrap_error())

        command.extend([
            '--block-device-mappings',
            r_block_device_mappings.unwrap().serialize_to_json()
        ])

        if 'additional-options' in self.pool_config:
            command.extend(self.pool_config['additional-options'])

        tags = r_base_tags.unwrap()

        if tags:
            command += [
                '--tag-specifications'
            ] + _tags_to_tag_specifications(tags, 'instance', 'volume')

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
            pool_data=AWSPoolData(instance_id=instance_id),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _request_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_type: Flavor,
        image: AWSPoolImageInfo
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        # find our spot instance prices for the instance_type in our availability zone
        r_price = self._get_spot_price(logger, instance_type, image)
        if r_price.is_error:
            # _get_spot_price has different return value, we cannot return it as it is
            return Error(r_price.unwrap_error())

        spot_price = r_price.unwrap()

        if guest_request.post_install_script:
            # NOTE(ivasilev) Encoding is needed as base62.b64encode() requires bytes object per py3 specification,
            # and decoding is getting us the expected str back.
            user_data = base64.b64encode(guest_request.post_install_script.encode('utf-8')).decode('utf-8')
        else:
            post_install_script_file = self.pool_config.get('post-install-script')
            if post_install_script_file:
                # path to a post-install-script is defined in the pool and isn't a default empty string
                with open(post_install_script_file) as f:
                    user_data = base64.b64encode(f.read().encode('utf8')).decode('utf-8')
            else:
                user_data = ""

        r_block_device_mappings = self._create_block_device_mappings(logger, guest_request, image, instance_type)

        if r_block_device_mappings.is_error:
            return Error(r_block_device_mappings.unwrap_error())

        specification = AWS_INSTANCE_SPECIFICATION.render(
            ami_id=image.id,
            key_name=self.pool_config['master-key-name'],
            instance_type=instance_type,
            availability_zone=self.pool_config['availability-zone'],
            subnet_id=self.pool_config['subnet-id'],
            security_group=self.pool_config['security-group'],
            user_data=user_data,
            block_device_mappings=r_block_device_mappings.unwrap().serialize()
        )

        log_dict_yaml(logger.info, 'spot request launch specification', json.loads(specification))

        command = [
            'ec2', 'request-spot-instances',
            f'--spot-price={spot_price}',
            f'--launch-specification={" ".join(specification.split())}'
        ]

        tags = r_base_tags.unwrap()

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
            pool_data=AWSPoolData(spot_instance_id=spot_instance_id),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _do_update_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        pool_data = AWSPoolData.unserialize(guest_request)

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
                    spot_instance_id=pool_data.spot_instance_id
                ),
                delay_update=r_delay.unwrap()
            ))

        if state == 'open':
            if is_old_enough(logger, spot_instance['CreateTime'], KNOB_SPOT_OPEN_TIMEOUT.value):
                PoolMetrics.inc_error(self.poolname, 'instance-building-too-long')

                return Ok(ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=AWSPoolData.unserialize(guest_request),
                    pool_failures=[Failure('spot instance stuck in "open" for too long')]
                ))

        if state in ('cancelled', 'failed', 'closed', 'disabled'):
            PoolMetrics.inc_error(self.poolname, 'spot-instance-terminated-prematurely')

            spot_instance_fault = spot_instance.get('Fault', {})

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=AWSPoolData.unserialize(guest_request),
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
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_output = self._describe_instance(guest_request)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        instance, owner = r_output.unwrap()

        state = instance['State']['Name']

        pool_data = AWSPoolData.unserialize(guest_request)

        assert pool_data.instance_id is not None

        logger.info(f'current instance state {pool_data.instance_id}:{state}')

        # EC2 instance lifecycle documentation
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html

        if state == 'terminated' or state == 'shutting-down':
            PoolMetrics.inc_error(self.poolname, 'instance-terminated-prematurely')

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=AWSPoolData.unserialize(guest_request),
                pool_failures=[Failure('instance terminated prematurely')]
            ))

        if state == 'pending':
            if is_old_enough(logger, instance['LaunchTime'], KNOB_PENDING_TIMEOUT.value):
                PoolMetrics.inc_error(self.poolname, 'instance-building-too-long')

                return Ok(ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=AWSPoolData.unserialize(guest_request),
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
                r_output.unwrap_error().update(
                    tags=tags,
                    resource_ids=taggable_resource_ids
                )
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=pool_data,
            address=instance['PrivateIpAddress']
        ))

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        pool_data = AWSPoolData.unserialize(guest_request)

        # If there is a spot instance request, check its state. If it's complete, the pool data would be updated
        # with freshly known instance ID - next time we're asked for update, we would proceed to check the state
        # of this instance, no longer checking the spot request since `pool_data.instance_id` would be set by then.

        if pool_data.instance_id is None:
            return self._do_update_spot_instance(logger, guest_request)

        return self._do_update_instance(logger, session, guest_request)

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
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key to upload to the guest.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """
        return self._do_acquire_guest(
            logger,
            session,
            guest_request,
            cancelled
        )

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        # find out image from enviroment
        r_image = self.image_info_mapper.map(logger, guest_request)

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        # get instance type from environment
        r_instance_type = self._env_to_instance_type(logger, session, guest_request, image)
        if r_instance_type.is_error:
            return Error(r_instance_type.unwrap_error())

        instance_type = r_instance_type.unwrap()

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

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if AWSPoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = AWSPoolData.unserialize(guest_request)

        resource_ids: List[AWSPoolResourcesIDs] = []

        # Prevent "double free" error by using a sequence: if we succeed freeing the instance,
        # we no longer try to free it in the case of retries, we'd focus on spot request only.
        if pool_data.instance_id is not None:
            resource_ids.append(AWSPoolResourcesIDs(instance_id=pool_data.instance_id))

        if pool_data.spot_instance_id is not None:
            resource_ids.append(AWSPoolResourcesIDs(spot_instance_id=pool_data.spot_instance_id))

        if not resource_ids:
            return Error(Failure('guest has no identification'))

        r_cleanup = self.dispatch_resource_cleanup(logger, *resource_ids, guest_request=guest_request)

        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())

        return Ok(True)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        if self.pool_config.get('image-regex'):
            image_name_pattern: Optional[Pattern[str]] = re.compile(self.pool_config['image-regex'])

        else:
            image_name_pattern = None

        def _fetch_images(name_filter: Optional[str] = None) -> Result[List[PoolImageInfo], Failure]:
            cli_options = [
                'ec2',
                'describe-images',
                '--owners'
            ] + self._image_owners

            if name_filter is not None:
                cli_options += [
                    '--filter', f'Name=name,Values={name_filter}'
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
                if image_name_pattern is not None \
                   and not image_name_pattern.match(image.get('Name') or image['ImageId']):
                    continue

                try:
                    aws_boot_method = cast(Optional[str], JQ_QUERY_IMAGE_SUPPORTED_BOOT_MODE.input(image).first())

                except Exception as exc:
                    return Error(Failure.from_exc(
                        'failed to parse AWS output',
                        exc
                    ))

                if aws_boot_method:
                    image_boot = FlavorBoot(method=[_aws_boot_to_boot(aws_boot_method)])

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
                        platform_details=image['PlatformDetails'],
                        block_device_mappings=image['BlockDeviceMappings'],
                        # some AMI lack this field, and we need to make sure it's really a boolean, not `null` or `None`
                        ena_support=image.get('EnaSupport', False) or False
                    ))

                except KeyError as exc:
                    return Error(Failure.from_exc(
                        'malformed image description',
                        exc,
                        image_info=r_images.unwrap()
                    ))

            return Ok(images)

        images: List[PoolImageInfo] = []
        # As a default, use `[None]` - if image-name-filter is not specified, we'd iterate at least
        # once with name_filter=None thanks to this, simplifying the code.
        image_filters = cast(List[Optional[str]], self.pool_config.get('image-name-filters', [None]))

        for name_filter in image_filters:
            r_images = _fetch_images(name_filter=name_filter)

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

        r_flavors = self._aws_command(
            ['ec2', 'describe-instance-types'],
            key='InstanceTypes',
            commandname='aws.ec2-describe-instance-types'
        )

        if r_flavors.is_error:
            return Error(Failure.from_failure(
                'failed to fetch instance type information',
                r_flavors.unwrap_error()
            ))

        if self.pool_config.get('flavor-regex'):
            flavor_name_pattern: Optional[Pattern[str]] = re.compile(self.pool_config['flavor-regex'])

        else:
            flavor_name_pattern = None

        flavors: List[Flavor] = []

        # Here we covert instance types retrieved from API into flavors. We filter out instance types
        # whose names don't match a flavor name patter, if specified. Then we take a look at architectures
        # supported by instance type, and create distinct flavors for each architecture. That way, we can
        # have pools supporting more than one architecture, and let Artemis match flavors and requestes
        # based on their attributes, not because maintainers "hide" the instance types with wrong parameters.
        try:
            for flavor in cast(List[Dict[str, Any]], r_flavors.unwrap()):
                if flavor_name_pattern is not None and not flavor_name_pattern.match(flavor['InstanceType']):
                    continue

                for arch in cast(APIInstanceTypeProcessorInfo, flavor['ProcessorInfo'])['SupportedArchitectures']:
                    artemis_arch = _aws_arch_to_arch(arch)

                    if not capabilities.supports_arch(artemis_arch):
                        continue

                    try:
                        boot_methods: List[FlavorBootMethodType] = [
                            _aws_boot_to_boot(boot_method)
                            for boot_method in JQ_QUERY_FLAVOR_SUPPORTED_BOOT_MODES.input(flavor).all()
                        ]

                    except Exception as exc:
                        return Error(Failure.from_exc(
                            'failed to parse AWS output',
                            exc
                        ))

                    flavors.append(AWSFlavor(
                        name=flavor['InstanceType'],
                        id=flavor['InstanceType'],
                        arch=artemis_arch,
                        boot=FlavorBoot(method=boot_methods),
                        cpu=FlavorCpu(
                            cores=int(flavor['VCpuInfo']['DefaultVCpus'])
                        ),
                        # memory is reported in MB
                        memory=UNITS.Quantity(int(flavor['MemoryInfo']['SizeInMiB']), UNITS.mebibytes),
                        virtualization=FlavorVirtualization(
                            hypervisor=flavor.get('Hypervisor', None),
                            is_virtualized=True if flavor.get('Hypervisor', '').lower() in AWS_VM_HYPERVISORS else False
                        ),
                        ena_support=flavor.get('NetworkInfo', {}).get('EnaSupport', 'unsupported')
                    ))

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed flavor description',
                exc,
                flavor_info=r_flavors.unwrap()
            ))

        return Ok(flavors)

    def get_cached_pool_flavor_info(self, flavorname: str) -> Result[Optional[Flavor], Failure]:
        return get_cached_set_item(CACHE.get(), self.flavor_info_cache_key, flavorname, AWSFlavor)

    def get_cached_pool_flavor_infos(self) -> Result[List[Flavor], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return get_cached_set_as_list(CACHE.get(), self.flavor_info_cache_key, AWSFlavor)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        subnet_id = self.pool_config['subnet-id']

        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        r_flavors = self.get_cached_pool_flavor_infos()

        if r_flavors.is_error:
            return Error(r_flavors.unwrap_error())

        flavors = {
            flavor.name: flavor
            for flavor in r_flavors.unwrap()
        }

        # Count instances - only those using our subnet
        r_instances = self._aws_command([
            'ec2', 'describe-instances',
            '--filter', f'Name=subnet-id,Values={subnet_id}'
        ], commandname='aws.ec2-describe-instances')

        if r_instances.is_error:
            return Error(Failure.from_failure(
                'failed to fetch instance information',
                r_instances.unwrap_error()
            ))

        resources.usage.instances = 0
        resources.usage.cores = 0
        resources.usage.memory = 0

        try:
            for instance_info in JQ_QUERY_POOL_INSTANCES.input(r_instances.unwrap()).all():
                resources.usage.instances += 1

                flavor = flavors.get(instance_info['InstanceType'])

                # This may happen, with multiple pools with different flavors using the same credentials
                # and overlapping subnets.
                if flavor is None:
                    logger.warning(f'flavor {instance_info["InstanceType"]} not cached')
                    continue

                resources.usage.cores += flavor.cpu.cores or 0
                resources.usage.memory += flavor.memory.to('bytes').magnitude if flavor.memory is not None else 0

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse AWS output',
                exc
            ))

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

    @guest_log_updater('aws', 'console', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Update console/blob guest log.

        According to [1], there are two options:

        * cached, buffered blob stored after the most recent transition state of the instance (start, stop, ...),
        * the "latest output" - which is available only for instances powered by Nitro.

        Since we're not yet familiar with Nitro instances, and the driver can't really track this bit of
        information and tell the difference, let's start with fetching the cached blob,
        and possibly merging them if they change, to capture logs across reboots.

        [1] https://docs.aws.amazon.com/cli/latest/reference/ec2/get-console-output.html
        """

        pool_data = AWSPoolData.unserialize(guest_request)

        # This can actually happen, spot instances may take some time to get the instance ID.
        if pool_data.instance_id is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.PENDING,
                delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
            ))

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

        output = cast(str, JQ_QUERY_CONSOLE_OUTPUT.input(r_output.unwrap()).first())

        # TODO logs: do some sort of magic to find out whether the blob we just got is already in DB.
        # Maybe use difflib, or use delimiters and timestamps. We do not want to overide what we already have.

        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.IN_PROGRESS,
            # TODO logs: well, this *is* overwriting what we already downloaded... Do something.
            blob=output,
            delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
        ))

    @guest_log_updater('aws', 'console', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Update console/url guest log.
        """

        pool_data = AWSPoolData.unserialize(guest_request)

        # This can actually happen, spot instances may take some time to get the instance ID.
        if pool_data.instance_id is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.PENDING,
                delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
            ))

        # In AWS case only logged in users can access the console (1 session a time). The url has fixed format
        # depending on instance_id only, let's just generate it for every instance.
        output = KNOB_CONSOLE_EC2_URL.value.format(instance_id=pool_data.instance_id)  # noqa: FS002

        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.COMPLETE,
            url=output
        ))


PoolDriver._drivers_registry['aws'] = AWSDriver
