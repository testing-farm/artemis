import base64
import dataclasses
import datetime
import ipaddress
import json
import os
import re
import threading
from typing import Any, Dict, List, MutableSequence, Optional, Pattern, Tuple, cast

import gluetool.log
import jq
import pint
import sqlalchemy.orm.session
from gluetool.log import log_dict
from gluetool.result import Error, Ok, Result
from gluetool.utils import normalize_bool_option
from jinja2 import Template
from typing_extensions import Literal, TypedDict

from .. import Failure, JSONType, SerializableContainer, get_cached_item, get_cached_items_as_list, log_dict_yaml
from ..context import CACHE
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..environment import UNITS, Flavor, FlavorCpu, FlavorVirtualization
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, GuestLogUpdateProgress, GuestTagsType, HookImageInfoMapper, \
    ImageInfoMapperOptionalResultType, PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, PoolImageSSHInfo, \
    PoolResourcesIDs, ProvisioningProgress, ProvisioningState, SerializedPoolResourcesIDs, run_cli_tool, \
    test_cli_error

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
APIBlockDeviceMappingEbsType = TypedDict(
    'APIBlockDeviceMappingEbsType',
    {
        'DeleteOnTermination': bool,
        'Encrypted': bool,
        'Iops': int,
        'KmsKeyId': str,
        'SnapshotId': str,
        'VolumeSize': int,
        'VolumeType': EBSVolumeTypeType
    },
    total=False
)


# Type of container holding block device mapping.
#
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-blockdev-mapping.html
APIBlockDeviceMappingType = TypedDict(
    'APIBlockDeviceMappingType',
    {
        'DeviceName': str,
        'Ebs': APIBlockDeviceMappingEbsType
    },
    total=True
)


# Type of container holding block device mappings.
#
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html
APIBlockDeviceMappingsType = List[APIBlockDeviceMappingType]


class APIImageType(TypedDict):
    Name: str
    ImageId: str
    PlatformDetails: str
    BlockDeviceMappings: APIBlockDeviceMappingsType
    EnaSupport: Optional[bool]


AWS_VM_HYPERVISORS = ('nitro', 'xen')


MISSING_INSTANCE_ERROR_PATTERN = re.compile(r'.+\(InvalidInstanceID\.NotFound\).+The instance ID \'.+\' does not exist')

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


class FailedSpotRequest(Failure):
    def __init__(
        self,
        message: str,
        spot_instance_id: str,
        **kwargs: Any
    ):
        super(FailedSpotRequest, self).__init__(message, **kwargs)
        self.spot_instance_id = spot_instance_id


@dataclasses.dataclass
class AWSPoolData(PoolData):
    instance_id: Optional[str] = None
    spot_instance_id: Optional[str] = None


@dataclasses.dataclass
class AWSPoolImageInfo(PoolImageInfo):
    #: Carries ``PlatformDetails`` field as provided by AWS image description.
    platform_details: str

    #: Carries ``BlockDeviceMappings`` field as provided by AWS image description.
    block_device_mappings: APIBlockDeviceMappingsType

    #: Carries `EnaSupport` field as provided by AWS image description.
    ena_support: bool

    def __repr__(self) -> str:
        return (
            '<AWSPoolImageInfo:'
            f' name={self.name}'
            f' id={self.id}'
            f' ssh={repr(self.ssh)}'
            f' platform-details={self.platform_details}'
            f' ena_support={self.ena_support}'
            '>'
        )

    def serialize_to_json_scrubbed(self) -> Dict[str, Any]:
        serialized = super(AWSPoolImageInfo, self).serialize_to_json_scrubbed()

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
        r_image = super(AWSHookImageInfoMapper, self).map_or_none(logger, guest_request)

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
        super(BlockDeviceMappings, self).__init__()

        self.data = mappings[:] if mappings else []

    # Abstract methods we need to define to keep types happy, since MutableSequence leaves them to us.
    def __delitem__(self, index: int) -> None:  # type: ignore  # does not match supertype, but it's correct
        del self.data[index]

    def __getitem__(  # type: ignore  # does not match supertype, but it's correct
        self,
        index: int
    ) -> APIBlockDeviceMappingType:
        return self.data[index]

    def __len__(self) -> int:
        return len(self.data)

    def __setitem__(  # type: ignore  # does not match supertype, but it's correct
        self,
        index: int,
        value: APIBlockDeviceMappingType
    ) -> None:
        self.data[index] = value

    def insert(self, index: int, value: APIBlockDeviceMappingType) -> None:
        self[index] = value

    # Override serialization - we're fine with quite a trivial approach.
    def serialize_to_json(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self.data)

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'BlockDeviceMappings':
        cast_serialized = cast(APIBlockDeviceMappingsType, serialized)

        return BlockDeviceMappings(cast_serialized)

    # These two methods would deserve their own class, representing a single block device mapping, but, because
    # such mapping isn't plain str/str dictionary, we would have to write so many checks and types to deal with
    # the variants. It's more readable to have them here, namespaced, rather than top-level functions.
    @staticmethod
    def create_mapping(
        device_name: str,
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[pint.Quantity] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Create block device mapping.

        All parameters except ``device_name`` are optional, and when not specified, their value in the device mapping
        will remain unset.

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
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[pint.Quantity] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Update given block device mapping.

        All parameters are optional, and when not specified, the value currently set in the block device mapping
        will remain unchanged.

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

    def append_mapping(
        self,
        device_name: str,
        delete_on_termination: Optional[bool] = None,
        encrypted: Optional[bool] = None,
        size: Optional[pint.Quantity] = None,
        volume_type: Optional[EBSVolumeTypeType] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        """
        Append new block device mapping.

        All parameters except ``device_name`` are optional, and when not specified, their value in the device mapping
        will remain unset.

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

    def set_root_disk_size(
        self,
        size: Optional[pint.Quantity] = None
    ) -> Result[APIBlockDeviceMappingType, Failure]:
        mapping = self._get_mapping(0)

        if mapping is None:
            return Error(Failure(
                'block device mapping does not exist',
                block_device_mappings=self.data,
                block_device_mapping_index=0
            ))

        return self.update_mapping(mapping, size=size)


class AWSDriver(PoolDriver):
    image_info_class = AWSPoolImageInfo
    flavor_info_class = AWSFlavor

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super(AWSDriver, self).__init__(logger, poolname, pool_config)
        self.environ = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": self.pool_config['access-key-id'],
            "AWS_SECRET_ACCESS_KEY": self.pool_config['secret-access-key'],
            "AWS_DEFAULT_REGION": self.pool_config['default-region'],
            "AWS_DEFAULT_OUTPUT": 'json'
        }

    # TODO: return value does not match supertype - it should, it does, but mypy ain't happy: why?
    @property
    def image_info_mapper(self) -> AWSHookImageInfoMapper:  # type: ignore  # does not match supertype
        return AWSHookImageInfoMapper(self, 'AWS_ENVIRONMENT_TO_IMAGE')

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

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_id: Optional[str] = None,
        spot_instance_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = AWSPoolResourcesIDs(instance_id=instance_id, spot_instance_id=spot_instance_id)

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = AWSPoolResourcesIDs.unserialize(raw_resource_ids)

        if resource_ids.spot_instance_id is not None:
            r_output = self._aws_command([
                'ec2', 'cancel-spot-instance-requests',
                f'--spot-instance-request-ids={resource_ids.spot_instance_id}'
            ], commandname='aws.ec2-cancel-spot-instance-requests')

            if r_output.is_error:
                return Error(r_output.unwrap_error())

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        if resource_ids.instance_id is not None:
            r_output = self._aws_command([
                'ec2', 'terminate-instances',
                f'--instance-ids={resource_ids.instance_id}'
            ], commandname='aws.ec2-terminate-instances')

            if r_output.is_error:
                return Error(r_output.unwrap_error())

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        return Ok(None)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        r_answer = super(AWSDriver, self).can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        r_image = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        if r_image.unwrap() is None:
            return Ok(False)

        r_type = self._env_to_instance_type(logger, session, guest_request)

        if r_type.is_error:
            return Error(r_type.unwrap_error())

        return Ok(True)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _env_to_instance_type(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[Flavor, Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = cast(List[AWSFlavor], r_suitable_flavors.unwrap())

        # console/URL logs require ENA support
        if guest_request.requests_guest_log('console', GuestLogContentType.URL):
            suitable_flavors = [
                flavor
                for flavor in suitable_flavors
                if flavor.ena_support in ('required', 'supported')
            ]

        if not suitable_flavors:
            guest_request.log_warning_event(
                logger,
                session,
                'no suitable flavors, using default'
            )

            return self._map_environment_to_flavor_info_by_cache_by_name(
                logger,
                self.pool_config['default-instance-type']
            )

        if self.pool_config['default-instance-type'] in [flavor.name for flavor in suitable_flavors]:
            logger.info('default flavor among suitable ones, using it')

            return Ok([
                flavor
                for flavor in suitable_flavors
                if flavor.name == self.pool_config['default-instance-type']
            ][0])

        return Ok(suitable_flavors[0])

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

        # command returned an unxpected result
        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(cast(List[Dict[str, Any]], r_output.unwrap())[0])

    def _aws_command(
        self,
        args: List[str],
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
            json_output=True,
            env=self.environ,
            poolname=self.poolname,
            commandname=commandname
        )

        if r_run.is_error:
            failure = r_run.unwrap_error()

            # Detect "instance does not exist" - this error is clearly irrecoverable. No matter how often we would
            # run this method, we would never evenr made it remove instance that doesn't exist.
            if test_cli_error(failure, MISSING_INSTANCE_ERROR_PATTERN):
                failure.recoverable = False

                PoolMetrics.inc_error(self.poolname, 'missing-instance')

            return Error(failure)

        output = r_run.unwrap()

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
            return Error(r_spot_price.unwrap_error())

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
            'instance type': instance_type.serialize_to_json(),
            'product description': image.platform_details,
            'bid': f'{spot_price_bid_percentage}%',
            'print': price
        })

        return Ok(price)

    def _create_block_device_mappings(
        self,
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

        mappings = BlockDeviceMappings(image.block_device_mappings)

        if flavor.disk and flavor.disk[0].size is not None:
            r_bdms = mappings.set_root_disk_size(flavor.disk[0].size)

            if r_bdms.is_error:
                return Error(r_bdms.unwrap_error())

        elif 'default-root-disk-size' in self.pool_config:
            r_bdms = mappings.set_root_disk_size(UNITS[f'{self.pool_config["default-root-disk-size"]} GiB'])

            if r_bdms.is_error:
                return Error(r_bdms.unwrap_error())

# TODO: once we merge all the pieces, we should be able to request additional storage, e.g.:
#
#        r_mapping = mappings.append_mapping(
#            '/dev/sdd',
#            delete_on_termination=True,
#            encrypted=False,
#            size=UNITS('120 GiB'),
#            volume_type='gp3'
#        )
#
#        if r_mapping.is_error:
#            return Error(r_mapping.unwrap_error())

        return Ok(mappings)

    def _request_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: Flavor,
        image: AWSPoolImageInfo,
        guestname: str
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

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

        r_block_device_mappings = self._create_block_device_mappings(image, instance_type)

        if r_block_device_mappings.is_error:
            return Error(r_block_device_mappings.unwrap_error())

        command.append(f'--block-device-mappings={r_block_device_mappings.unwrap().serialize_to_json()}')

        if 'additional-options' in self.pool_config:
            command.extend(self.pool_config['additional-options'])

        r_instance_request = self._aws_command(command, key='Instances', commandname='aws.ec2-run-instances')

        if r_instance_request.is_error:
            return Error(r_instance_request.unwrap_error())

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

        r_block_device_mappings = self._create_block_device_mappings(image, instance_type)

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
            block_device_mappings=r_block_device_mappings.unwrap().serialize_to_json()
        )

        log_dict_yaml(logger.info, 'spot request launch specification', json.loads(specification))

        r_spot_request = self._aws_command([
            'ec2', 'request-spot-instances',
            f'--spot-price={spot_price}',
            f'--launch-specification={" ".join(specification.split())}',
        ], key='SpotInstanceRequests', commandname='aws.ec2-request-spot-instances')

        if r_spot_request.is_error:
            return Error(r_spot_request.unwrap_error())

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

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=AWSPoolData.unserialize(guest_request),
                pool_failures=[Failure(
                    'spot instance terminated prematurely',
                    spot_instance_state=state,
                    spot_instance_status=status,
                    spot_instance_error=spot_instance['Status']['Message']
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

        # tag the instance if requested
        # TODO: move these into configuration. Before that, we need to add support for templates in tags, so we
        # could generate tags like `Name`. But it really belongs to configuration.
        tags: Dict[str, str] = {
            'Name': f'{instance["PrivateIpAddress"]}::{instance["ImageId"]}'
        }

        if pool_data.spot_instance_id is not None:
            tags['SpotRequestId'] = pool_data.spot_instance_id

        self._tag_instance(logger, session, guest_request, instance, owner, tags=tags)

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

    def _tag_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance: Dict[str, Any],
        owner: str,
        tags: Optional[GuestTagsType] = None
    ) -> None:
        base_tags = self.get_guest_tags(session, guest_request)

        # TODO: this is a huge problem, AWS driver tends to ignore many of possible errors, we need to fix that
        # so we can propagate issues like this one upwards.
        if base_tags.is_error:
            return

        tags = {
            **base_tags.unwrap(),
            **(tags if tags is not None else {})
        }

        if not tags:
            self.debug('Skipping tagging as no tags specified.')
            return

        # we need ARN of the instance for tagging
        # region can be transformed from availability zone by omiting the last character
        arn = f'arn:aws:ec2:{self.pool_config["availability-zone"][:-1]}:{owner}:instance/{instance["InstanceId"]}'

        r_tag = self._aws_command([
            'resourcegroupstaggingapi',
            'tag-resources',
            '--resource-arn-list', arn,
            '--tags', ','.join([f'{tag}={value}' for tag, value in tags.items()])
        ], commandname='aws.resourcegroupstaggingapi-tag-resources')

        # do not fail if failed to tag
        if r_tag.is_error:
            failure = r_tag.unwrap_error()

            failure.update(
                arn=arn,
                tags=tags
            )

            failure.handle(logger, 'failed to tag AWS instance')

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

        # get instance type from environment
        r_instance_type = self._env_to_instance_type(logger, session, guest_request)
        if r_instance_type.is_error:
            return Error(r_instance_type.unwrap_error())

        instance_type = r_instance_type.unwrap()

        # find out image from enviroment
        r_image = self.image_info_mapper.map(logger, guest_request)

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

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

        return self._request_instance(logger, instance_type, image, guest_request.guestname)

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if AWSPoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = AWSPoolData.unserialize(guest_request)

        if pool_data.instance_id is None and pool_data.spot_instance_id is None:
            return Error(Failure('guest has no identification'))

        r_cleanup = self._dispatch_resource_cleanup(
            logger,
            instance_id=pool_data.instance_id,
            spot_instance_id=pool_data.spot_instance_id,
            guest_request=guest_request
        )

        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())

        return Ok(True)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        r_images = self._aws_command(
            ['ec2', 'describe-images', '--owner=self'],
            key='Images',
            commandname='aws.ec2-describe-images'
        )

        if r_images.is_error:
            return Error(r_images.unwrap_error())

        try:
            return Ok([
                AWSPoolImageInfo(
                    name=image['Name'],
                    id=image['ImageId'],
                    ssh=PoolImageSSHInfo(),
                    platform_details=image['PlatformDetails'],
                    block_device_mappings=image['BlockDeviceMappings'],
                    # some AMI lack this field, and we need to make sure it's really a boolean, not `null` or `None`
                    ena_support=image.get('EnaSupport', False) or False
                )
                for image in cast(List[APIImageType], r_images.unwrap())
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed image description',
                exc,
                image_info=r_images.unwrap()
            ))

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
        # See AWS docs: https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-types.html

        r_flavors = self._aws_command(
            ['ec2', 'describe-instance-types'],
            key='InstanceTypes',
            commandname='aws.ec2-describe-instance-types'
        )

        if r_flavors.is_error:
            return Error(r_flavors.unwrap_error())

        if self.pool_config.get('flavor-regex'):
            flavor_name_pattern: Optional[Pattern[str]] = re.compile(self.pool_config['flavor-regex'])

        else:
            flavor_name_pattern = None

        try:
            return Ok([
                AWSFlavor(
                    name=flavor['InstanceType'],
                    id=flavor['InstanceType'],
                    cpu=FlavorCpu(
                        cores=int(flavor['VCpuInfo']['DefaultVCpus'])
                    ),
                    # memory is reported in MB
                    memory=int(flavor['MemoryInfo']['SizeInMiB']) * UNITS.mebibytes,
                    virtualization=FlavorVirtualization(
                        hypervisor=flavor.get('Hypervisor', None),
                        is_virtualized=True if flavor.get('Hypervisor', '').lower() in AWS_VM_HYPERVISORS else False
                    ),
                    ena_support=flavor.get('NetworkInfo', {}).get('EnaSupport', 'unsupported')
                )
                for flavor in cast(List[Dict[str, Any]], r_flavors.unwrap())
                if flavor_name_pattern is None or flavor_name_pattern.match(flavor['InstanceType'])
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed flavor description',
                exc,
                flavor_info=r_flavors.unwrap()
            ))

    def get_cached_pool_flavor_info(self, flavorname: str) -> Result[Optional[Flavor], Failure]:
        return get_cached_item(CACHE.get(), self.flavor_info_cache_key, flavorname, AWSFlavor)

    def get_cached_pool_flavor_infos(self) -> Result[List[Flavor], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return get_cached_items_as_list(CACHE.get(), self.flavor_info_cache_key, AWSFlavor)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        # TODO: Extract usage of components - CPU cores, memory, disk space - but that might be much harder.
        # TODO: Or even pointless and not needed.

        subnet_id = self.pool_config['subnet-id']

        r_resources = super(AWSDriver, self).fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        # Count instances - only those using our subnet
        r_instances = self._aws_command([
            'ec2', 'describe-instances',
            '--filter', f'Name=subnet-id,Values={subnet_id}'
        ], commandname='aws.ec2-describe-instances')

        if r_instances.is_error:
            return Error(r_instances.unwrap_error())

        try:
            resources.usage.instances = len(JQ_QUERY_POOL_INSTANCES.input(r_instances.unwrap()).all())

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
            return Error(r_subnet.unwrap_error())

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

    def update_guest_log(
        self,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        if guest_log.logname != 'console' or guest_log.contenttype not in [GuestLogContentType.URL, GuestLogContentType.BLOB]:  # noqa: E501
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.ERROR
            ))

        pool_data = AWSPoolData.unserialize(guest_request)
        # This can actually happen, spot instances may take some time to get the instance ID.
        if pool_data.instance_id is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.PENDING,
                delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
            ))

        if guest_log.contenttype == GuestLogContentType.BLOB:
            # We're left with console/blob.

            # According to [1], there are two options:
            #
            # * cached, buffered blob stored after the most recent transition state of the instance (start, stop, ...)
            # * the "latest output" - which is available only for instances powered by Nitro.
            #
            # Since we're not yet familiar with Nitro instances, and the driver can't really track this bit of
            # information and tell the difference, let's start with fetching the cached blob,
            # and possibly merging them if they change, to capture logs across reboots.
            #
            # [1] https://docs.aws.amazon.com/cli/latest/reference/ec2/get-console-output.html

            r_output = self._aws_command([
                'ec2',
                'get-console-output',
                '--instance-id', pool_data.instance_id
            ], commandname='aws.ec2-get-console-output')

            if r_output.is_error:
                return Error(r_output.unwrap_error())

            output = cast(str, JQ_QUERY_CONSOLE_OUTPUT.input(r_output.unwrap()).first())

            # TODO logs: do some sort of magic to find out whether the blob we just got is already in DB.
            # Maybe use difflib, or use delimiters and timestamps. We do not want to overide what we already have.

            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.IN_PROGRESS,
                # TODO logs: well, this *is* overwriting what we already downloaded... Do something.
                blob=output,
                delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
            ))

        else:
            # Dealing with a console url. In AWS case only logged in users can access the console (1 session a time).
            # The url has fixed format depending on instance_id only, let's just generate it for every instance.
            output = KNOB_CONSOLE_EC2_URL.value.format(instance_id=pool_data.instance_id)  # noqa: FS002

            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.COMPLETE,
                url=output
            ))
