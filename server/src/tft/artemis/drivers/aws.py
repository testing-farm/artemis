import base64
import dataclasses
import json
import os
import re
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.log import log_blob, log_dict
from gluetool.result import Error, Ok, Result
from gluetool.utils import normalize_bool_option, wait
from jinja2 import Template

from .. import Failure, JSONType, Knob
from ..db import GuestRequest, SSHKey
from ..environment import Environment
from ..script import hook_engine
from . import GuestTagsType, PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, PoolResourcesIDs, \
    ProvisioningProgress, ProvisioningState, SerializedPoolResourcesIDs, run_cli_tool, test_cli_error

#
# Custom typing types
#
BlockDeviceMappingsType = List[Dict[str, Any]]
InstanceOwnerType = Tuple[Dict[str, Any], str]

MISSING_INSTANCE_ERROR_PATTERN = re.compile(r'.+\(InvalidInstanceID\.NotFound\).+The instance ID \'.+\' does not exist')

AWS_INSTANCE_SPECIFICATION = Template("""
{
  "ImageId": "{{ ami_id }}",
  "KeyName": "{{ key_name }}",
  "InstanceType": "{{ instance_type }}",
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

#: How long, in seconds, is an instance allowed to stay in `pending` state until cancelled and reprovisioned.
KNOB_PENDING_TIMEOUT: Knob[int] = Knob(
    'aws.pending-timeout',
    has_db=False,
    envvar='ARTEMIS_AWS_PENDING_TIMEOUT',
    envvar_cast=int,
    default=600
)

#: A delay, in seconds, between two calls of `update-guest-request` checking provisioning progress.
KNOB_UPDATE_TICK: Knob[int] = Knob(
    'aws.update.tick',
    has_db=False,
    envvar='ARTEMIS_AWS_UPDATE_TICK',
    envvar_cast=int,
    default=30
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
    instance_id: str
    spot_instance_id: Optional[str] = None


@dataclasses.dataclass
class AWSPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    spot_instance_id: Optional[str] = None


class AWSDriver(PoolDriver):
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

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        r_capabilities = super(AWSDriver, self).capabilities()

        if r_capabilities.is_error:
            return r_capabilities

        r_capabilities.unwrap().supports_native_post_install_script = True
        return r_capabilities

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
                return Error(Failure("Required variable '{}' not found in pool configuration".format(variable)))

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
                '--spot-instance-request-ids={}'.format(resource_ids.spot_instance_id)
            ])

            if r_output.is_error:
                return Error(r_output.unwrap_error())

        if resource_ids.instance_id is not None:
            r_output = self._aws_command([
                'ec2', 'terminate-instances',
                '--instance-ids={}'.format(resource_ids.instance_id)
            ])

            if r_output.is_error:
                return Error(r_output.unwrap_error())

        return Ok(None)

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        if environment.hw.arch != 'x86_64':
            return Ok(False)

        r_image = self._env_to_image(self.logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        r_type = self._env_to_instance_type(environment)
        if r_type.is_error:
            return Error(r_type.value)

        return Ok(True)

    def image_info_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        r_ii = self.get_pool_image_info(imagename)

        if r_ii.is_error:
            return Error(r_ii.unwrap_error())

        ii = r_ii.unwrap()

        if ii is None:
            return Error(Failure(
                'cannot find image by name',
                imagename=imagename
            ))

        return Ok(ii)

    def _env_to_instance_type(self, environment: Environment) -> Result[Any, Failure]:
        # TODO: in the future we will here translate the environment into an instance type
        return Ok(self.pool_config['default-instance-type'])

    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[PoolImageInfo, Failure]:
        r_engine = hook_engine('AWS_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image: Result[PoolImageInfo, Failure] = engine.run_hook(
            'AWS_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )

        if r_image.is_error:
            failure = r_image.unwrap_error()
            failure.update(environment=environment)

            return Error(failure)

        return r_image

    def _describe_instance(
        self,
        guest_request: GuestRequest
    ) -> Result[InstanceOwnerType, Failure]:

        aws_options = [
            'ec2',
            'describe-instances',
            '--instance-id={}'.format(AWSPoolData.unserialize(guest_request).instance_id)
        ]

        r_output = self._aws_command(aws_options, key='Reservations')

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

    def _aws_command(self, args: List[str], key: Optional[str] = None) -> Result[JSONType, Failure]:
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
            env=self.environ
        )

        if r_run.is_error:
            failure = r_run.unwrap_error()

            # Detect "instance does not exist" - this error is clearly irrecoverable. No matter how often we would
            # run this method, we would never evenr made it remove instance that doesn't exist.
            if test_cli_error(failure, MISSING_INSTANCE_ERROR_PATTERN):
                failure.recoverable = False

            return Error(failure)

        output = r_run.unwrap()

        if key is None:
            return Ok(output.json)

        try:
            return Ok(cast(Dict[str, Any], output.json)[key])

        except KeyError:
            return Error(Failure(
                "key '{}' not found in CLI output".format(key),
                command_output=output.process_output,
                scrubbed_command=command
            ))

    def _get_spot_price(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: str,
        image: PoolImageInfo
    ) -> Result[float, Failure]:

        availability_zone = self.pool_config['availability-zone']

        r_spot_price = self._aws_command([
            'ec2', 'describe-spot-price-history',
            '--instance-types={}'.format(instance_type),
            '--availability-zone={}'.format(availability_zone),
            '--product-descriptions={}'.format(image.pool_details['PlatformDetails']),
            '--max-items=1'
        ], key='SpotPriceHistory')

        if r_spot_price.is_error:
            return Error(r_spot_price.unwrap_error())

        prices = cast(List[Dict[str, str]], r_spot_price.unwrap())

        log_dict(logger.debug, 'spot prices', prices)

        try:
            current_price = float(prices[0]['SpotPrice'])
        except KeyError:
            return Error(Failure('failed to detect spot price'))

        # we bid some % to the price
        price = current_price + current_price * (float(self.pool_config['spot-price-bid-percentage']) / 100.0)

        spot_price_bid_percentage = self.pool_config['spot-price-bid-percentage']

        log_dict(logger.info, 'using spot price {} for'.format(price), {
            'availability zone': self.pool_config['availability-zone'],
            'current price': current_price,
            'instance type': instance_type,
            'product description': image.pool_details['PlatformDetails'],
            'bid': '{}%'.format(spot_price_bid_percentage)
        })

        return Ok(price)

    def _set_root_disk_size(
        self,
        block_device_mappings: BlockDeviceMappingsType,
        root_disk_size: int
    ) -> Result[BlockDeviceMappingsType, Failure]:

        try:
            block_device_mappings[0]['Ebs']['VolumeSize'] = root_disk_size
        except (KeyError, IndexError) as error:
            return Error(
                Failure.from_exc(
                    'Failed to set root disk size',
                    error,
                    block_device_mappings=block_device_mappings
                )
            )

        return Ok(block_device_mappings)

    def _get_block_device_mappings(self, image_id: str) -> Result[BlockDeviceMappingsType, Failure]:

        # get image block device mappings
        command = [
            'ec2', 'describe-images',
            '--image-id', image_id,
        ]

        r_image = self._aws_command(command, key='Images')

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = cast(List[Dict[str, BlockDeviceMappingsType]], r_image.unwrap())

        try:
            block_device_mappings = image[0]['BlockDeviceMappings']
        except (KeyError, IndexError) as error:
            return Error(
                Failure.from_exc(
                    'Failed to get block device mappings',
                    error,
                    block_device_mappings=block_device_mappings
                )
            )

        return Ok(block_device_mappings)

    def _request_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: str,
        image: PoolImageInfo,
        guestname: str
    ) -> Result[ProvisioningProgress, Failure]:

        command = [
            'ec2', 'run-instances',
            '--image-id', image.id,
            '--key-name', self.pool_config['master-key-name'],
            '--instance-type', instance_type
        ]

        if 'subnet-id' in self.pool_config:
            command.extend(['--subnet-id', self.pool_config['subnet-id']])

        if 'security-group' in self.pool_config:
            command.extend(['--security-group-ids', self.pool_config['security-group']])

        if 'default-root-disk-size' in self.pool_config:

            r_block_device_mappings = self._get_block_device_mappings(image_id=image.id)

            if r_block_device_mappings.is_error:
                return Error(r_block_device_mappings.unwrap_error())

            r_block_device_mappings = self._set_root_disk_size(
                r_block_device_mappings.unwrap(),
                root_disk_size=self.pool_config['default-root-disk-size']
            )

            block_device_mappings = r_block_device_mappings.unwrap()

            command.append("--block-device-mappings={}".format(json.dumps(block_device_mappings)))

        if 'additional-options' in self.pool_config:
            command.extend(self.pool_config['additional-options'])

        r_instance_request = self._aws_command(command, key='Instances')

        if r_instance_request.is_error:
            return Error(r_instance_request.unwrap_error())

        instance_request = cast(List[Dict[str, str]], r_instance_request.unwrap())

        try:
            instance_id = instance_request[0]['InstanceId']
        except (KeyError, IndexError):
            return Error(Failure('Failed to find InstanceID in aws output', output=instance_request))

        # instance state is "pending" after launch
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html
        logger.info('acquired instance status {}:{}'.format(
            instance_id,
            "pending"
        ))

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=AWSPoolData(instance_id=instance_id),
            delay_update=KNOB_UPDATE_TICK.value
        ))

    def _request_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_type: str,
        image: PoolImageInfo
    ) -> Result[ProvisioningProgress, Failure]:

        block_device_mappings: Optional[BlockDeviceMappingsType] = None

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

        if 'default-root-disk-size' in self.pool_config:

            r_block_device_mappings = self._get_block_device_mappings(image_id=image.id)

            if r_block_device_mappings.is_error:
                return Error(r_block_device_mappings.unwrap_error())

            r_block_device_mappings = self._set_root_disk_size(
                r_block_device_mappings.unwrap(),
                root_disk_size=self.pool_config['default-root-disk-size']
            )

            block_device_mappings = r_block_device_mappings.unwrap()

        specification = AWS_INSTANCE_SPECIFICATION.render(
            ami_id=image.id,
            key_name=self.pool_config['master-key-name'],
            instance_type=instance_type,
            availability_zone=self.pool_config['availability-zone'],
            subnet_id=self.pool_config['subnet-id'],
            security_group=self.pool_config['security-group'],
            user_data=user_data,
            block_device_mappings=block_device_mappings
        )

        log_blob(logger.info, 'spot request launch specification', specification)

        r_spot_request = self._aws_command([
            'ec2', 'request-spot-instances',
            '--spot-price={}'.format(spot_price),
            '--launch-specification={}'.format(' '.join(specification.split())),
        ], key='SpotInstanceRequests')

        if r_spot_request.is_error:
            return Error(r_spot_request.unwrap_error())

        spot_instance_id = cast(List[Dict[str, str]], r_spot_request.unwrap())[0]['SpotInstanceRequestId']
        logger.info("spot instance request '{}'".format(spot_instance_id))

        # wait until spot request fullfilled, accept busy waiting as this should take only few seconds
        # TODO: remove busy waiting later
        def _check_spot_request_fulfilled() -> Result[Any, Failure]:
            # wait for request to be fulfilled
            r_spot_status = self._aws_command([
                'ec2', 'describe-spot-instance-requests',
                '--spot-instance-request-ids={}'.format(spot_instance_id)
            ], key='SpotInstanceRequests')

            # Command returned error, there is no point to continue, return None
            if r_spot_status.is_error:
                r_spot_status.unwrap_error().log(logger.error, label='provisioning failed')
                return Ok(None)

            spot_request_result = cast(List[Dict[str, Any]], r_spot_status.unwrap())[0]

            if spot_request_result['Status']['Code'] == 'fulfilled':
                # note: we are returning a result as the value
                return Ok(spot_request_result['InstanceId'])

            return Error(Failure('Request in state {}'.format(spot_request_result['Status']['Code'])))

        logger.info('waiting for spot request to be fulfilled for {}s, tick each {}s'.format(
            self.pool_config['spot-request-timeout'], self.pool_config['spot-request-tick']
        ))
        instance_id = wait(
            'wait for spot request to be fulfilled', _check_spot_request_fulfilled,
            timeout=int(self.pool_config['spot-request-timeout']), tick=int(self.pool_config['spot-request-tick'])
        )

        if instance_id is None:
            return Error(FailedSpotRequest('Failed to get spot instance fullfillment state', spot_instance_id))

        # instance state is "pending" after launch
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html
        logger.info('acquired instance status {}:{}'.format(
            instance_id,
            "pending"
        ))

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=AWSPoolData(instance_id=instance_id, spot_instance_id=spot_instance_id),
            delay_update=KNOB_UPDATE_TICK.value
        ))

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:

        r_output = self._describe_instance(guest_request)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        instance, owner = r_output.unwrap()

        status = instance['State']['Name']

        pool_data = AWSPoolData.unserialize(guest_request)

        logger.info('current instance status {}:{}'.format(
            pool_data.instance_id,
            status
        ))

        # EC2 instance lifecycle documentation
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-lifecycle.html

        if status == 'terminated' or status == 'shutting-down':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=AWSPoolData.unserialize(guest_request),
                pool_failures=[Failure('instance terminated prematurely')]
            ))

        if status == 'pending':
            try:
                created_stamp = datetime.strptime(instance['LaunchTime'], '%Y-%m-%dT%H:%M:%S.%fZ')

            except Exception as exc:
                Failure.from_exc(
                    'failed to parse "created" timestamp',
                    exc,
                    stamp=instance['LaunchTime']
                ).handle(self.logger)

            else:
                diff = datetime.utcnow() - created_stamp

                if diff.total_seconds() > KNOB_PENDING_TIMEOUT.value:
                    return Ok(ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=AWSPoolData.unserialize(guest_request),
                        pool_failures=[Failure('instance stuck in "pending" for too long')]
                    ))

            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=pool_data,
                delay_update=KNOB_UPDATE_TICK.value
            ))

        # tag the instance if requested
        # TODO: move these into configuration. Before that, we need to add support for templates in tags, so we
        # could generate tags like `Name`. But it really belongs to configuration.
        tags: Dict[str, str] = {
            'Name': '{}::{}'.format(instance['PrivateIpAddress'], instance['ImageId'])
        }

        if pool_data.spot_instance_id is not None:
            tags['SpotRequestId'] = pool_data.spot_instance_id

        self._tag_instance(session, guest_request, instance, owner, tags=tags)

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=pool_data,
            address=instance['PrivateIpAddress']
        ))

    def _tag_instance(
        self,
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
        arn = 'arn:aws:ec2:{}:{}:instance/{}'.format(
            # region can be transformed from availability zone by omiting the last character
            self.pool_config['availability-zone'][:-1],
            owner,
            instance['InstanceId']
        )

        for tag, value in tags.items():
            self.info("tagging resource '{}' with '{}={}'".format(arn, tag, value))
            r_tag = self._aws_command([
                'resourcegroupstaggingapi', 'tag-resources',
                '--resource-arn-list', arn,
                '--tags', '{}={}'.format(tag, value)
            ])

            # do not fail if failed to tag, but scream to Sentry
            if r_tag.is_error:
                self.warn("Failed to tag ARN '{}' to tag '{}={}'".format(arn, tag, value), sentry=True)

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
            environment,
            master_key,
            cancelled
        )

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:

        logger.info('provisioning environment {}'.format(environment.serialize_to_json()))

        # get instance type from environment
        r_instance_type = self._env_to_instance_type(environment)
        if r_instance_type.is_error:
            return r_instance_type

        instance_type = r_instance_type.unwrap()

        # find out image from enviroment
        r_image = self._env_to_image(logger, environment)

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        # Non-spot request
        if not normalize_bool_option(self.pool_config.get('use-spot-request', False)):
            return self._request_instance(logger, instance_type, image, guest_request.guestname)

        # Spot requests require special handling
        logger.info('provisioning spot instance from image {}'.format(image))

        # request a spot instance and wait for it's full fillment
        r_instance = self._request_spot_instance(
            logger, session, guest_request, instance_type, image
        )

        if r_instance.is_error:
            # cleanup the spot request if needed
            if isinstance(r_instance.error, FailedSpotRequest):
                self._aws_command([
                    'ec2', 'cancel-spot-instance-requests',
                    '--spot-instance-request-ids={}'.format(r_instance.error.spot_instance_id)
                ])

                return Error(Failure(r_instance.error.message))

        return r_instance

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

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
        r_images = self._aws_command(['ec2', 'describe-images', '--owner=self'], key='Images')

        if r_images.is_error:
            return Error(r_images.unwrap_error())

        try:
            return Ok([
                PoolImageInfo(
                    name=image['Name'],
                    id=image['ImageId'],
                    pool_details={
                        'PlatformDetails': image['PlatformDetails']
                    }
                )
                for image in cast(List[Dict[str, str]], r_images.unwrap())
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed image description',
                exc,
                image_info=r_images.unwrap()
            ))
