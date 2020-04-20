import json
import re
import threading

from typing import cast, Any, Dict, List, Optional

import gluetool.log
from gluetool.log import log_dict
from gluetool.result import Result, Ok, Error
from gluetool.utils import Command, wait

import artemis
from artemis import Failure
import artemis.db
import artemis.drivers

#
# All these defautls should go to configuration later
#
AWS_PRODUCT_DESC_RHEL = 'Red Hat Enterprise Linux'
AWS_PRODUCT_DESC_LINUX = 'Linux/UNIX'
AWS_SPOT_PRICE_BID_PERCENTAGE = 10  # how much % to bid to the spot price

AWS_INSTANCE_SPECIFICATION = """
{{
  "ImageId": "{ami_id}",
  "KeyName": "{key_name}",
  "InstanceType": "{instance_type}",
  "Placement": {{
    "AvailabilityZone": "{availability_zone}"
  }},
  "NetworkInterfaces": [
    {{
      "DeviceIndex": 0,
      "SubnetId": "{subnet_id}",
      "DeleteOnTermination": true,
      "Groups": [
        "{security_group}"
      ],
      "AssociatePublicIpAddress": false
    }}
  ]
}}
"""


class FailedSpotRequest(Failure):
    def __init__(
        self,
        message: str,
        spot_request_id: str,
        **kwargs: Any
    ):
        super(FailedSpotRequest, self).__init__(message, **kwargs)
        self.spot_request_id = spot_request_id


class AWSGuest(artemis.guest.Guest):
    def __init__(
        self,
        instance_id: str,
        spot_request_id: str,
        address: Optional[str] = None,
        ssh_info: Optional[artemis.guest.SSHInfo] = None
    ) -> None:
        super(AWSGuest, self).__init__(address, ssh_info)
        self._instance_id = instance_id
        self._spot_request_id = spot_request_id

    def __repr__(self) -> str:
        return '<AWSGuest: id={}, spot_request_id={}, address={}, ssh_info={}>'.format(
            self._instance_id,
            self._spot_request_id,
            self.address,
            self.ssh_info
        )

    def pool_data_to_db(self) -> str:
        return json.dumps({
            'instance_id': str(self._instance_id),
            'spot_request_id': str(self._spot_request_id)
        })


class AWSDriver(artemis.drivers.PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        pool_config: Dict[str, Any],
        poolname: Optional[str] = None
    ) -> None:
        super(AWSDriver, self).__init__(logger, pool_config, poolname=poolname)

    def sanity(self) -> Result[bool, Failure]:
        required_variables = [
            'availability-zone',
            'command',
            'default-instance-type',
            'master-key-name',
            'security-group',
            'subnet-id',
            'spot-price-bid-percentage'
        ]

        for variable in required_variables:
            if variable not in self.pool_config:
                return Error(Failure("Required variable '{}' not found in pool configuration".format(variable)))

        return Ok(True)

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[artemis.guest.Guest, Failure]:

        if not guest_request.pool_data:
            return Error(Failure('invalid pool data'))

        pool_data = json.loads(guest_request.pool_data)

        result = self._aws_command(
            ['ec2', 'describe-instances', '--instance-id={}'.format(pool_data['instance_id'])],
            key='Reservations'
        )

        # no instance found
        if result.is_error:
            return Error(Failure('no instance found'))

        instance = result.unwrap()[0]['Instances'][0]

        return Ok(
            AWSGuest(
                pool_data['instance_id'],
                pool_data['spot_request_id'],
                instance['PrivateIpAddress'],
                artemis.guest.SSHInfo(
                    port=guest_request.ssh_port,
                    username=guest_request.ssh_username,
                    key=ssh_key
                )
            )
        )

    def can_acquire(self, environment: artemis.environment.Environment) -> Result[bool, Failure]:
        if environment.arch != 'x86_64':
            return Ok(False)

        return Ok(True)

    def _env_to_instance_type(self, environment: artemis.environment.Environment) -> Result[Any, Failure]:
        # TODO: in the future we will here translate the environment into an instance type
        return Ok(self.pool_config['default-instance-type'])

    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: artemis.environment.Environment
    ) -> Result[Any, Failure]:
        r_engine = artemis.script.hook_engine('AWS_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            assert r_engine.error is not None

            raise Exception('Failed to load AWS_ENVIRONMENT_TO_IMAGE hook: {}'.format(r_engine.error.message))

        engine = r_engine.unwrap()

        r_image = engine.run_hook(
            'AWS_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )

        if r_image.is_error:
            return Error(Failure('Failed to find image for environment {}'.format(environment)))

        return r_image

    def _aws_command(self, args: List[str], key: Optional[str] = None) -> Result[Any, Failure]:
        """
        Runs command via aws cli and returns a dictionary with command reply.

        :param list(str) args: Arguments for aws.
        :param str key: Optional key to return.
        """
        command = [self.pool_config['command']] + args

        try:
            output = Command(command).run()
        except gluetool.glue.GlueCommandError as exc:
            return Error(Failure.from_exc("Error running aws command '{}'".format(' '.join(command)), exc))

        assert output.stdout  # required to make typing happy
        json = gluetool.utils.from_json(output.stdout)

        try:
            return Ok(json[key] if key else json)
        except KeyError:
            return Error(Failure("Key '{}' not found in aws command '{}' json output".format(key, command)))

    def _get_spot_price(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: str,
        image: Dict[str, str]
    ) -> Result[float, Failure]:

        # We guess the product description from image name currently. The product description influences
        # the spot instance price. For Fedora the instances are 10x cheaper then for RHEL ...
        product_description = AWS_PRODUCT_DESC_RHEL if re.search('(?i)rhel', image['Name']) else AWS_PRODUCT_DESC_LINUX
        availability_zone = self.pool_config['availability-zone']

        r_spot_price = self._aws_command([
            'ec2', 'describe-spot-price-history',
            '--instance-types={}'.format(instance_type),
            '--availability-zone={}'.format(availability_zone),
            '--product-descriptions={}'.format(product_description),
            '--max-items=1'
        ], key='SpotPriceHistory')

        if r_spot_price.is_error:
            return r_spot_price

        prices = r_spot_price.unwrap()

        log_dict(logger.debug, 'spot prices', prices)

        try:
            current_price = float(prices[0]['SpotPrice'])
        except KeyError:
            return Error(Failure('failed to detect spot price'))

        # we bid some % to the price
        price = current_price + current_price * (float(self.pool_config['spot-price-bid-percentage'])/100.0)

        spot_price_bid_percentage = self.pool_config['spot-price-bid-percentage']

        log_dict(logger.info, 'using spot price {} for'.format(price), {
            'availability zone': self.pool_config['availability-zone'],
            'current price': current_price,
            'instance type': instance_type,
            'product description': product_description,
            'bid': '{}%'.format(spot_price_bid_percentage)
        })

        return Ok(price)

    def _request_spot_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_type: str,
        image: Dict[str, str]
    ) -> Result[artemis.guest.Guest, Failure]:

        # find our spot instance prices for the instance_type in our availability zone
        r_price = self._get_spot_price(logger, instance_type, image)
        if r_price.is_error:
            # _get_spot_price has different return value, we cannot return it as it is
            assert r_price.error
            return Error(r_price.error)

        spot_price = r_price.unwrap()

        specification = AWS_INSTANCE_SPECIFICATION.format(
            ami_id=image['ImageId'],
            key_name=self.pool_config['master-key-name'],
            instance_type=instance_type,
            availability_zone=self.pool_config['availability-zone'],
            subnet_id=self.pool_config['subnet-id'],
            security_group=self.pool_config['security-group']
        )

        r_spot_request = self._aws_command([
            'ec2', 'request-spot-instances',
            '--spot-price={}'.format(spot_price),
            '--launch-specification={}'.format(' '.join(specification.split())),
        ], key='SpotInstanceRequests')

        if r_spot_request.is_error:
            return r_spot_request

        spot_request_id = r_spot_request.unwrap()[0]['SpotInstanceRequestId']
        logger.info("spot instance request '{}'".format(spot_request_id))

        # wait until spot request fullfilled
        def _check_spot_request_fulfilled() -> Result[Any, Failure]:
            # wait for request to be fulfilled
            r_spot_status = self._aws_command([
                'ec2', 'describe-spot-instance-requests',
                '--spot-instance-request-ids={}'.format(spot_request_id)
            ], key='SpotInstanceRequests')

            # Command returned error, there is no point to continue, return None
            if r_spot_status.is_error:
                assert r_spot_status.error
                cast(Failure, r_spot_status).log(logger.error, label='provisioning failed')
                return Ok(None)

            spot_request_result = r_spot_status.unwrap()[0]

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
            return Error(FailedSpotRequest('Failed to get spot instance fullfillment state', spot_request_id))

        logger.info("instance id '{}'".format(instance_id))

        # wait until instance running
        def _check_instance_running() -> Result[Any, Failure]:
            # wait for request to be fulfilled
            r_instance = self._aws_command([
                'ec2', 'describe-instances',
                '--instance-id={}'.format(instance_id)
            ], key='Reservations')

            # command returned an unxpected result
            if r_instance.is_error:
                assert r_instance.error
                cast(Failure, r_instance).log(logger.error, label='provisioning failed')
                return Ok(None)

            instance = r_instance.unwrap()[0]['Instances'][0]
            owner = r_instance.unwrap()[0]['OwnerId']

            # return an instance if it became 'running'
            if instance['State']['Name'] == 'running':
                return Ok((instance, owner))

            return Error(Failure('Instance in state {}'.format(instance['State']['Name'])))

        logger.info('waiting for instance to be running for {}s, tick each {}s'.format(
            self.pool_config['instance-running-timeout'], self.pool_config['instance-running-tick']
        ))
        r_wait_instance = wait(
            'wait for for instance to be running', _check_instance_running,
            timeout=int(self.pool_config['instance-running-timeout']),
            tick=int(self.pool_config['instance-running-tick'])
        )

        if r_wait_instance is None:
            return Error(FailedSpotRequest('Failed to get spot instance state', spot_request_id))

        instance, owner = r_wait_instance

        self.info('instance succesfully provisioned and it has become running')

        # tag the instance if requested
        self._tag_instance(instance, owner, tags={
            'Name': '{}::{}'.format(instance['PrivateIpAddress'], image['Name']),
            'SpotRequestId': spot_request_id,
        })

        return Ok(
            AWSGuest(
                instance['InstanceId'],
                spot_request_id,
                instance['PrivateIpAddress'],
                ssh_info=None
            )
        )

    def _tag_instance(
        self,
        instance: Dict[str, Any],
        owner: str,
        tags: Optional[Dict[str, str]] = None
    ) -> None:

        tags = tags or {}

        # add tags from pool config
        if 'tags' in self.pool_config:
            tags.update(self.pool_config['tags'])

        if not tags:
            self.debug('Skipping tagging as no tags specified.')
            return

        # we need ARN of the instnace for tagging
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
        guest_request: artemis.db.GuestRequest,
        environment: artemis.environment.Environment,
        master_key: artemis.db.SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[artemis.guest.Guest, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key to upload to the guest.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, str]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        logger.info('provisioning environment {}'.format(environment.serialize_to_json()))

        # get instance type from environment
        r_instance_type = self._env_to_instance_type(environment)
        if r_instance_type.is_error:
            return r_instance_type

        instance_type = r_instance_type.unwrap()

        # find out image from enviroment
        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return r_image

        image = r_image.unwrap()

        # request a spot instance and wait for it's full fillment
        r_spot_instance = self._request_spot_instance(logger, instance_type, image)

        if r_spot_instance.is_error:
            # cleanup the spot request if needed
            if isinstance(r_spot_instance.error, FailedSpotRequest):
                self._aws_command([
                    'ec2', 'cancel-spot-instance-requests',
                    '--spot-instance-request-ids={}'.format(r_spot_instance.error.spot_request_id)
                ])

                return Error(Failure(r_spot_instance.error.message))

            # just return the error, no cleanup required
            return r_spot_instance

        guest = r_spot_instance.unwrap()

        return Ok(guest)

    def release_guest(self, guest: artemis.guest.Guest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if not isinstance(guest, AWSGuest):
            return Error(Failure('Guest is not an AWS guest'))

        # required for type checking
        assert isinstance(guest, AWSGuest)

        if guest._instance_id is None or guest._spot_request_id is None:
            return Error(Failure('guest has no identification'))

        r_cancel_request = self._aws_command([
            'ec2', 'cancel-spot-instance-requests',
            '--spot-instance-request-ids={}'.format(guest._spot_request_id)
        ])

        if r_cancel_request.is_error:
            return r_cancel_request

        r_terminate_instance = self._aws_command([
            'ec2', 'terminate-instances',
            '--instance-ids={}'.format(guest._instance_id)
        ])

        if r_terminate_instance.is_error:
            return r_terminate_instance

        return Ok(True)

    def capabilities(self) -> Result[artemis.drivers.PoolCapabilities, Failure]:
        result = super(AWSDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        # NOTE: we definitely would like to support snapshots later
        capabilities.supports_snapshots = False

        return Ok(capabilities)
