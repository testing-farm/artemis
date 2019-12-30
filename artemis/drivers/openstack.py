import json
import os
import socket
import tempfile
import threading

import gluetool.log
from gluetool.log import log_dict
from gluetool.result import Result, Ok, Error

import libcloud.common.types
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from libcloud.compute.deployment import MultiStepDeployment, SSHKeyDeployment, ScriptDeployment

import artemis
from artemis import Failure
import artemis.drivers

from typing import Any, Dict, Optional


NodeRefType = Any


class OpenStackGuest(artemis.guest.Guest):
    def __init__(
        self,
        node: NodeRefType,
        address: Optional[str] = None,
        ssh_info: Optional[artemis.guest.SSHInfo] = None
    ) -> None:
        super(OpenStackGuest, self).__init__(address, ssh_info)

        self._node = node

    def __repr__(self) -> str:
        return '<OpenStackGuest: os_instance={}, address={}, ssh_info={}>'.format(
            self._node.uuid,
            self.address,
            self.ssh_info
        )

    def pool_data_to_db(self) -> str:
        return json.dumps({
            'instance_id': str(self._node.id)
        })


class OpenStackDriver(artemis.drivers.PoolDriver):
    def __init__(self, logger: gluetool.log.ContextAdapter, pool_config: Dict[str, Any]) -> None:
        super(OpenStackDriver, self).__init__(logger, pool_config)

        os_driver_class = get_driver(Provider.OPENSTACK)

        self._os_driver = os_driver_class(
            pool_config['username'],
            pool_config['password'],
            api_version='2.0',
            ex_force_auth_url=pool_config['auth-url'],
            ex_tenant_name=pool_config['project-name'],
            ex_domain_name=pool_config['user-domain-name'],
            ex_force_service_region='regionOne'
        )

        self.master_key_pool_name = pool_config['master-key-name']

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[artemis.guest.Guest, Failure]:
        if not guest_request.pool_data:
            return Error(Failure('invalid pool data'))

        pool_data = json.loads(guest_request.pool_data)

        nodes = [
            node
            for node in self._os_driver.list_nodes()
            if node.id == pool_data['instance_id']
        ]

        if not nodes:
            return Error(Failure('no such guest'))

        return Ok(
            OpenStackGuest(
                nodes[0],
                guest_request.address,
                artemis.guest.SSHInfo(
                    port=guest_request.ssh_port,
                    username=guest_request.ssh_username,
                    key=ssh_key
                )
            )
        )

    def can_acquire(self, environment: artemis.environment.Environment) -> Result[bool, Failure]:
        if environment.arch not in self.pool_config['available-arches']:
            return Ok(False)

        return Ok(True)

    def _env_to_flavor(self, environment: artemis.environment.Environment) -> Result[Any, Failure]:
        try:
            sizes = self._os_driver.list_sizes()

        except libcloud.common.types.LibcloudError as exc:
            return Error(Failure.from_exc('failed to fetch flavors', exc))

        # TODO: this will be handled by a script, for now we simply pick our local common variety of a flavor.

        suitable_sizes = [size for size in sizes if size.name == self.pool_config['default-flavor']]

        if not suitable_sizes:
            return Error(Failure('no such flavor'))

        return Ok(suitable_sizes[0])

    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: artemis.environment.Environment
    ) -> Result[Any, Failure]:
        try:
            images = self._os_driver.list_images()

        except libcloud.common.types.LibcloudError as exc:
            return Error(Failure.from_exc('failed to fetch images', exc))

        # TODO: this will be handled by a script, for now we simply pick our local common variety of an image.
        if environment.compose.is_openstack:
            assert environment.compose.openstack
            image_name = environment.compose.openstack.image

        else:
            image_name = self.pool_config['default-image']

        suitable_images = [image for image in images if image.name == image_name]

        if not suitable_images:
            log_dict(logger.warning, 'available images', [image.name for image in images])
            return Error(Failure('no such image "{}"'.format(self.pool_config['default-image'])))

        return Ok(suitable_images[0])

    def _env_to_network(self, environment: artemis.environment.Environment) -> Result[Any, Failure]:
        try:
            networks = self._os_driver.ex_list_networks()

        except libcloud.common.types.LibcloudError as exc:
            return Error(Failure('failed to fetch networks', exc))

        # TODO: this will be handled by a script, for now we simply pick our local common variety of a network.

        suitable_networks = [network for network in networks if network.name == self.pool_config['default-network']]

        if not suitable_networks:
            return Error(Failure('no such network'))

        return Ok(suitable_networks[0])

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
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
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        logger.info('provisioning environment {}'.format(environment.serialize_to_json()))

        result = self._env_to_flavor(environment)
        if result.is_error:
            return Error(result.value)

        size = result.unwrap()

        result = self._env_to_image(logger, environment)
        if result.is_error:
            return Error(result.value)

        image = result.unwrap()

        result = self._env_to_network(environment)
        if result.is_error:
            return Error(result.value)

        network = result.unwrap()

        add_master_key = SSHKeyDeployment(master_key.public)

        # if cloud_user:
        if True:
            ssh_username = 'cloud-user'
            copy_to_root = ScriptDeployment('sudo cp /home/cloud-user/.ssh/authorized_keys /root/.ssh/authorized_keys')

            msd = MultiStepDeployment([add_master_key, copy_to_root])

        else:
            ssh_username = 'root'
            msd = MultiStepDeployment([add_master_key])

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as master_key_private_file:
            master_key_private_file.write(master_key.private)
            master_key_private_file.flush()

        try:
            node = self._os_driver.deploy_node(
                name='libcloud-experiment',
                size=size,
                image=image,
                networks=[network],
                ex_keyname=self.master_key_pool_name,
                ssh_key=master_key_private_file.name,
                ssh_username=ssh_username,
                deploy=msd,
                ssh_interface='private_ips'
            )

        except libcloud.common.types.LibcloudError as exc:
            return Error(Failure.from_exc('failed to deploy node', exc))

        finally:
            os.unlink(master_key_private_file.name)

        addresses = node.private_ips

        if not addresses:
            return Error(Failure('no known IP address'))

        valid_ipv4_addresses = [
            address
            for address in addresses if libcloud.compute.base.is_valid_ip_address(address, family=socket.AF_INET)
        ]

        if not addresses:
            return Error(Failure('no known IPv4 address'))

        return Ok(
            OpenStackGuest(
                node,
                valid_ipv4_addresses[0],
                ssh_info=None
            )
        )

    def release_guest(self, guest: artemis.guest.Guest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if not isinstance(guest, OpenStackGuest):
            return Error(Failure('guest is not an OpenStack guest'))

        assert isinstance(guest, OpenStackGuest)

        if guest._node is None:
            return Error(Failure('guest has no node'))

        try:
            guest._node.destroy()

        except libcloud.common.types.LibcloudError as exc:
            return Error(Failure.from_exc('failed to destroy node', exc))

        except Exception as exc:
            return Error(Failure.from_exc('failed to destroy node', exc))

        return Ok(True)

    def capabilities(self) -> Result[artemis.drivers.PoolCapabilities, Failure]:
        result = super(OpenStackDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        capabilities.supports_snapshots = True

        return Ok(capabilities)
