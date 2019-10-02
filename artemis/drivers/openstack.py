import os
import socket
import tempfile
import threading

from gluetool.result import Result, Ok, Error

import libcloud.common.types
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from libcloud.compute.deployment import MultiStepDeployment, SSHKeyDeployment, ScriptDeployment

import artemis
import artemis.drivers

from typing import Any, Dict, Optional


OpenStackInstanceRefType = Any


class OpenStackGuest(artemis.guest.Guest):
    def __init__(self, os_instance, address, ssh_info):
        # type: (OpenStackInstanceRefType, str, artemis.guest.SSHInfo) -> None

        super(OpenStackGuest, self).__init__(address, ssh_info)

        self._os_instance = os_instance

    def __repr__(self):
        # type: () -> str

        return '<OpenStackGuest: os_instance={}, address={}, ssh_info={}>'.format(
            self._os_instance.uuid,
            self.address,
            self.ssh_info
        )


class OpenStackDriver(artemis.drivers.PoolDriver):
    def __init__(self, server_config, pool_config):
        # type: (Dict[str, Any], Dict[str, Any]) -> None

        super(OpenStackDriver, self).__init__(server_config, pool_config)

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

        self.master_key_name = pool_config['master-key-name']

    def can_acquire(self,
                    environment  # type: artemis.environment.Environment
                   ):  # noqa
        # type: (...) -> Result[bool, str]

        if environment.arch != 'x86_64':
            return Ok(False)

        return Ok(True)

    def _env_to_flavor(self, environment):
        # type: (artemis.environment.Environment) -> Result[Any, str]

        try:
            sizes = self._os_driver.list_sizes()

        except libcloud.common.types.LibcloudError as exc:
            return Error(exc)

        # TODO: this will be handled by a script, for now we simply pick our local common variety of a flavor.

        suitable_sizes = [size for size in sizes if size.name == self.pool_config['default-flavor']]

        if not suitable_sizes:
            return Error('No such flavor')

        return Ok(suitable_sizes[0])

    def _env_to_image(self, environment):
        # type: (artemis.environment.Environment) -> Result[Any, str]

        try:
            images = self._os_driver.list_images()

        except libcloud.common.types.LibcloudError as exc:
            return Error(exc)

        # TODO: this will be handled by a script, for now we simply pick our local common variety of an image.

        suitable_images = [image for image in images if image.name == self.pool_config['default-image']]

        if not suitable_images:
            return Error('No such image')

        return Ok(suitable_images[0])

    def _env_to_network(self, environment):
        # type: (artemis.environment.Environment) -> Result[Any, str]

        try:
            networks = self._os_driver.ex_list_networks()

        except libcloud.common.types.LibcloudError as exc:
            return Error(exc)

        # TODO: this will be handled by a script, for now we simply pick our local common variety of a network.

        suitable_networks = [network for network in networks if network.name == self.pool_config['default-network']]

        if not suitable_networks:
            return Error('No such network')

        return Ok(suitable_networks[0])

    def acquire_guest(self,
                      environment,  # type: artemis.environment.Environment
                      ssh_key,  # type: artemis.keys.Key
                      cancelled=None  # type: Optional[threading.Event]
                     ):  # noqa
        # type: (...) -> Result[artemis.guest.Guest, str]
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

        result = self._env_to_flavor(environment)
        if result.is_error:
            return Error(result.value)

        size = result.unwrap()

        result = self._env_to_image(environment)
        if result.is_error:
            return Error(result.value)

        image = result.unwrap()

        result = self._env_to_network(environment)
        if result.is_error:
            return Error(result.value)

        network = result.unwrap()

        add_key = SSHKeyDeployment(ssh_key.public)
        copy_to_root = ScriptDeployment('sudo cp /home/cloud-user/.ssh/authorized_keys /root/.ssh/authorized_keys')

        msd = MultiStepDeployment([add_key, copy_to_root])

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_private_file:
            key_private_file.write(ssh_key.private)
            key_private_file.flush()

        try:
            instance = self._os_driver.deploy_node(
                name='libcloud-experiment',
                size=size,
                image=image,
                networks=[network],
                ex_keyname=self.master_key_name,
                ssh_key=key_private_file.name,
                ssh_username='cloud-user',
                deploy=msd,
                ssh_interface='private_ips'
            )

        except libcloud.common.types.LibcloudError as exc:
            return Error(exc)

        finally:
            os.unlink(key_private_file.name)

        addresses = instance.private_ips

        if not addresses:
            return Error('No known IP address')

        valid_ipv4_addresses = [
            address
            for address in addresses if libcloud.compute.base.is_valid_ip_address(address, family=socket.AF_INET)
        ]

        if not addresses:
            return Error('No known IPv4 address')

        return Ok(
            OpenStackGuest(
                instance,
                valid_ipv4_addresses[0],
                artemis.guest.SSHInfo(
                    port=22,
                    username='root',
                    key=ssh_key
                )
            )
        )

    def release_guest(self, guest):
        # type: (artemis.guest.Guest) -> Result[bool, str]
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if not isinstance(guest, OpenStackGuest):
            return Error('')

        assert isinstance(guest, OpenStackGuest)

        if guest._os_instance is None:
            return Error('')

        try:
            guest._os_instance.destroy()

        except libcloud.common.types.LibcloudError as exc:
            return Error(str(exc))

        except Exception as exc:
            return Error(str(exc))

        return Ok(True)

    def capabilities(self):
        # type: () -> Result[artemis.drivers.PoolCapabilities, str]

        result = super(OpenStackDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        capabilities.supports_snapshots = True

        return Ok(capabilities)
