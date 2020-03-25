import json
import re
import threading
from datetime import datetime

import gluetool.log
from gluetool.glue import GlueCommandError
from gluetool.result import Result, Ok, Error
from gluetool.utils import Command

import artemis
import artemis.db
import artemis.drivers
from artemis import Failure

from typing import Any, Dict, List, Optional


class OpenStackGuest(artemis.guest.Guest):
    def __init__(
        self,
        guestname: str,
        instance_id: str,
        address: Optional[str] = None,
        ssh_info: Optional[artemis.guest.SSHInfo] = None
    ) -> None:
        super(OpenStackGuest, self).__init__(guestname, address, ssh_info)

        self.instance_id = instance_id

    def __repr__(self) -> str:
        return '<OpenStackGuest: os_instance={}, address={}, ssh_info={}>'.format(
            self.instance_id,
            self.address,
            self.ssh_info
        )

    def pool_data_to_db(self) -> str:
        return json.dumps({
            'instance_id': str(self.instance_id)
        })


class OpenStackDriver(artemis.drivers.PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        pool_config: Dict[str, Any],
        poolname: Optional[str] = None
    ) -> None:
        super(OpenStackDriver, self).__init__(logger, pool_config, poolname=poolname)

        self.pool_config = pool_config

    def _run_os(self, options: List[str], json_format: bool = True) -> Result[Any, Failure]:
        """
        Run os command with additional options and return output in json format

        :param List(str) options: options for the command
        :param bool json_format: returns json format if true
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with output, or specification of error.
        """
        os_base = [
            'openstack',
            '--os-auth-url', self.pool_config['auth-url'],
            '--os-identity-api-version', self.pool_config['api-version'],
            '--os-user-domain-name', self.pool_config['user-domain-name'],
            '--os-project-domain-name', self.pool_config['project-domain-name'],
            '--os-project-name', self.pool_config['project-name'],
            '--os-username', self.pool_config['username'],
            '--os-password', self.pool_config['password']
        ]

        # -f(format) option must be placed after a command
        if json_format:
            options += ['-f', 'json']

        try:
            output = Command(os_base, options=options, logger=self.logger).run()

        except GlueCommandError as exc:
            return Error(Failure("Failure during 'os {}' execution: {}".format(' '.join(options), exc.output.stderr)))

        if output.stdout:
            if isinstance(output.stdout, str):
                cmd_out = output.stdout
            else:
                cmd_out = output.stdout.decode('utf-8')

            assert isinstance(cmd_out, str)

            if not json_format:
                return Ok(cmd_out)

            try:
                json_out = json.loads(cmd_out)
            except json.JSONDecodeError as exc:
                return Error(Failure.from_exc(
                    "Failed to parse output of 'os {}' to json".format(' '.join(options)), exc))

            return Ok(json_out)

        return Ok(True)

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[artemis.guest.Guest, Failure]:
        if not guest_request.pool_data:
            return Error(Failure('invalid pool data'))

        pool_data = json.loads(guest_request.pool_data)

        options = ['server', 'show', pool_data['instance_id']]
        r_output = self._run_os(options)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        return Ok(
            OpenStackGuest(
                guest_request.guestname,
                pool_data['instance_id'],
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
        r_flavors = self._run_os(['flavor', 'list'])

        if r_flavors.is_error:
            return Error(r_flavors.value)
        flavors = r_flavors.unwrap()

        # flavors has next structure:
        # [
        #   {
        #       "Name": str,
        #       "RAM": int,
        #       "Ephemeral": int,
        #       "VCPUs": int,
        #       "Is Public": bool,
        #       "Disk": int,
        #       "ID": str,
        #   },
        #   ...
        # ]

        # TODO: this will be handled by a script, for now we simply pick our local common variety of a flavor.

        suitable_flavors = [flavor for flavor in flavors if flavor["Name"] == self.pool_config['default-flavor']]

        if not suitable_flavors:
            return Error(Failure('no such flavor'))

        return Ok(suitable_flavors[0]["ID"])

    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: artemis.environment.Environment
    ) -> Result[Any, Failure]:
        r_engine = artemis.script.hook_engine('OPENSTACK_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            assert r_engine.error is not None

            raise Exception('Failed to load OPENSTACK_ENVIRONMENT_TO_IMAGE hook: {}'.format(r_engine.error.message))

        engine = r_engine.unwrap()

        r_image = engine.run_hook(
            'OPENSTACK_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )  # type: Result[Any, Failure]

        if r_image.is_error:
            return Error(
                Failure(
                    'Failed to find image for environment {}'.format(environment),
                    environment=environment.serialize_to_json()
                )
            )

        return r_image

    def _env_to_network(self, environment: artemis.environment.Environment) -> Result[Any, Failure]:
        ip_version = self.pool_config['ip-version']
        network_regex = self.pool_config['network-regex']

        r_networks = self._run_os(['ip', 'availability', 'list', '--ip-version', ip_version])

        if r_networks.is_error:
            return Error(r_networks.value)
        networks = r_networks.unwrap()

        # networks has next structure:
        # [
        #   {
        #     "Network ID": str,
        #     "Network Name": str,
        #     "Total IPs": int,
        #     "Used IPs": int
        #   },
        #   ...
        # ]

        # Keep only matched with regex networks
        suitable_networks = [network for network in networks if re.match(network_regex, network["Network Name"])]

        if not suitable_networks:
            return Error(Failure('no suitable network'))

        # Count free IPs for all suitable networks
        for network in suitable_networks:
            network['Free IPs'] = network['Total IPs'] - network['Used IPs']

        # Find max 'Free Ips' value and return network dict
        suitable_network = max(suitable_networks, key=lambda x: x['Free IPs'])

        self.logger.info('Using {} network with {} free IPs'.format(
            suitable_network['Network Name'],
            suitable_network['Free IPs']
        ))

        return Ok(suitable_network["Network ID"])

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
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        logger.info('provisioning environment {}'.format(environment))

        r_flavor = self._env_to_flavor(environment)
        if r_flavor.is_error:
            return Error(r_flavor.value)

        flavor = r_flavor.unwrap()

        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            assert r_image.error
            return Error(r_image.error)

        image = r_image.unwrap()

        r_network = self._env_to_network(environment)
        if r_network.is_error:
            return Error(r_network.value)

        network = r_network.unwrap()

        name = 'artemis-guest-{}'.format(datetime.now().strftime('%d-%m-%Y-%H-%M-%S'))

        os_options = [
            'server',
            'create',
            '--flavor', flavor,
            '--image', image,
            '--network', network,
            '--key-name', self.pool_config['master-key-name'],
            '--wait',
            name
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)
        output = r_output.unwrap()

        if not output['id']:
            return Error(Failure('Instance id not found'))
        instance_id = output['id']

        if not output['addresses']:
            return Error(Failure('Ip addresses not found'))

        # output['addresses'] == "network_name=ip_address[, ipv6]"
        match_obj = re.match(r'.*=([^,]*)', output['addresses'])
        if match_obj:
            ip_address = match_obj.group(1)

        return Ok(
            OpenStackGuest(
                guest_request.guestname,
                instance_id,
                ip_address,
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

        options = ['server', 'delete', '--wait', guest.instance_id]

        r_output = self._run_os(options, json_format=False)
        if r_output.is_error:
            return Error(r_output.value)

        return Ok(True)

    def capabilities(self) -> Result[artemis.drivers.PoolCapabilities, Failure]:
        result = super(OpenStackDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        capabilities.supports_snapshots = True

        return Ok(capabilities)
