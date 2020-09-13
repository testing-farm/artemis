import os
import json
import re
import threading
from datetime import datetime

import gluetool.log
from gluetool.glue import GlueCommandError
from gluetool.result import Result, Ok, Error
from gluetool.utils import Command, wait

from . import PoolDriver, PoolCapabilities, PoolResourceLimits, PoolResourceUsage
from .. import Failure
from ..db import GuestRequest, SnapshotRequest, SSHKey
from ..environment import Environment
from ..guest import Guest, SSHInfo
from ..script import hook_engine
from ..snapshot import Snapshot

from typing import Any, Dict, List, Optional, Tuple, Union


# Temeout for wait function in _stop_guest and _start_guest events
WAIT_TIMEOUT = int(os.getenv('ARTEMIS_OPENSTACK_WAIT_TIMEOUT', 180))


class OpenStackGuest(Guest):
    def __init__(
        self,
        guestname: str,
        instance_id: str,
        address: Optional[str] = None,
        ssh_info: Optional[SSHInfo] = None
    ) -> None:
        super(OpenStackGuest, self).__init__(guestname, address, ssh_info)

        self.instance_id = instance_id

    def __repr__(self) -> str:
        return '<OpenStackGuest: os_instance={}, address={}, ssh_info={}>'.format(
            self.instance_id,
            self.address,
            self.ssh_info
        )

    @property
    def pool_data(self) -> Dict[str, Any]:
        return {
            'instance_id': str(self.instance_id)
        }


class OpenStackSnapshot(Snapshot):
    def __init__(
        self,
        snapshotname: str,
        guestname: str,
        status: Optional[str] = None
    ) -> None:
        super(OpenStackSnapshot, self).__init__(snapshotname, guestname)
        self.status = status

    @property
    def is_promised(self) -> bool:
        return self.status != 'active'


class OpenStackDriver(PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        pool_config: Dict[str, Any],
        poolname: Optional[str] = None
    ) -> None:
        super(OpenStackDriver, self).__init__(logger, pool_config, poolname=poolname)

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

            # The command has sensitive data which we don't want to expose in logs
            # scrubbed_command is free of sensitive data
            scrubbed_command = ['openstack'] + options

            return Error(Failure.from_exc(
                "Error running openstack command",
                exc,
                command_output=exc.output,
                scrubbed_command=scrubbed_command
            ))

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

    def _env_to_flavor(self, environment: Environment) -> Result[Any, Failure]:
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
        environment: Environment
    ) -> Result[Any, Failure]:
        r_engine = hook_engine('OPENSTACK_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            raise Exception(
                'Failed to load OPENSTACK_ENVIRONMENT_TO_IMAGE hook: {}'.format(r_engine.unwrap_error().message)
            )

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
                    'Failed to find image for environment',
                    caused_by=r_image.unwrap_error(),
                    environment=environment.serialize_to_json()
                )
            )

        return r_image

    def _env_to_network(self, environment: Environment) -> Result[Any, Failure]:
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

    def _show_guest(
        self,
        instance_id: str,
    ) -> Result[Any, Failure]:
        os_options = ['server', 'show', instance_id]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(r_output.unwrap())

    def _show_snapshot(
        self,
        snapshotname: str,
    ) -> Result[Any, Failure]:
        os_options = ['image', 'show', snapshotname]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(r_output.unwrap())

    def _is_guest_stopped(
        self,
        instance_id: str,
    ) -> Result[bool, Failure]:
        r_output = self._show_guest(instance_id)

        if r_output.is_error:
            return Error(r_output.value)

        output = r_output.unwrap()

        if output['status'] == 'SHUTOFF':
            return Ok(True)
        return Ok(False)

    def _stop_guest(
        self,
        instance_id: str,
    ) -> Result[bool, Failure]:
        # Do nothing if guest is already stopped
        r_stopped = self._is_guest_stopped(instance_id)

        if r_stopped.is_error:
            return Error(r_stopped.unwrap_error())

        if r_stopped.unwrap():
            return Ok(True)

        self.logger.info('stoping the guest instance')
        os_options = ['server', 'stop', instance_id]
        r_stop = self._run_os(os_options, json_format=False)

        if r_stop.is_error:
            return Error(r_stop.value)

        # TODO: dirty fix for now, will be implemented as a task ASAP
        def _wait_is_guest_stopped() -> Result[bool, Union[bool, Failure]]:

            r_stopped = self._is_guest_stopped(instance_id)

            if r_stopped.is_error:
                return Error(r_stopped.unwrap_error())

            if r_stopped.unwrap():
                return Ok(True)

            return Error(False)

        # Wait until guest will be stopped
        try:
            wait('wait for guest been stopped', _wait_is_guest_stopped, timeout=WAIT_TIMEOUT, logger=self.logger)

        except Exception as exc:
            return Error(Failure.from_exc('failed while waiting for guest been stopped', exc))

        return Ok(True)

    def _start_guest(
        self,
        instance_id: str,
    ) -> Result[bool, Failure]:
        # Do nothing if guest is not stopped
        r_stopped = self._is_guest_stopped(instance_id)

        if r_stopped.is_error:
            return Error(r_stopped.unwrap_error())

        if not r_stopped.unwrap():
            return Ok(True)

        self.logger.info('starting the guest instance')
        os_options = ['server', 'start', instance_id]
        r_stop = self._run_os(os_options, json_format=False)

        if r_stop.is_error:
            return Error(r_stop.value)

        # TODO: dirty fix for now, will be implemented as a task ASAP
        def _wait_is_guest_started() -> Result[bool, Union[bool, Failure]]:

            r_stopped = self._is_guest_stopped(instance_id)

            if r_stopped.is_error:
                return Error(r_stopped.unwrap_error())

            if not r_stopped.unwrap():
                return Ok(True)

            return Error(False)

        # Wait until guest will be started
        try:
            wait('wait for guest been stopped', _wait_is_guest_started, timeout=WAIT_TIMEOUT, logger=self.logger)

        except Exception as exc:
            return Error(Failure.from_exc('failed while waiting for guest been started', exc))

        return Ok(True)

    def _output_to_ip(self, output: Any) -> Result[Optional[str], Failure]:
        if not output['addresses']:
            # It's ok! That means the instance is not ready yet. We need to wait a bit for ip address.
            # The `update_guest` task will be scheduled until ip adress is None.
            return Ok(None)

        # output['addresses'] == "network_name=ip_address[, ipv6]"
        match_obj = re.match(r'.*=((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*', output['addresses'])
        if not match_obj:
            return Error(Failure('Failed to get ip', addresses=output['addresses']))

        return Ok(match_obj.group(1))

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:

        logger.info('provisioning environment {}'.format(environment))

        r_flavor = self._env_to_flavor(environment)
        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor = r_flavor.unwrap()

        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        r_network = self._env_to_network(environment)
        if r_network.is_error:
            return Error(r_network.unwrap_error())

        network = r_network.unwrap()

        name = 'artemis-guest-{}'.format(datetime.now().strftime('%d-%m-%Y-%H-%M-%S'))

        os_options = [
            'server',
            'create',
            '--flavor', flavor,
            '--image', image,
            '--network', network,
            '--key-name', self.pool_config['master-key-name'],
            '--property', 'ArtemisGuestName={}'.format(guest_request.guestname),
            name
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()

        if not output['id']:
            return Error(Failure('Instance id not found'))
        instance_id = output['id']

        status = output['status'].lower()

        self.logger.info('instance status is {}'.format(status))

        # There is no chance that the guest will be ready in this step
        # Return the guest with no ip and check it in the next update_guest event
        return Ok(
            OpenStackGuest(
                guest_request.guestname,
                instance_id,
                None,
                ssh_info=None
            )
        )

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        if environment.arch not in self.pool_config['available-arches']:
            return Ok(False)

        return Ok(True)

    def guest_factory(
        self,
        guest_request: GuestRequest,
        ssh_key: SSHKey
    ) -> Result[Guest, Failure]:
        if not guest_request.pool_data:
            return Error(Failure('invalid pool data'))

        pool_data = json.loads(guest_request.pool_data)

        if 'instance_id' not in pool_data:
            return Error(Failure('no guest was provisioned for request'))

        r_output = self._show_guest(pool_data['instance_id'])

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(
            OpenStackGuest(
                guest_request.guestname,
                pool_data['instance_id'],
                guest_request.address,
                SSHInfo(
                    port=guest_request.ssh_port,
                    username=guest_request.ssh_username,
                    key=ssh_key
                )
            )
        )

    def snapshot_factory(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[Snapshot, Failure]:
        r_output = self._show_snapshot(snapshot_request.snapshotname)

        if r_output.is_error:
            return Error(r_output.value)

        output = r_output.unwrap()

        status = ''

        if output:
            status = output['status']

        return Ok(
            OpenStackSnapshot(
                snapshot_request.snapshotname,
                snapshot_request.guestname,
                status if status else None
            )
        )

    def create_snapshot(
        self,
        snapshot_request: SnapshotRequest,
        guest: Guest
    ) -> Result[Snapshot, Failure]:

        if not isinstance(guest, OpenStackGuest):
            return Error(Failure('guest is not an OpenStack guest'))

        assert isinstance(guest, OpenStackGuest)

        r_stop = self._stop_guest(guest.instance_id)

        if r_stop.is_error:
            return Error(r_stop.unwrap_error())

        os_options = [
            'server', 'image', 'create',
            '--name', snapshot_request.snapshotname,
            guest.instance_id
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)
        output = r_output.unwrap()

        status = ''

        if output:
            status = output['status']

        # If snapshot is active, we can turn on the guest if start_again is True
        if status == 'active' and snapshot_request.start_again:
            r_start = self._start_guest(guest.instance_id)

            if r_start.is_error:
                return Error(r_start.unwrap_error())

        return Ok(OpenStackSnapshot(
            snapshot_request.snapshotname,
            snapshot_request.guestname,
            status if status else None
        ))

    def update_snapshot(
        self,
        snapshot: Snapshot,
        guest: Guest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[Snapshot, Failure]:

        if not isinstance(snapshot, OpenStackSnapshot):
            return Error(Failure('snapshot is not an OpenStack guest'))

        assert isinstance(snapshot, OpenStackSnapshot)

        if not isinstance(guest, OpenStackGuest):
            return Error(Failure('guest is not an OpenStack guest'))

        assert isinstance(guest, OpenStackGuest)

        r_output = self._show_snapshot(snapshot.snapshotname)

        if r_output.is_error:
            return Error(r_output.value)

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Image show commmand output is empty'))

        status = output['status']
        self.logger.info('snapshot status is {}'.format(status))

        if status != 'active':
            return Ok(snapshot)

        # If snapshot is active and start_again is True, we can turn on the guest
        if start_again:
            r_start = self._start_guest(guest.instance_id)

            if r_start.is_error:
                return Error(r_start.unwrap_error())

        snapshot.status = status
        return Ok(snapshot)

    def remove_snapshot(
        self,
        snapshot: Snapshot,
    ) -> Result[bool, Failure]:
        os_options = ['image', 'delete', snapshot.snapshotname]

        r_output = self._run_os(os_options, json_format=False)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(True)

    def restore_snapshot(
        self,
        snapshot_request: SnapshotRequest,
        guest: Guest
    ) -> Result[bool, Failure]:
        if not isinstance(guest, OpenStackGuest):
            return Error(Failure('guest is not an OpenStack guest'))

        assert isinstance(guest, OpenStackGuest)

        os_options = [
            'server', 'rebuild',
            '--image', snapshot_request.snapshotname,
            guest.instance_id, '--wait'
        ]

        r_output = self._run_os(os_options, json_format=False)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(True)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
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
            guest_request,
            environment,
            master_key,
            cancelled)

    def update_guest(
        self,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:

        assert guest_request.poolname
        if 'openstack' not in guest_request.poolname.lower():
            return Error(Failure('guest is not an OpenStack guest'))

        r_guest = self.guest_factory(guest_request, ssh_key=master_key)

        if r_guest.is_error:
            return Error(r_guest.unwrap_error())
        guest = r_guest.unwrap()

        assert isinstance(guest, OpenStackGuest)

        r_output = self._show_guest(guest.instance_id)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        status = output['status'].lower()

        self.logger.info('instance status is {}'.format(status))

        if status == 'error':
            self.release_guest(
                OpenStackGuest(
                    guest.guestname,
                    guest.instance_id,
                    None,
                    ssh_info=None
                )
            )
            self.logger.warning('Instance ended up in error state. provisioning a new one')

            return self._do_acquire_guest(self.logger, guest_request, environment, master_key)

        r_ip_address = self._output_to_ip(output)

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())
        ip_address = r_ip_address.unwrap()

        guest.address = ip_address

        return Ok(guest)

    def release_guest(self, guest: Guest) -> Result[bool, Failure]:
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

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        result = super(OpenStackDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        capabilities.supports_snapshots = True

        return Ok(capabilities)

    def get_pool_resource_metrics(self) -> Result[Tuple[PoolResourceLimits, PoolResourceUsage], Failure]:
        r_query_limits = self._run_os(
            ['limits', 'show', '--absolute', '--reserved'],
            json_format=True
        )

        if r_query_limits.is_error:
            return Error(r_query_limits.unwrap_error())

        raw_limits_container = r_query_limits.unwrap()

        if not isinstance(raw_limits_container, list):
            return Error(Failure('Invalid format of OpenStack limits report'))

        limits, usage = PoolResourceLimits(), PoolResourceUsage()

        for entry in raw_limits_container:
            name, value = entry.get('Name'), entry.get('Value')

            if not isinstance(entry, dict) or 'Name' not in entry or 'Value' not in entry:
                return Error(Failure('Invalid format of OpenStack limits report'))

            if name == 'totalCoresUsed':
                usage.cores = int(value)

            elif name == 'totalRAMUsed':
                usage.memory = int(value) * 1048576

            elif name == 'totalInstancesUsed':
                usage.instances = int(value)

            elif name == 'totalSnapshotsUsed':
                usage.snapshots = int(value)

            elif name == 'maxTotalCores':
                limits.cores = int(value)

            elif name == 'maxTotalInstances':
                limits.instances = int(value)

            elif name == 'maxTotalRAMSize':
                # RAM size/usage is reported in megabytes
                limits.memory = int(value) * 1048576

            elif name == 'maxTotalSnapshots':
                limits.snapshots = int(value)

        return Ok((limits, usage))
