import dataclasses
import re
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure, Knob
from ..db import GuestRequest, SnapshotRequest, SSHKey
from ..environment import Environment
from ..script import hook_engine
from . import PoolData, PoolDriver, PoolImageInfoType, PoolResourcesIDsType, PoolResourcesMetrics, \
    ProvisioningProgress, create_tempfile, run_cli_tool

#: How long, in seconds, is an instance allowed to stay in `BUILD` state until cancelled and reprovisioned.
KNOB_BUILD_TIMEOUT: Knob[int] = Knob(
    'openstack.build-timeout',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_BUILD_TIMEOUT',
    envvar_cast=int,
    default=600
)

#: A delay, in seconds, between two calls of `update-guest-request` checking provisioning progress.
KNOB_UPDATE_TICK: Knob[int] = Knob(
    'openstack.update.tick',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_UPDATE_TICK',
    envvar_cast=int,
    default=30
)


@dataclasses.dataclass
class OpenStackPoolData(PoolData):
    instance_id: str


class OpenStackDriver(PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super(OpenStackDriver, self).__init__(logger, poolname, pool_config)

        self._os_cmd_base = [
            'openstack',
            '--os-auth-url', self.pool_config['auth-url'],
            '--os-identity-api-version', self.pool_config['api-version'],
            '--os-user-domain-name', self.pool_config['user-domain-name'],
            '--os-project-name', self.pool_config['project-name'],
            '--os-username', self.pool_config['username'],
            '--os-password', self.pool_config['password']
        ]

        if self.pool_config.get('project-domain-name'):
            self._os_cmd_base += [
                '--os-project-domain-name', self.pool_config['project-domain-name']
            ]

        elif self.pool_config.get('project-domain-id'):
            self._os_cmd_base += [
                '--os-project-domain-id', self.pool_config['project-domain-id']
            ]

    def _run_os(self, options: List[str], json_format: bool = True) -> Result[Any, Failure]:
        """
        Run os command with additional options and return output in json format

        :param List(str) options: options for the command
        :param bool json_format: returns json format if true
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with output, or specification of error.
        """

        # Copy the command base, we don't want to spoil it for others.
        os_base = self._os_cmd_base[:]

        # -f(format) option must be placed after a command
        if json_format:
            options += ['-f', 'json']

        r_run = run_cli_tool(
            self.logger,
            os_base + options,
            json_output=json_format,
            command_scrubber=lambda cmd: (['openstack'] + options)
        )

        if r_run.is_error:
            # Detect "instance does not exist" - this error is clearly irrecoverable. No matter how often we would
            # run this method, we would never evenr made it remove instance that doesn't exist.
            failure = r_run.unwrap_error()

            if 'command_output' in failure.details:
                os_output = cast(gluetool.utils.ProcessOutput, failure.details['command_output'])

                if os_output.stderr \
                   and cast(bytes, os_output.stderr).strip().startswith(b'No server with a name or ID'):
                    failure.recoverable = False

            return Error(failure)

        if json_format:
            json_output, _ = r_run.unwrap()

            return Ok(json_output)

        raw_output, _ = r_run.unwrap()

        return Ok(raw_output)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = {}

        if instance_id is not None:
            resource_ids['instance_id'] = instance_id

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def image_info_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfoType, Failure]:
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
    ) -> Result[PoolImageInfoType, Failure]:
        r_engine = hook_engine('OPENSTACK_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image: Result[PoolImageInfoType, Failure] = engine.run_hook(
            'OPENSTACK_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )

        if r_image.is_error:
            failure = r_image.unwrap_error()
            failure.update(environment=environment)

            return Error(failure)

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
        guest_request: GuestRequest
    ) -> Result[Any, Failure]:
        os_options = [
            'server',
            'show',
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(r_output.unwrap())

    def _show_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[Any, Failure]:
        os_options = ['image', 'show', snapshot_request.snapshotname]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(r_output.unwrap())

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
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:

        logger.info('provisioning environment {}'.format(environment))

        r_flavor = self._env_to_flavor(environment)
        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor = r_flavor.unwrap()

        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        logger.info('provisioning from image {}'.format(image))

        r_network = self._env_to_network(environment)
        if r_network.is_error:
            return Error(r_network.unwrap_error())

        network = r_network.unwrap()
        name = 'artemis-guest-{}'.format(datetime.now().strftime('%d-%m-%Y-%H-%M-%S'))

        def _create(user_data_filename: str) -> Result[Any, Failure]:
            """The actual call to the openstack cli guest create command is happening here.
               If user_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            tags = self.get_guest_tags(session, guest_request)

            if tags.is_error:
                return Error(tags.unwrap_error())

            property_options: List[str] = sum([
                ['--property', '{}={}'.format(tag, value)]
                for tag, value in tags.unwrap().items()
            ], [])

            os_options = [
                'server',
                'create',
                '--flavor', flavor,
                '--image', image.id,
                '--network', network,
                '--key-name', self.pool_config['master-key-name'],
                '--security-group', self.pool_config.get('security-group', 'default'),
                '--user-data', user_data_filename
            ] + property_options + [
                name
            ]

            return self._run_os(os_options)

        if guest_request.post_install_script:
            # user has specified custom script to execute, contents stored as post_install_script
            with create_tempfile(file_contents=guest_request.post_install_script) as user_data_filename:
                r_output = _create(user_data_filename)
        else:
            # using post_install_script setting from the pool config
            r_output = _create(self.pool_config.get('post-install-script', ''))

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()
        if not output['id']:
            return Error(Failure('Instance id not found'))
        instance_id = output['id']

        status = output['status'].lower()

        logger.info('acquired instance status {}:{}'.format(
            instance_id,
            status
        ))

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            is_acquired=False,
            pool_data=OpenStackPoolData(instance_id=instance_id),
            delay_update=KNOB_UPDATE_TICK.value
        ))

    def _get_guest_status(
        self,
        guest_request: GuestRequest
    ) -> Result[str, Failure]:
        r_show = self._show_guest(guest_request)

        if r_show.is_error:
            return Error(r_show.unwrap_error())

        output = r_show.unwrap()

        return Ok(output['status'].lower())

    def is_guest_stopped(
        self,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        r_status = self._get_guest_status(guest_request)

        if r_status.is_error:
            return Error(r_status.unwrap_error())
        status = r_status.unwrap()

        return Ok(status == 'shutoff')

    def is_guest_running(
        self,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        r_status = self._get_guest_status(guest_request)

        if r_status.is_error:
            return Error(r_status.unwrap_error())
        status = r_status.unwrap()

        return Ok(status == 'active')

    def stop_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        logger.info('stoping the guest instance')
        os_options = ['server', 'stop', OpenStackPoolData.unserialize(guest_request).instance_id]
        r_stop = self._run_os(os_options, json_format=False)

        if r_stop.is_error:
            return Error(r_stop.value)

        return Ok(True)

    def start_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        logger.info('starting the guest instance')
        os_options = ['server', 'start', OpenStackPoolData.unserialize(guest_request).instance_id]
        r_start = self._run_os(os_options, json_format=False)

        if r_start.is_error:
            return Error(r_start.value)

        return Ok(True)

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        if environment.arch not in self.pool_config['available-arches']:
            return Ok(False)

        r_image = self._env_to_image(self.logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        r_flavor = self._env_to_flavor(environment)
        if r_flavor.is_error:
            return Error(r_flavor.value)

        return Ok(True)

    def create_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
    ) -> Result[ProvisioningProgress, Failure]:
        os_options = [
            'server', 'image', 'create',
            '--name', snapshot_request.snapshotname,
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(ProvisioningProgress(
            is_acquired=False,
            pool_data=OpenStackPoolData.unserialize(guest_request),
            delay_update=KNOB_UPDATE_TICK.value
        ))

    def update_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[ProvisioningProgress, Failure]:
        r_output = self._show_snapshot(snapshot_request)

        if r_output.is_error:
            return Error(r_output.value)

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Image show commmand output is empty'))

        status = output['status']
        self.logger.info('snapshot status is {}'.format(status))

        if status != 'active':
            return Ok(ProvisioningProgress(
                is_acquired=False,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        return Ok(ProvisioningProgress(
            is_acquired=True,
            pool_data=OpenStackPoolData.unserialize(guest_request)
        ))

    def remove_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[bool, Failure]:
        os_options = ['image', 'delete', snapshot_request.snapshotname]

        r_output = self._run_os(os_options, json_format=False)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(True)

    def restore_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest,
    ) -> Result[bool, Failure]:
        os_options = [
            'server', 'rebuild',
            '--image', snapshot_request.snapshotname,
            '--wait',
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options, json_format=False)

        if r_output.is_error:
            return Error(r_output.value)

        return Ok(True)

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

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        r_output = self._show_guest(guest_request)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        status = output['status'].lower()

        logger.info('current instance status {}:{}'.format(
            OpenStackPoolData.unserialize(guest_request).instance_id,
            status
        ))

        def _reprovision(msg: str) -> Result[ProvisioningProgress, Failure]:
            logger.warning(msg)

            r_acquire = self._do_acquire_guest(logger, session, guest_request, environment, master_key)

            if r_acquire.is_ok:
                logger.info('successfully reprovisioned, releasing the broken instance')

                # We can schedule release only when acquire succeeded. Only successfull acquire
                # let's us update guest request pool data with new instance ID. If acquire failed,
                # we keep our broken instance, and enter update guest task later, trying again
                # to either update or reschedule and drop the failed one.
                self._dispatch_resource_cleanup(
                    logger,
                    instance_id=OpenStackPoolData.unserialize(guest_request).instance_id,
                    guest_request=guest_request
                )

            return r_acquire

        if status == 'error':
            return _reprovision('Instance ended up in error state. provisioning a new one')

        if status == 'build' and 'created' in output:
            try:
                created_stamp = datetime.strptime(output['created'], '%Y-%m-%dT%H:%M:%SZ')

            except Exception as exc:
                Failure.from_exc(
                    'failed to parse "created" timestamp',
                    exc,
                    stamp=output['created']
                ).handle(self.logger)

            else:
                diff = datetime.utcnow() - created_stamp

                if diff.total_seconds() > KNOB_BUILD_TIMEOUT.value:
                    return _reprovision('instance stuck in BUILD state for {}, provisioning a new one'.format(diff))

            return Ok(ProvisioningProgress(
                is_acquired=False,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        r_ip_address = self._output_to_ip(output)

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())
        ip_address = r_ip_address.unwrap()

        return Ok(ProvisioningProgress(
            is_acquired=True,
            pool_data=OpenStackPoolData.unserialize(guest_request),
            address=ip_address
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if guest_request.poolname != self.poolname:
            return Error(Failure('guest is not owned by this pool'))

        r_cleanup = self._dispatch_resource_cleanup(
            logger,
            instance_id=OpenStackPoolData.unserialize(guest_request).instance_id,
            guest_request=guest_request
        )

        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())

        return Ok(True)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_ids: PoolResourcesIDsType
    ) -> Result[None, Failure]:
        if 'instance_id' in resource_ids:
            r_output = self._run_os([
                'server',
                'delete',
                '--wait',
                resource_ids['instance_id']
            ], json_format=False)

            if r_output.is_error:
                return Error(r_output.value)

        return Ok(None)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_query_limits = self._run_os(
            ['limits', 'show', '--absolute', '--reserved'],
            json_format=True
        )

        if r_query_limits.is_error:
            return Error(r_query_limits.unwrap_error())

        raw_limits_container = r_query_limits.unwrap()

        if not isinstance(raw_limits_container, list):
            return Error(Failure('Invalid format of OpenStack limits report'))

        resources = PoolResourcesMetrics()

        for entry in raw_limits_container:
            name, value = entry.get('Name'), entry.get('Value')

            if not isinstance(entry, dict) or 'Name' not in entry or 'Value' not in entry:
                return Error(Failure('Invalid format of OpenStack limits report'))

            if name == 'totalCoresUsed':
                resources.usage.cores = int(value)

            elif name == 'totalRAMUsed':
                resources.usage.memory = int(value) * 1048576

            elif name == 'totalInstancesUsed':
                resources.usage.instances = int(value)

            elif name == 'totalSnapshotsUsed':
                resources.usage.snapshots = int(value)

            elif name == 'maxTotalCores':
                resources.limits.cores = int(value)

            elif name == 'maxTotalInstances':
                resources.limits.instances = int(value)

            elif name == 'maxTotalRAMSize':
                # RAM size/usage is reported in megabytes
                resources.limits.memory = int(value) * 1048576

            elif name == 'maxTotalSnapshots':
                resources.limits.snapshots = int(value)

        return Ok(resources)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfoType], Failure]:
        r_images = self._run_os(['image', 'list'])

        if r_images.is_error:
            return Error(r_images.unwrap_error())

        try:
            return Ok([
                PoolImageInfoType(name=image['Name'], id=image['ID'])
                for image in r_images.unwrap()
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed image description',
                exc,
                image_info=r_images.unwrap()
            ))
