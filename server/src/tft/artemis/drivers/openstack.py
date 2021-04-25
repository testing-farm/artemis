import dataclasses
import re
import sys
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure, JSONType, Knob, get_cached_item, refresh_cached_set
from ..context import CACHE
from ..db import GuestRequest, SnapshotRequest, SSHKey
from ..environment import Environment
from ..metrics import PoolNetworkResources, PoolResourcesMetrics
from ..script import hook_engine
from . import PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, PoolResourcesIDs, ProvisioningProgress, \
    ProvisioningState, SerializedPoolResourcesIDs, create_tempfile, run_cli_tool, test_cli_error

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

MISSING_INSTANCE_ERROR_PATTERN = re.compile(r'^No server with a name or ID')


@dataclasses.dataclass
class OpenStackPoolData(PoolData):
    instance_id: str


@dataclasses.dataclass
class OpenStackPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None


@dataclasses.dataclass
class FlavorInfo:
    """
    Describes important information about an OpenStack flavor.
    """

    name: str
    id: str

    def __repr__(self) -> str:
        return '<FlavorInfo: name={} id={}>'.format(self.name, self.id)


class OpenStackDriver(PoolDriver):
    #: Template for a cache key holding flavor image info.
    POOL_FLAVOR_INFO_CACHE_KEY = 'pool.{}.flavor-info'

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, JSONType]
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

        self.flavor_info_cache_key = self.POOL_FLAVOR_INFO_CACHE_KEY.format(self.poolname)

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        r_capabilities = super(OpenStackDriver, self).capabilities()

        if r_capabilities.is_error:
            return r_capabilities

        r_capabilities.unwrap().supports_native_post_install_script = True
        return r_capabilities

    def _run_os(self, options: List[str], json_format: bool = True) -> Result[Union[JSONType, str], Failure]:
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
            failure = r_run.unwrap_error()

            # Detect "instance does not exist" - this error is clearly irrecoverable. No matter how often we would
            # run this method, we would never evenr made it remove instance that doesn't exist.
            if test_cli_error(failure, MISSING_INSTANCE_ERROR_PATTERN):
                failure.recoverable = False

            return Error(failure)

        cli_output = r_run.unwrap()

        if json_format:
            return Ok(cli_output.json)

        return Ok(cli_output.stdout)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = OpenStackPoolResourcesIDs(instance_id=instance_id)

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

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

    def _env_to_flavor(self, environment: Environment) -> Result[FlavorInfo, Failure]:
        # TODO: this will be handled by a script, for now we simply pick our local common variety of a flavor.

        r_flavor = get_cached_item(
            CACHE.get(),
            self.flavor_info_cache_key,
            self.pool_config['default-flavor'],
            FlavorInfo
        )

        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor_info = r_flavor.unwrap()

        if flavor_info is None:
            return Error(Failure(
                'no such flavor',
                flavorname=self.pool_config['default-flavor']
            ))

        return Ok(flavor_info)

    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[PoolImageInfo, Failure]:
        r_engine = hook_engine('OPENSTACK_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image: Result[PoolImageInfo, Failure] = engine.run_hook(
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

    def _env_to_network(self, environment: Environment) -> Result[str, Failure]:
        metrics = PoolResourcesMetrics(self.poolname)
        metrics.sync()

        # For each network, we need to extract number of free addresses, noting its name as well.
        suitable_networks: List[Tuple[int, str]] = []

        for network_name in metrics.usage.networks.keys():
            limit, usage = metrics.limits.networks.get(network_name), metrics.usage.networks.get(network_name)

            # If there's unknown limit or usage, then pool does not care enough. Use the biggest possible number
            # to signal this network can be picked freely, without any restrictions.
            if not limit or not usage:
                suitable_networks.append((sys.maxsize, network_name))
                continue

            # The same applies if pool noticed the network, but did not extract any address counts.
            if limit.addresses is None or usage.addresses is None:
                suitable_networks.append((sys.maxsize, network_name))
                continue

            suitable_networks.append((limit.addresses - usage.addresses, network_name))

        if not suitable_networks:
            return Error(Failure('no suitable network'))

        # Sort networks by the number of available IPs, in descending order, and pick the first one.
        free_ips, network_name = sorted(suitable_networks, key=lambda x: x[0], reverse=True)[0]

        self.logger.info('Using {} network with {} free IPs'.format(
            network_name,
            free_ips
        ))

        return Ok(network_name)

    def _show_guest(
        self,
        guest_request: GuestRequest
    ) -> Result[JSONType, Failure]:
        os_options = [
            'server',
            'show',
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(r_output.unwrap())

    def _show_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[JSONType, Failure]:
        os_options = ['image', 'show', snapshot_request.snapshotname]

        r_output = self._run_os(os_options)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(r_output.unwrap())

    def _output_to_ip(self, output: JSONType) -> Result[Optional[str], Failure]:
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

        logger.info('provisioning from image {} and flavor {}'.format(image, flavor))

        r_network = self._env_to_network(environment)
        if r_network.is_error:
            return Error(r_network.unwrap_error())

        network = r_network.unwrap()

        def _create(user_data_filename: str) -> Result[JSONType, Failure]:
            """The actual call to the openstack cli guest create command is happening here.
               If user_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            r_tags = self.get_guest_tags(session, guest_request)

            if r_tags.is_error:
                return Error(r_tags.unwrap_error())

            tags = r_tags.unwrap()

            property_options: List[str] = sum([
                ['--property', '{}={}'.format(tag, value)]
                for tag, value in tags.items()
            ], [])

            os_options = [
                'server',
                'create',
                '--flavor', flavor.id,
                '--image', image.id,
                '--network', network,
                '--key-name', self.pool_config['master-key-name'],
                '--security-group', self.pool_config.get('security-group', 'default'),
                '--user-data', user_data_filename
            ] + property_options + [
                tags['ArtemisGuestLabel']
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
            state=ProvisioningState.PENDING,
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
            return Error(r_stop.unwrap_error())

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
            return Error(r_start.unwrap_error())

        return Ok(True)

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        if environment.arch not in self.pool_config['available-arches']:
            return Ok(False)

        r_image = self._env_to_image(self.logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        r_flavor = self._env_to_flavor(environment)
        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

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
            return Error(r_output.unwrap_error())

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
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
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Image show commmand output is empty'))

        status = output['status']
        self.logger.info('snapshot status is {}'.format(status))

        if status != 'active':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=OpenStackPoolData.unserialize(guest_request)
        ))

    def remove_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[bool, Failure]:
        os_options = ['image', 'delete', snapshot_request.snapshotname]

        r_output = self._run_os(os_options, json_format=False)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

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
            return Error(r_output.unwrap_error())

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

        if status == 'error':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                pool_failures=[Failure('instance ended up in "ERROR" state')]
            ))

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
                    return Ok(ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=OpenStackPoolData.unserialize(guest_request),
                        pool_failures=[Failure('instance stuck in "BUILD" for too long')]
                    ))

            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        r_ip_address = self._output_to_ip(output)

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())
        ip_address = r_ip_address.unwrap()

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
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
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = OpenStackPoolResourcesIDs.unserialize(raw_resource_ids)

        if resource_ids.instance_id:
            r_output = self._run_os([
                'server',
                'delete',
                '--wait',
                resource_ids.instance_id
            ], json_format=False)

            if r_output.is_error:
                # Irrecoverable failures in release-pool-resources chain shouldn't influence the guest request.
                # The release process is decoupled, and therefore pool outages should no longer affect the request.
                failure = r_output.unwrap_error()
                failure.fail_guest_request = False

                return Error(failure)

        return Ok(None)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super(OpenStackDriver, self).fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        r_query_limits = self._run_os(
            ['limits', 'show', '--absolute', '--reserved'],
            json_format=True
        )

        if r_query_limits.is_error:
            return Error(r_query_limits.unwrap_error())

        raw_limits_container = r_query_limits.unwrap()

        if not isinstance(raw_limits_container, list):
            return Error(Failure('Invalid format of OpenStack limits report'))

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

            # When updating limits, make sure to not overwrite those already specified by pool configuration.
            elif name == 'maxTotalCores' and resources.limits.cores is None:
                resources.limits.cores = int(value)

            elif name == 'maxTotalInstances' and resources.limits.instances is None:
                resources.limits.instances = int(value)

            # RAM size/usage is reported in megabytes
            elif name == 'maxTotalRAMSize' and resources.limits.memory is None:
                resources.limits.memory = int(value) * 1048576

            elif name == 'maxTotalSnapshots' and resources.limits.snapshots is None:
                resources.limits.snapshots = int(value)

        r_networks = self._run_os([
            'ip',
            'availability',
            'list',
            '--ip-version', self.pool_config['ip-version']
        ], json_format=True)

        if r_networks.is_error:
            return Error(r_networks.unwrap_error())

        # networks have the following structure:
        # [
        #   {
        #     "Network ID": str,
        #     "Network Name": str,
        #     "Total IPs": int,
        #     "Used IPs": int
        #   },
        #   ...
        # ]

        network_pattern = re.compile(self.pool_config['network-regex'])

        for network in cast(List[Dict[str, str]], r_networks.unwrap()):
            network_name = network['Network Name']

            if not network_pattern.match(network_name):
                continue

            resources.usage.networks[network_name] = PoolNetworkResources(addresses=int(network['Used IPs']))
            resources.limits.networks[network_name] = PoolNetworkResources(addresses=int(network['Total IPs']))

        return Ok(resources)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        r_images = self._run_os(['image', 'list'])

        if r_images.is_error:
            return Error(r_images.unwrap_error())

        try:
            return Ok([
                PoolImageInfo(name=image['Name'], id=image['ID'])
                for image in cast(List[Dict[str, str]], r_images.unwrap())
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed image description',
                exc,
                image_info=r_images.unwrap()
            ))

    def refresh_flavor_info(self) -> Result[None, Failure]:
        """
        Responsible for updating the cache with the most up-to-date flavor info.

        Data are stored as a mapping between flavor name and containers serialized into JSON blobs.
        """

        # Flavors are described by OpenStack CLI with the following structure:
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

        r_flavors = self._run_os(['flavor', 'list'])

        if r_flavors.is_error:
            return Error(r_flavors.unwrap_error())

        try:
            flavors: Dict[str, FlavorInfo] = {
                flavor['Name']: FlavorInfo(name=flavor['Name'], id=flavor['ID'])
                for flavor in cast(List[Dict[str, str]], r_flavors.unwrap())
            }

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed flavor description',
                exc,
                flavor_info=r_flavors.unwrap()
            ))

        return refresh_cached_set(CACHE.get(), self.flavor_info_cache_key, flavors)

    def get_pool_flavor_infos(self) -> Result[List[FlavorInfo], Failure]:
        """
        Retrieve all flavor info known to the pool.
        """

        return self._fetch_cached_info(self.flavor_info_cache_key, FlavorInfo)
