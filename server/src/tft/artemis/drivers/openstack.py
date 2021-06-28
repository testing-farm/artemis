import dataclasses
import re
import sys
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Pattern, Tuple, Union, cast

import gluetool.log
import jq
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure, JSONType, Knob, log_dict_yaml
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest, SnapshotRequest
from ..environment import UNITS, Environment, Flavor, FlavorCpu, FlavorDisk
from ..metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, ResourceType
from ..script import hook_engine
from . import ConsoleUrlData, GuestLogUpdateProgress, PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, \
    PoolResourcesIDs, ProvisioningProgress, ProvisioningState, SerializedPoolResourcesIDs, create_tempfile, \
    run_cli_tool, test_cli_error

KNOB_BUILD_TIMEOUT: Knob[int] = Knob(
    'openstack.build-timeout',
    'How long, in seconds, is an instance allowed to stay in `BUILD` state until cancelled and reprovisioned.',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_BUILD_TIMEOUT',
    cast_from_str=int,
    default=600
)

KNOB_UPDATE_TICK: Knob[int] = Knob(
    'openstack.update.tick',
    'A delay, in seconds, between two calls of `update-guest-request` checking provisioning progress.',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_UPDATE_TICK',
    cast_from_str=int,
    default=30
)

KNOB_CONSOLE_URL_EXPIRES: Knob[int] = Knob(
    'openstack.console.url.expires',
    'How long, in seconds, it takes for a console url to be qualified as expired.',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_CONSOLE_URL_EXPIRES',
    cast_from_str=int,
    default=600
)

KNOB_CONSOLE_BLOB_UPDATE_TICK: Knob[int] = Knob(
    'openstack.console.blob.update-tick',
    'How long, in seconds, to take between updating guest console log.',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_CONSOLE_BLOB_UPDATE_TICK',
    cast_from_str=int,
    default=30
)

MISSING_INSTANCE_ERROR_PATTERN = re.compile(r'^No server with a name or ID')
INSTANCE_NOT_READY_ERROR_PATTERN = re.compile(r'^Instance [a-z0-9\-]+ is not ready')

# IP address is suplied in a list of mappings
JQ_QUERY_INSTANCE_IPV4_ADDRESS = jq.compile('.addresses | to_entries[0].value[0]')


@dataclasses.dataclass
class OpenStackPoolData(PoolData):
    instance_id: str


@dataclasses.dataclass
class OpenStackPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None


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

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        r_capabilities = super(OpenStackDriver, self).capabilities()

        if r_capabilities.is_error:
            return r_capabilities

        capabilities = r_capabilities.unwrap()

        capabilities.supports_native_post_install_script = True
        capabilities.supports_console_url = True
        capabilities.supports_snapshots = True

        return r_capabilities

    def _run_os(
        self,
        options: List[str],
        json_format: bool = True,
        commandname: Optional[str] = None
    ) -> Result[Union[JSONType, str], Failure]:
        """
        Run os command with additional options and return output in json format

        :param List(str) options: options for the command
        :param bool json_format: returns json format if true
        :param commandname: if specified, driver will increase "CLI calls" metrics for this ``commandname``.
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
            command_scrubber=lambda cmd: (['openstack'] + options),
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

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _env_to_flavor(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[Flavor, Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(logger, environment)

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = r_suitable_flavors.unwrap()

        if not suitable_flavors:
            # TODO: somehow notify user that we were not able to find fitting flavor
            logger.warning('no sutiable flavors, using default')

            return self._map_environment_to_flavor_info_by_cache_by_name(logger, self.pool_config['default-flavor'])

        if self.pool_config['default-flavor'] in [flavor.name for flavor in suitable_flavors]:
            logger.info('default flavor among suitable ones, using it')

            return Ok([
                flavor
                for flavor in suitable_flavors
                if flavor.name == self.pool_config['default-flavor']
            ][0])

        return Ok(suitable_flavors[0])

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

    def _env_to_network(self, environment: Environment) -> Result[Any, Failure]:
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

        self.logger.info(f'Using {network_name} network with {free_ips} free IPs')

        return Ok(network_name)

    def _show_guest(
        self,
        guest_request: GuestRequest
    ) -> Result[Any, Failure]:
        os_options = [
            'server',
            'show',
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options, commandname='os.server-show')

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(r_output.unwrap())

    def _show_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[Any, Failure]:
        os_options = ['image', 'show', snapshot_request.snapshotname]

        r_output = self._run_os(os_options, commandname='os.image-show')

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(r_output.unwrap())

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        environment = Environment.unserialize_from_str(guest_request.environment)

        log_dict_yaml(
            logger.info,
            'provisioning environment',
            environment.serialize_to_json()
        )

        r_flavor = self._env_to_flavor(logger, environment)
        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor = r_flavor.unwrap()

        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        log_dict_yaml(
            logger.info,
            'provisioning from',
            {
                'flavor': flavor.serialize_to_json(),
                'image': image.serialize_to_json()
            }
        )

        r_network = self._env_to_network(environment)
        if r_network.is_error:
            return Error(r_network.unwrap_error())

        network = r_network.unwrap()

        def _create(user_data_filename: str) -> Result[Any, Failure]:
            """The actual call to the openstack cli guest create command is happening here.
               If user_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            r_tags = self.get_guest_tags(session, guest_request)

            if r_tags.is_error:
                return Error(r_tags.unwrap_error())

            tags = r_tags.unwrap()

            property_options: List[str] = sum([
                ['--property', f'{tag}={value}']
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

            return self._run_os(os_options, commandname='os.server-create')

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

        logger.info(f'acquired instance status {instance_id}:{status}')

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
        r_stop = self._run_os(os_options, json_format=False, commandname='os.server-stop')

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
        r_start = self._run_os(os_options, json_format=False, commandname='os.server-start')

        if r_start.is_error:
            return Error(r_start.unwrap_error())

        return Ok(True)

    def can_acquire(self, logger: gluetool.log.ContextAdapter, environment: Environment) -> Result[bool, Failure]:
        r_answer = super(OpenStackDriver, self).can_acquire(logger, environment)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        r_flavor = self._env_to_flavor(logger, environment)
        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        return Ok(True)

    def acquire_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest: GuestRequest
    ) -> Result[ConsoleUrlData, Failure]:
        """
        Acquire a guest console.
        """

        instance_id = OpenStackPoolData.unserialize(guest).instance_id
        os_options = [
            'console', 'url', 'show', instance_id
        ]
        r_output = self._run_os(os_options, commandname='os.console-url-show')
        if r_output.is_error:
            return Error(r_output.unwrap_error())
        # NOTE(ivasilev) The following cast is needed to keep quiet the typing check
        data = cast(Dict[str, str], r_output.unwrap())

        return Ok(ConsoleUrlData(url=data['url'],
                                 type=data['type'],
                                 expires=datetime.utcnow() + timedelta(seconds=KNOB_CONSOLE_URL_EXPIRES.value)))

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

        r_output = self._run_os(os_options, commandname='os.server-image-create')

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
        self.logger.info(f'snapshot status is {status}')

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

        r_output = self._run_os(os_options, json_format=False, commandname='os.image-delete')

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

        r_output = self._run_os(os_options, json_format=False, commandname='os.server-rebuild')

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(True)

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

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        r_output = self._show_guest(guest_request)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        status = output['status'].lower()

        logger.info(f'current instance status {OpenStackPoolData.unserialize(guest_request).instance_id}:{status}')

        if status == 'error':
            PoolMetrics.inc_error(self.poolname, 'instance-in-error-state')

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
                    PoolMetrics.inc_error(self.poolname, 'instance-building-too-long')

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

        try:
            ip_address = cast(str, JQ_QUERY_INSTANCE_IPV4_ADDRESS.input(output).first())

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse IP address',
                exc,
                output=output
            ))

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
            ], json_format=False, commandname='os.server-delete')

            if r_output.is_error:
                # Irrecoverable failures in release-pool-resources chain shouldn't influence the guest request.
                # The release process is decoupled, and therefore pool outages should no longer affect the request.
                failure = r_output.unwrap_error()
                failure.fail_guest_request = False

                return Error(failure)

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

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
            json_format=True,
            commandname='os.limits-show'
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
        ], json_format=True, commandname='os.ip-availability-list')

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
        r_images = self._run_os(['image', 'list'], commandname='os.image-list')

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

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
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

        r_flavors = self._run_os(['flavor', 'list'], commandname='os.flavor-list')

        if r_flavors.is_error:
            return Error(r_flavors.unwrap_error())

        if self.pool_config.get('flavor-regex'):
            flavor_name_pattern: Optional[Pattern[str]] = re.compile(self.pool_config['flavor-regex'])

        else:
            flavor_name_pattern = None

        try:
            return Ok([
                Flavor(
                    name=flavor['Name'],
                    id=flavor['ID'],
                    cpu=FlavorCpu(
                        cores=int(flavor['VCPUs'])
                    ),
                    # memory is reported in MiB
                    memory=int(flavor['RAM']) * UNITS.mebibytes,
                    disk=FlavorDisk(
                        # diskspace is reported in GiB
                        space=int(flavor['Disk']) * UNITS.gibibytes
                    )
                )
                for flavor in cast(List[Dict[str, str]], r_flavors.unwrap())
                if flavor_name_pattern is None or flavor_name_pattern.match(flavor['Name'])
            ])

        except KeyError as exc:
            return Error(Failure.from_exc(
                'malformed flavor description',
                exc,
                flavor_info=r_flavors.unwrap()
            ))

    def update_guest_log(
        self,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        if guest_log.logname != 'console':
            # anything but "console" is unsupported so far
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.ERROR
            ))

        def _do_fetch(resource: str, json_format: bool = True) -> Result[Optional[JSONType], Failure]:
            r_output = self._run_os([
                'console',
                resource,
                'show',
                OpenStackPoolData.unserialize(guest_request).instance_id
            ], json_format=json_format, commandname=f'console-{resource}-show')

            if r_output.is_error:
                failure = r_output.unwrap_error()

                # Detect "instance not ready".
                if test_cli_error(failure, INSTANCE_NOT_READY_ERROR_PATTERN):
                    return Ok(None)

            return r_output

        if guest_log.contenttype == GuestLogContentType.URL:
            r_output = _do_fetch('url')

            if r_output.is_error:
                return Error(r_output.unwrap_error())

            output = r_output.unwrap()

            if output is None:
                return Ok(GuestLogUpdateProgress(
                    state=GuestLogState.IN_PROGRESS,
                    delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
                ))

            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.COMPLETE,
                url=cast(Dict[str, str], output)['url'],
                expires=datetime.utcnow() + timedelta(seconds=KNOB_CONSOLE_URL_EXPIRES.value)
            ))

        # We're left with console/blob.
        r_output = _do_fetch('log', json_format=False)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        # TODO logs: do some sort of magic to find out whether the blob we just got is already in DB.
        # Maybe use difflib, or use delimiters and timestamps. We do not want to overide what we already have.

        output = r_output.unwrap()

        if output is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.IN_PROGRESS,
                delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
            ))

        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.IN_PROGRESS,
            # TODO logs: well, this *is* overwriting what we already downloaded... Do something.
            blob=cast(str, output),
            delay_update=KNOB_CONSOLE_BLOB_UPDATE_TICK.value
        ))
