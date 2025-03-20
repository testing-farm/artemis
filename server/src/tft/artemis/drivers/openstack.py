# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import re
import sys
from typing import Any, Dict, Iterator, List, Optional, Pattern, Tuple, Union, cast

import glanceclient
import gluetool.log
import keystoneauth1
import novaclient.v2.client
import novaclient.v2.flavors
import novaclient.v2.servers
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from keystoneauth1.identity import v3
from novaclient import client as nocl

from .. import Failure, JSONType, log_dict_yaml, process_output_to_str, safe_call
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest, SnapshotRequest
from ..environment import (
    UNITS,
    Environment,
    Flavor,
    FlavorBoot,
    FlavorCpu,
    FlavorDisk,
    FlavorDisks,
    FlavorNetwork,
    FlavorNetworks,
    FlavorVirtualization,
)
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from . import (
    KNOB_UPDATE_GUEST_REQUEST_TICK,
    CanAcquire,
    ConsoleUrlData,
    GuestLogUpdateProgress,
    HookImageInfoMapper,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolErrorCauses,
    PoolImageInfo,
    PoolImageSSHInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    SerializedPoolResourcesIDs,
    create_tempfile,
    guest_log_updater,
    run_cli_tool,
)

KNOB_BUILD_TIMEOUT: Knob[int] = Knob(
    'openstack.build-timeout',
    'How long, in seconds, is an instance allowed to stay in `BUILD` state until cancelled and reprovisioned.',
    has_db=False,
    envvar='ARTEMIS_OPENSTACK_BUILD_TIMEOUT',
    cast_from_str=int,
    default=600
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
    per_entity=True,
    envvar='ARTEMIS_OPENSTACK_CONSOLE_BLOB_UPDATE_TICK',
    cast_from_str=int,
    default=30
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'openstack.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_OPENSTACK_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-openstack.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'openstack.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_OPENSTACK_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)


class OpenStackErrorCauses(PoolErrorCauses):
    NONE = 'none'
    RESOURCE_METRICS_REFRESH_FAILED = 'resource-metrics-refresh-failed'
    FLAVOR_INFO_REFRESH_FAILED = 'flavor-info-refresh-failed'
    IMAGE_INFO_REFRESH_FAILED = 'image-info-refresh-failed'
    NO_SUCH_COMMAND = 'no-such-command'
    MISSING_INSTANCE = 'missing-instance'
    INSTANCE_NOT_READY = 'instance-not-ready'
    INSTANCE_IN_ERROR_STATE = 'instance-in-error-state'
    INSTANCE_BUILDING_TOO_LONG = 'instance-building-too-long'


CLI_ERROR_PATTERNS = {
    OpenStackErrorCauses.NO_SUCH_COMMAND: re.compile(r'openstack: .+ is not an openstack command'),
    OpenStackErrorCauses.MISSING_INSTANCE: re.compile(r'^No server with a name or ID'),
    OpenStackErrorCauses.INSTANCE_NOT_READY: re.compile(r'^Instance [a-z0-9\-]+ is not ready')
}


def os_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> OpenStackErrorCauses:
    if output.exit_code == 0:
        return OpenStackErrorCauses.NONE

    stdout = process_output_to_str(output, stream='stdout')
    stderr = process_output_to_str(output, stream='stderr')

    stdout = stdout.strip() if stdout is not None else None
    stderr = stderr.strip() if stderr is not None else None

    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if stdout and pattern.match(stdout):
            return cause

        if stderr and pattern.match(stderr):
            return cause

    return OpenStackErrorCauses.NONE


@dataclasses.dataclass
class OpenStackPoolData(PoolData):
    instance_id: str


@dataclasses.dataclass
class OpenStackPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None


class OpenStackDriver(PoolDriver):
    drivername = 'openstack'

    pool_data_class = OpenStackPoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super().__init__(logger, poolname, pool_config)

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

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
        return HookImageInfoMapper(self, 'OPENSTACK_ENVIRONMENT_TO_IMAGE')

    def login_session(
            self,
            logger: gluetool.log.ContextAdapter
    ) -> Result[keystoneauth1.session.Session, Failure]:
        # NOTE(ivasilev) Either project-domain-name or project-domain-id can be used for auth, so let's pass whatever's
        # defined in the config without restricting to project-domain-name only and let keystone client decide what
        # to use
        auth = v3.Password(
            auth_url=self.pool_config['auth-url'], username=self.pool_config['username'],
            password=self.pool_config['password'], user_domain_name=self.pool_config['user-domain-name'],
            project_domain_name=self.pool_config.get('project-domain-name'),
            project_domain_id=self.pool_config.get('project-domain-id'),
            project_name=self.pool_config['project-name']
        )
        try:
            sess = keystoneauth1.session.Session(auth=auth)
            return Ok(sess)
        except Exception as exc:
            return Error(Failure.from_exc(
                'Failed to log into OpenStack tenant',
                exc,
            ))

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = False
        capabilities.supports_native_post_install_script = True
        capabilities.supports_console_url = True
        capabilities.supports_snapshots = True
        capabilities.supported_guest_logs = [
            ('console:dump', GuestLogContentType.BLOB),
            ('console:interactive', GuestLogContentType.URL)
        ]

        return Ok(capabilities)

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
            commandname=commandname,
            cause_extractor=os_error_cause_extractor
        )

        if r_run.is_error:
            failure = r_run.unwrap_error()

            # Detect "instance does not exist" - this error is clearly irrecoverable. No matter how often we would
            # run this method, we would never evenr made it remove instance that doesn't exist.
            if failure.command_output \
               and os_error_cause_extractor(failure.command_output) == OpenStackErrorCauses.MISSING_INSTANCE:
                failure.recoverable = False

                PoolMetrics.inc_error(self.poolname, OpenStackErrorCauses.MISSING_INSTANCE)

            return Error(failure)

        cli_output = r_run.unwrap()

        if json_format:
            return Ok(cli_output.json)

        return Ok(cli_output.stdout)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _env_to_flavor_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[Optional[Flavor], Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = r_suitable_flavors.unwrap()

        if not suitable_flavors:
            if self.pool_config.get('use-default-flavor-when-no-suitable', True):
                guest_request.log_warning_event(
                    logger,
                    session,
                    'no suitable flavors, using default',
                    poolname=self.poolname
                )

                return self._map_environment_to_flavor_info_by_cache_by_name_or_none(
                    logger,
                    self.pool_config['default-flavor']
                )

            guest_request.log_warning_event(
                logger,
                session,
                'no suitable flavors',
                poolname=self.poolname
            )

            return Ok(None)

        if self.pool_config['default-flavor'] in [flavor.name for flavor in suitable_flavors]:
            logger.info('default flavor among suitable ones, using it')

            return Ok([
                flavor
                for flavor in suitable_flavors
                if flavor.name == self.pool_config['default-flavor']
            ][0])

        return Ok(suitable_flavors[0])

    def _env_to_flavor(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[Flavor, Failure]:
        r_flavor = self._env_to_flavor_or_none(logger, session, guest_request)

        if r_flavor.is_error:
            return Error(r_flavor.unwrap_error())

        flavor = r_flavor.unwrap()

        if flavor is None:
            return Error(Failure('no suitable flavor'))

        return Ok(flavor)

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

    def _get_nova(self) -> Result[novaclient.v2.client.Client, Failure]:

        sess = self.login_session(self.logger)
        if sess.is_error:
            return Error(sess.unwrap_error())
        try:
            nova = nocl.Client(self.pool_config['nova-version'], session=sess.unwrap())
            return Ok(nova)
        except Exception as exc:
            return Error(Failure.from_exc(
                'Failed to get nova Client',
                exc,
            ))

    def _show_guest(
        self,
        guest_request: GuestRequest
    ) -> Result[novaclient.v2.servers.Server, Failure]:

        r_nova = self._get_nova()
        if r_nova.is_error:
            return Error(r_nova.unwrap_error())
        instance = safe_call(r_nova.unwrap().servers.get, OpenStackPoolData.unserialize(guest_request).instance_id)

        return instance

    def _show_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[Any, Failure]:
        os_options = ['image', 'show', snapshot_request.snapshotname]

        r_output = self._run_os(os_options, commandname='os.image-show')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to fetch snapshot information',
                r_output.unwrap_error()
            ))

        return Ok(r_output.unwrap())

    def _get_glance(self) -> Result[glanceclient.Client, Failure]:

        sess = self.login_session(self.logger)
        if sess.is_error:
            return Error(sess.unwrap_error())
        try:
            glance = glanceclient.Client(self.pool_config['glance-version'], session=sess.unwrap())
            return Ok(glance)
        except Exception as exc:
            return Error(Failure.from_exc(
                'Failed to get glance Client',
                exc,
            ))

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        log_dict_yaml(
            logger.info,
            'provisioning environment',
            guest_request._environment
        )

        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_images = self.image_info_mapper.map(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

        pairs: List[Tuple[PoolImageInfo, Flavor]] = []

        for image in images:
            r_flavor = self._env_to_flavor(logger, session, guest_request)
            if r_flavor.is_error:
                return Error(r_flavor.unwrap_error())

            pairs.append((image, r_flavor.unwrap()))

        if not pairs:
            return Error(Failure('no suitable image/flavor combination found'))

        log_dict_yaml(logger.info, 'available image/flavor combinations', [
            {
                'flavor': flavor.serialize(),
                'image': image.serialize()
            } for image, flavor in pairs
        ])

        image, flavor = pairs[0]

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
            flavor=flavor,
            image=image
        )

        r_network = self._env_to_network(guest_request.environment)
        if r_network.is_error:
            return Error(r_network.unwrap_error())

        network = r_network.unwrap()

        def _create(user_data_filename: Optional[str] = None) -> Result[Any, Failure]:
            """The actual call to the openstack cli guest create command is happening here.
               If user_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            r_tags = self.get_guest_tags(logger, session, guest_request)

            if r_tags.is_error:
                return Error(r_tags.unwrap_error())

            tags = r_tags.unwrap()

            property_options: List[str] = sum((
                ['--property', f'{tag}={value}']
                for tag, value in tags.items()
            ), [])

            user_data_options: List[str] = [] if not user_data_filename else ['--user-data', user_data_filename]

            os_options = [
                'server',
                'create',
                '--flavor', flavor.id,
                '--image', image.id,
                '--network', network,
                '--key-name', self.pool_config['master-key-name'],
                '--security-group', self.pool_config.get('security-group', 'default'),
            ] + property_options + user_data_options + [
                tags['ArtemisGuestLabel']
            ]

            return self._run_os(os_options, commandname='os.server-create')

        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return Error(Failure.from_failure('Could not generate post-install script',
                                              r_post_install_script.unwrap_error()))

        post_install_script = r_post_install_script.unwrap()
        if post_install_script:
            with create_tempfile(file_contents=post_install_script) as user_data_filename:
                r_output = _create(user_data_filename)
        else:
            r_output = _create()

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
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _get_guest_status(
        self,
        guest_request: GuestRequest
    ) -> Result[str, Failure]:
        r_show = self._show_guest(guest_request)

        if r_show.is_error:
            return Error(r_show.unwrap_error())

        instance = r_show.unwrap()

        return Ok(instance.status.lower())

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
            return Error(Failure.from_failure(
                'failed to stop instance',
                r_stop.unwrap_error()
            ))

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
            return Error(Failure.from_failure(
                'failed to start instance',
                r_start.unwrap_error()
            ))
            return Error(r_start.unwrap_error())

        return Ok(True)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        # Disallow HW constraints the driver does not implement yet
        if guest_request.environment.has_hw_constraints:
            r_constraints = guest_request.environment.get_hw_constraints()

            if r_constraints.is_error:
                return Error(r_constraints.unwrap_error())

            constraints = r_constraints.unwrap()
            assert constraints is not None

        r_images = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if not images:
            return Ok(CanAcquire.cannot('compose not supported'))

        # The driver does not support kickstart natively. Filter only images we can perform ks install on.
        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

            if not images:
                return Ok(CanAcquire.cannot('compose does not support kickstart'))

        pairs: List[Tuple[PoolImageInfo, Flavor]] = []

        for image in images:
            r_flavor = self._env_to_flavor_or_none(logger, session, guest_request)

            if r_flavor.is_error:
                return Error(r_flavor.unwrap_error())

            flavor = r_flavor.unwrap()

            if flavor is None:
                continue

            pairs.append((image, flavor))

        if not pairs:
            return Ok(CanAcquire.cannot('no suitable image/flavor combination found'))

        log_dict_yaml(logger.info, 'available image/flavor combinations', [
            {
                'flavor': flavor.serialize(),
                'image': image.serialize()
            } for image, flavor in pairs
        ])

        return Ok(CanAcquire())

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
            return Error(Failure.from_failure(
                'failed to fetch console URL',
                r_output.unwrap_error()
            ))
        # NOTE(ivasilev) The following cast is needed to keep quiet the typing check
        data = cast(Dict[str, str], r_output.unwrap())

        return Ok(ConsoleUrlData(
            url=data['url'],
            type=data['type'],
            expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=KNOB_CONSOLE_URL_EXPIRES.value)
        ))

    def create_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        os_options = [
            'server', 'image', 'create',
            '--name', snapshot_request.snapshotname,
            OpenStackPoolData.unserialize(guest_request).instance_id
        ]

        r_output = self._run_os(os_options, commandname='os.server-image-create')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to create snapshot',
                r_output.unwrap_error()
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=OpenStackPoolData.unserialize(guest_request),
            delay_update=r_delay.unwrap()
        ))

    def update_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest,
        start_again: bool = True
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

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
                delay_update=r_delay.unwrap()
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=OpenStackPoolData.unserialize(guest_request)
        ))

    def remove_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[bool, Failure]:
        r_glance = self._get_glance()
        if r_glance.is_error:
            return Error(r_glance.unwrap_error())
        r_output = safe_call(r_glance.unwrap().images.delete, snapshot_request.snapshotname)

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to delete snapshot',
                r_output.unwrap_error()
            ))

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
            return Error(Failure.from_failure(
                'failed to rebuild instance',
                r_output.unwrap_error()
            ))

        return Ok(True)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key to upload to the guest.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """
        return self._do_acquire_guest(
            logger,
            session,
            guest_request
        )

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_instance = self._show_guest(guest_request)

        if r_instance.is_error:
            return Error(Failure('no such guest'))

        instance = r_instance.unwrap()

        if not instance:
            return Error(Failure('Server show commmand output is empty'))

        status = instance.status.lower()

        logger.info(f'current instance status {OpenStackPoolData.unserialize(guest_request).instance_id}:{status}')

        if status == 'error':
            PoolMetrics.inc_error(self.poolname, OpenStackErrorCauses.INSTANCE_IN_ERROR_STATE)

            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                pool_failures=[Failure('instance ended up in "ERROR" state')]
            ))

        if status == 'build' and instance.created:
            try:
                created_stamp = datetime.datetime.strptime(instance.created, '%Y-%m-%dT%H:%M:%SZ')

            except Exception as exc:
                Failure.from_exc(
                    'failed to parse "created" timestamp',
                    exc,
                    stamp=instance.created
                ).handle(self.logger)

            else:
                diff = datetime.datetime.utcnow() - created_stamp

                if diff.total_seconds() > KNOB_BUILD_TIMEOUT.value:
                    PoolMetrics.inc_error(self.poolname, OpenStackErrorCauses.INSTANCE_BUILDING_TOO_LONG)

                    return Ok(ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=OpenStackPoolData.unserialize(guest_request),
                        pool_failures=[Failure('instance stuck in "BUILD" for too long')]
                    ))

            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=OpenStackPoolData.unserialize(guest_request),
                delay_update=r_delay.unwrap()
            ))

        try:
            raw_address = list(instance.addresses.values())[0]
            ip_address = cast(str, raw_address[0]['addr'])

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse IP address',
                exc,
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=OpenStackPoolData.unserialize(guest_request),
            address=ip_address
        ))

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        if OpenStackPoolData.is_empty(guest_request):
            return Ok(None)

        pool_data = OpenStackPoolData.unserialize(guest_request)

        return self.dispatch_resource_cleanup(
            logger,
            session,
            OpenStackPoolResourcesIDs(instance_id=pool_data.instance_id),
            guest_request=guest_request
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = OpenStackPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.instance_id:
            r_output = self._run_os([
                'server',
                'delete',
                '--wait',
                resource_ids.instance_id
            ], json_format=False, commandname='os.server-delete')

            if r_output.is_error:
                return Error(Failure.from_failure(
                    'failed to delete instance',
                    r_output.unwrap_error()
                ))

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        return Ok(None)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        r_query_limits = self._run_os(
            ['limits', 'show', '--absolute', '--reserved'],
            json_format=True,
            commandname='os.limits-show'
        )

        if r_query_limits.is_error:
            return Error(Failure.from_failure(
                'failed to fetch tenant limits',
                r_query_limits.unwrap_error()
            ))

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

            elif name == 'totalGigabytesUsed':
                resources.usage.diskspace = int(value) * 1073741824

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

            elif name == 'maxTotalVolumeGigabytes' and resources.limits.diskspace is None:
                resources.limits.diskspace = int(value) * 1073741824

        r_networks = self._run_os([
            'ip',
            'availability',
            'list',
            '--ip-version', self.pool_config['ip-version']
        ], json_format=True, commandname='os.ip-availability-list')

        if r_networks.is_error:
            return Error(Failure.from_failure(
                'failed to fetch network information',
                r_networks.unwrap_error()
            ))

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

        # Resource usage - instances and flavors
        def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[List[Dict[str, str]], Failure]:
            r_servers = self._run_os([
                'server',
                'list',
                '--user', self.pool_config['username']
            ], json_format=True, commandname='os.server-list')

            if r_servers.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch server list',
                    r_servers.unwrap_error()
                ))

            return Ok(cast(List[Dict[str, str]], r_servers.unwrap()))

        def _update_instance_usage(
            logger: gluetool.log.ContextAdapter,
            usage: PoolResourcesUsage,
            raw_instance: Dict[str, str],
            flavor: Optional[Flavor]
        ) -> Result[None, Failure]:
            assert usage.instances is not None  # narrow type

            usage.instances += 1

            if flavor is not None:
                if flavor.name not in usage.flavors:
                    usage.flavors[flavor.name] = 0

                usage.flavors[flavor.name] += 1

            return Ok(None)

        r_instances_usage = self.do_fetch_pool_resources_metrics_flavor_usage(
            logger,
            resources.usage,
            _fetch_instances,
            lambda raw_instance: raw_instance['Flavor'],  # type: ignore[index,no-any-return]
            _update_instance_usage
        )

        if r_instances_usage.is_error:
            return Error(r_instances_usage.unwrap_error())

        return Ok(resources)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        r_glance = self._get_glance()
        if r_glance.is_error:
            return Error(r_glance.unwrap_error())

        if self.pool_config.get('image-regex'):
            image_name_pattern: Optional[Pattern[str]] = re.compile(self.pool_config['image-regex'])

        else:
            image_name_pattern = None

        r_images = safe_call(r_glance.unwrap().images.list)

        if r_images.is_error:
            return Error(Failure.from_failure(
                'Failed to list images',
                r_images.unwrap_error()
            ))

        try:
            return Ok([
                PoolImageInfo(
                    name=image['name'],
                    id=image['id'],
                    arch=None,
                    boot=FlavorBoot(method=[image.get('hw_firmware_type', 'bios')]),
                    ssh=PoolImageSSHInfo(),
                    supports_kickstart=False
                )
                for image in r_images.unwrap()
                if image_name_pattern is None or image_name_pattern.match(image['name'])
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

        def _fetch(logger: gluetool.log.ContextAdapter) -> Result[List[novaclient.v2.flavors.Flavor], Failure]:
            r_nova = self._get_nova()

            if r_nova.is_error:
                return Error(r_nova.unwrap_error())

            return safe_call(r_nova.unwrap().flavors.list)

        def _constructor(
            logger: gluetool.log.ContextAdapter,
            raw_flavor: novaclient.v2.flavors.Flavor
        ) -> Iterator[Result[Flavor, Failure]]:
            yield Ok(Flavor(
                name=raw_flavor.name,
                id=raw_flavor.id,
                cpu=FlavorCpu(
                    processors=int(raw_flavor.vcpus)
                ),
                # memory is reported in MiB
                memory=UNITS.Quantity(int(raw_flavor.ram), UNITS.mebibytes),
                disk=FlavorDisks([
                    FlavorDisk(
                        # diskspace is reported in GiB
                        size=UNITS.Quantity(int(raw_flavor.disk), UNITS.gibibytes)
                    )
                ]),
                network=FlavorNetworks([FlavorNetwork(type='eth')]),
                virtualization=FlavorVirtualization(
                    is_virtualized=True
                )
            ))

        return self.do_fetch_pool_flavor_info(
            self.logger,
            _fetch,
            lambda raw_flavor: cast(str, raw_flavor.name),  # type: ignore[attr-defined]
            _constructor
        )

    def _do_fetch_console(
        self,
        guest_request: GuestRequest,
        resource: str,
        json_format: bool = True
    ) -> Result[Optional[JSONType], Failure]:
        r_output = self._run_os([
            'console',
            resource,
            'show',
            OpenStackPoolData.unserialize(guest_request).instance_id
        ], json_format=json_format, commandname=f'console-{resource}-show')

        if r_output.is_error:
            failure = r_output.unwrap_error()

            # Detect "instance not ready".
            if failure.command_output \
               and os_error_cause_extractor(failure.command_output) == OpenStackErrorCauses.INSTANCE_NOT_READY:
                return Ok(None)

        return r_output

    @guest_log_updater('openstack', 'console:interactive', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_delay_update = KNOB_CONSOLE_BLOB_UPDATE_TICK.get_value(entityname=self.poolname)

        if r_delay_update.is_error:
            return Error(r_delay_update.unwrap_error())

        delay_update = r_delay_update.unwrap()

        r_output = self._do_fetch_console(guest_request, 'url')

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()

        if output is None:
            return Ok(GuestLogUpdateProgress(
                state=GuestLogState.IN_PROGRESS,
                delay_update=delay_update
            ))

        return Ok(GuestLogUpdateProgress(
            state=GuestLogState.COMPLETE,
            url=cast(Dict[str, str], output)['url'],
            expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=KNOB_CONSOLE_URL_EXPIRES.value)
        ))

    @guest_log_updater('openstack', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_delay_update = KNOB_CONSOLE_BLOB_UPDATE_TICK.get_value(entityname=self.poolname)

        if r_delay_update.is_error:
            return Error(r_delay_update.unwrap_error())

        delay_update = r_delay_update.unwrap()

        r_output = self._do_fetch_console(guest_request, 'log', json_format=False)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        progress = GuestLogUpdateProgress.from_snapshot(
            logger,
            guest_log,
            datetime.datetime.utcnow(),
            cast(str, r_output.unwrap()),
            lambda guest_log, timestamp, content, content_hash: content_hash in guest_log.blob_content_hashes
        )
        progress.delay_update = delay_update

        return Ok(progress)

    def trigger_reboot(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        pool_data = OpenStackPoolData.unserialize(guest_request)

        assert pool_data.instance_id is not None

        r_nova = self._get_nova()
        if r_nova.is_error:
            return Error(r_nova.unwrap_error())

        r_output = safe_call(r_nova.unwrap().servers.reboot, pool_data.instance_id, reboot_type='HARD')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to trigger instance reboot',
                r_output.unwrap_error()
            ))

        return Ok(None)


PoolDriver._drivers_registry['openstack'] = OpenStackDriver
