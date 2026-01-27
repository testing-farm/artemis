# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import functools
import re
from re import Pattern
from typing import Any, Optional, TypedDict, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from returns.result import Result as _Result, Success as _Ok
from tmt.hardware import UNITS

from tft.artemis.drivers import PoolDriver, PoolImageInfo, PoolImageInfoT
from tft.artemis.drivers.ibmcloud import (
    IBMCloudDriver,
    IBMCloudFlavor,
    IBMCloudInstance,
    IBMCloudPoolData,
    IBMCloudPoolResourcesIDs,
    IBMCloudSession,
)

from ... import Failure, JSONType, log_dict_yaml, logging_filter, process_output_to_str
from ...db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ...environment import Flavor, FlavorBoot
from ...knobs import Knob
from ...metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from .. import (
    GuestLogUpdateProgress,
    PoolCapabilities,
    PoolErrorCauses,
    PoolImageSSHInfo,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
    guest_log_updater,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'ibmcloud-power.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-ibmcloud-power.yaml',
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'ibmcloud-power.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}',
)

KNOB_CONSOLE_URL_EXPIRES: Knob[int] = Knob(
    'ibmcloud-power.console.url.expires',
    'How long, in seconds, it takes for a console url to be qualified as expired.',
    has_db=False,
    envvar='ARTEMIS_IBMCLOUD_POWER_CONSOLE_URL_EXPIRES',
    cast_from_str=int,
    default=300,
)


ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'name-regex': str,
    },
    total=False,
)


@dataclasses.dataclass
class IBMCloudPowerInstance(IBMCloudInstance):
    @functools.cached_property
    def is_pending(self) -> bool:
        return self.status == 'building'

    @functools.cached_property
    def is_ready(self) -> bool:
        return self.status == 'active'

    @functools.cached_property
    def is_error(self) -> bool:
        return self.status == 'error'


class APIImageType(TypedDict):
    name: str
    href: str
    imageID: str
    specifications: dict[str, Any]
    creationDate: str


class IBMCloudPowerErrorCauses(PoolErrorCauses):
    NONE = 'none'

    MISSING_INSTANCE = 'missing-instance'
    INSTANCE_NOT_READY = 'instance-not-ready'
    UNEXPECTED_INSTANCE_STATE = 'unexpected-instance-state'


CLI_ERROR_PATTERNS = {
    IBMCloudPowerErrorCauses.MISSING_INSTANCE: re.compile(r'pvm-instance does not exist'),
    IBMCloudPowerErrorCauses.INSTANCE_NOT_READY: re.compile(
        r'server is still initializing, wait a few minutes and try again'
    ),
}


def ibm_cloud_power_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> IBMCloudPowerErrorCauses:
    if output.exit_code == 0:
        return IBMCloudPowerErrorCauses.NONE

    stdout = process_output_to_str(output, stream='stdout')
    stderr = process_output_to_str(output, stream='stderr')

    stdout = stdout.strip() if stdout is not None else None
    stderr = stderr.strip() if stderr is not None else None

    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if stdout and pattern.search(stdout):
            return cause

        if stderr and pattern.search(stderr):
            return cause

    return IBMCloudPowerErrorCauses.NONE


class IBMCloudPowerSession(IBMCloudSession):
    def _login(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        # Login can be reused from parent class as is but need to additionally set the target workspace

        login_result = super()._login(logger)
        if login_result.is_error:
            return login_result

        r_set_target_workspace = self._run_cmd(
            logger,
            ['pi', 'workspace', 'target', self.pool.pool_config['workspace-crn']],
            json_format=False,
            commandname='ibmcloud.workspace-target',
        )
        if r_set_target_workspace.is_error:
            return Error(Failure.from_failure('failed to set target workspace', r_set_target_workspace.unwrap_error()))

        return Ok(None)


@dataclasses.dataclass(repr=False)
class IBMCloudPowerPoolImageInfo(PoolImageInfo):
    # A super long identifier like
    # /pcloud/v1/cloud-instances/f60e5369884840cd85c1490f4fb506eb/images/b44fe39f-3ec4-4baa-ada5-cbd56acaec1d
    href: str


class IBMCloudPowerDriver(IBMCloudDriver[IBMCloudPowerInstance]):
    drivername = 'ibmcloud-power'

    image_info_class = IBMCloudPowerPoolImageInfo
    pool_data_class = IBMCloudPoolData

    _image_map_hook_name = 'IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE'

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> _Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = False
        capabilities.supports_native_post_install_script = True
        capabilities.supported_guest_logs = [
            ('console:interactive', GuestLogContentType.URL),
        ]

        return _Ok(capabilities)

    def list_images(
        self, logger: gluetool.log.ContextAdapter, filters: Optional[ConfigImageFilter] = None
    ) -> Result[list[PoolImageInfo], Failure]:
        """
        This method will will issue a cloud guest list command and return a list of pool image info objects for this
        particular cloud.
        Filters argument contains optional filtering options to be applied on the cloud side.
        """
        raw_images: list[dict[str, Any]] = []
        with IBMCloudPowerSession(logger, self) as session:
            r_images_list = session.run(logger, ['pi', 'image', 'list', '--json'], commandname='ibmcloud.pi-image-list')

            if r_images_list.is_error:
                return Error(Failure.from_failure('failed to fetch image information', r_images_list.unwrap_error()))

            images_list = cast(dict[str, Any], r_images_list.unwrap())

            if 'images' not in images_list:
                return Error(Failure('Unexpected cli return, items key is missing', data=images_list))

            raw_images = images_list['images']

        def _from_raw_image(image: dict[str, Any]) -> Result[PoolImageInfo, Failure]:
            try:
                arch = image['specifications']['architecture']
                # NOTE(ivasilev) ppc64 needs special treatment, as IBM had this brilliant idea to put both
                # ppc64 and ppc64le as `ppc64` and differentiate upon the value of `endianness` field..
                if arch == 'ppc64':
                    arch = 'ppc64le' if image['specifications']['endianness'] == 'little-endian' else 'ppc64'

                return Ok(
                    IBMCloudPowerPoolImageInfo(
                        href=image['href'],
                        id=image['imageID'],
                        name=image['name'],
                        arch=arch,
                        boot=FlavorBoot(),
                        ssh=PoolImageSSHInfo(),
                        supports_kickstart=False,
                        creation_date=image['creationDate'],
                    )
                )
            except KeyError as exc:
                return Error(Failure.from_exc('malformed image description', exc, image_info=image))

        res = []
        for image_raw in raw_images:
            r_image = _from_raw_image(image_raw)
            if r_image.is_error:
                return Error(
                    Failure.from_failure(
                        'Failed converting image data to a PoolImageInfo object', r_image.unwrap_error()
                    )
                )
            res.append(r_image.unwrap())

        return Ok(res)

    def fetch_pool_image_info(self) -> Result[list[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[list[PoolImageInfo], Failure]:
            # operating system as defined in operatingSystem.version
            name_pattern: Optional[Pattern[str]] = None
            arch_pattern: Optional[Pattern[str]] = None

            logger = self.logger

            def _process_regex_filter(filter_name: str, filters: ConfigImageFilter) -> Optional[Pattern[Any]]:
                if filter_name not in filters:
                    return None
                return re.compile(filters[filter_name])  # type: ignore[literal-required]

            if filters:
                try:
                    name_pattern = _process_regex_filter('name-regex', filters)
                    arch_pattern = _process_regex_filter('arch-regex', filters)
                except re.error as exc:
                    return Error(Failure.from_exc('failed to compile regex', exc))

            with IBMCloudPowerSession(logger, self) as session:
                r_images_list = session.run(
                    logger, ['pi', 'image', 'list', '--json'], commandname='ibmcloud.pi-image-list'
                )

                if r_images_list.is_error:
                    return Error(
                        Failure.from_failure('failed to fetch image information', r_images_list.unwrap_error())
                    )

            images: list[PoolImageInfo] = []
            for image in cast(list[APIImageType], cast(dict[str, Any], r_images_list.unwrap()).get('images', [])):
                try:
                    # Apply wild-card filter if specified, unfortunately no way to filter by name or regex via cli
                    if name_pattern and not name_pattern.match(image['name']):
                        continue

                    arch = image['specifications']['architecture']
                    # NOTE(ivasilev) ppc64 needs special treatment, as IBM had this brilliant idea to put both
                    # ppc64 and ppc64le as `ppc64` and differentiate upon the value of `endianness` field..
                    if arch == 'ppc64':
                        arch = 'ppc64le' if image['specifications']['endianness'] == 'little-endian' else 'ppc64'
                    if arch_pattern and not arch_pattern.match(arch):
                        continue

                    ctime = self.timestamp_to_datetime(image['creationDate'])
                    if ctime.is_error:
                        return Error(
                            Failure.from_failure(
                                'Could not parse image create timestamp', ctime.unwrap_error(), image=image['imageID']
                            )
                        )

                    images.append(
                        IBMCloudPowerPoolImageInfo(
                            href=image['href'],
                            id=image['imageID'],
                            name=image['name'],
                            arch=arch,
                            boot=FlavorBoot(),
                            ssh=PoolImageSSHInfo(),
                            supports_kickstart=False,
                            created_at=ctime.unwrap(),
                        )
                    )
                except KeyError as exc:
                    return Error(
                        Failure.from_exc('malformed image description', exc, image_info=r_images_list.unwrap())
                    )

            log_dict_yaml(self.logger.debug, 'image filters', filters)
            log_dict_yaml(self.logger.debug, 'found images', [image.name for image in images])

            return Ok(images)

        images: list[PoolImageInfo] = []
        image_filters = cast(list[ConfigImageFilter], self.pool_config.get('image-filters', []))

        if image_filters:
            for filters in image_filters:
                r_images = _fetch_images(filters)

                if r_images.is_error:
                    return r_images

                images += r_images.unwrap()

        else:
            r_images = _fetch_images()

            if r_images.is_error:
                return r_images

            images += r_images.unwrap()

        return Ok(images)

    def _filter_flavors_required_fields_defined(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: PoolImageInfo,
        suitable_flavors: list[IBMCloudFlavor],
    ) -> Result[list[IBMCloudFlavor], Failure]:
        return Ok(
            list(
                logging_filter(
                    logger,
                    suitable_flavors,
                    'processors and threads-per-core are defined',
                    lambda logger, flavor: (
                        flavor.cpu.processors is not None and flavor.cpu.threads_per_core is not None
                    ),
                )
            )
        )

    def _guest_request_to_flavor_or_none(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: PoolImageInfoT,
    ) -> Result[Optional[IBMCloudFlavor], Failure]:
        """
        Map a guest request and image to the most fitting flavor.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guest_request: guest request to map to a flavor.
        :param image: image selected for the provisioning.
        :returns: flavor most suitable for the given combination of the guest request and image, or ``None`` if no
            suitable flavor was found.
        """

        return self._do_guest_request_to_flavor_or_none(
            logger,
            session,
            guest_request,
            image,
            self._filter_flavors_image_arch,
            self._filter_flavors_required_fields_defined,
            self._filter_flavors_prefer_default_flavor,
            self._filter_flavors_default_fallback,
        )

    def fetch_pool_resources_metrics(
        self, logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        subnet_id = self.pool_config['subnet-id']

        with IBMCloudPowerSession(logger, self) as session:
            # Resource usage - instances and flavors
            def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[list[dict[str, Any]], Failure]:
                r_list_instances = self.list_instances(logger)
                if r_list_instances.is_error:
                    return Error(Failure.from_failure('Could not list instances', r_list_instances.unwrap_error()))

                raw_instances: list[dict[str, Any]] = []

                for raw_instance_entry in r_list_instances.unwrap():
                    # To get network details need to additionally get instance details
                    r_show_instance = self._show_instance(logger, raw_instance_entry.id)

                    if r_show_instance.is_error:
                        return Error(
                            Failure.from_failure(
                                'Could not get instance details',
                                r_show_instance.unwrap_error(),
                                raw_instance_entry=raw_instance_entry,
                            )
                        )

                    raw_instance = r_show_instance.unwrap()

                    # Filter out instances not on pool network
                    if subnet_id not in raw_instance['networkIDs']:
                        continue

                    raw_instances.append(raw_instance)

                return Ok(raw_instances)

            def _update_instance_usage(
                logger: gluetool.log.ContextAdapter,
                usage: PoolResourcesUsage,
                raw_instance: dict[str, Any],
                flavor: Optional[Flavor],
            ) -> Result[None, Failure]:
                assert usage.instances is not None  # narrow type
                assert usage.cores is not None  # narrow type
                assert usage.memory is not None  # narrow type

                usage.instances += 1

                usage.cores += int(raw_instance.get('virtualCores', {}).get('assigned', 0))
                # Instance memory is in GB
                usage.memory += UNITS.Quantity(raw_instance['memory'], UNITS.gigabytes).to('bytes').magnitude

                # TODO: once we find the flavor name, we can update its usage.

                return Ok(None)

            r_instances_usage = self.do_fetch_pool_resources_metrics_flavor_usage(
                logger,
                resources.usage,
                _fetch_instances,
                # TODO: once we find the flavor name, we can update its usage.
                lambda raw_instance: 'dummy-flavor-name-does-not-exist',
                _update_instance_usage,
            )

            if r_instances_usage.is_error:
                return Error(r_instances_usage.unwrap_error())

            # Get pool network metrics
            r_show_network = session.run(
                logger, ['pi', 'subnet', 'get', subnet_id, '--json'], commandname='ibmcloud.power.show-network'
            )
            if r_show_network.is_error:
                return Error(Failure.from_failure('Could not get network metrics', r_show_network.unwrap_error()))

            network = cast(dict[str, Any], r_show_network.unwrap())

            resources.limits.networks[subnet_id] = PoolNetworkResources(addresses=network['ipAddressMetrics']['total'])
            resources.usage.networks[subnet_id] = PoolNetworkResources(addresses=network['ipAddressMetrics']['used'])

        return Ok(resources)

    def create_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        flavor: Flavor,
        image: PoolImageInfo,
        instance_name: str,
        user_data_file: Optional[str] = None,
    ) -> Result[IBMCloudPowerInstance, Failure]:
        # Here will be setting defaults for memory, just in case.
        memory = flavor.memory.to('GiB').magnitude if flavor.memory else 4
        # Unusable flavors missing processors/threads_per_core should be already filtered out
        assert flavor.cpu.processors
        assert flavor.cpu.threads_per_core

        processors = max(flavor.cpu.processors / flavor.cpu.threads_per_core, 1)

        with IBMCloudPowerSession(logger, self) as session:
            create_cmd_args = [
                'pi',
                'instance',
                'create',
                instance_name,
                '--subnets',
                self.pool_config['subnet-id'],
                '--image',
                image.id,
                '--key-name',
                self.pool_config['master-key-name'],
                '--processors',
                str(processors),
                '--memory',
                str(memory),
                '--json',
            ]
            if user_data_file:
                create_cmd_args += ['--user-data', f'@{user_data_file}']

            r_instance_create = session.run(logger, create_cmd_args, commandname='ibmcloud.instance-create')

            if r_instance_create.is_error:
                return Error(Failure.from_failure('Instance creation failed', r_instance_create.unwrap_error()))

            instance = cast(list[dict[str, Any]], r_instance_create.unwrap())[0]
            created_at = self.timestamp_to_datetime(instance['creationDate'])
            if created_at.is_error:
                return Error(
                    Failure.from_failure(
                        'Could not parse instance create timestamp',
                        created_at.unwrap_error(),
                        instance_id=instance['pvmInstanceID'],
                    )
                )

            return Ok(
                IBMCloudPowerInstance(
                    id=instance['pvmInstanceID'],
                    name=instance['serverName'],
                    status=instance['status'],
                    created_at=created_at.unwrap(),
                )
            )

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        return self.do_acquire_guest(logger, session, guest_request)

    def update_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """

        instance_id = guest_request.pool_data.mine(self, IBMCloudPoolData).instance_id
        if not instance_id:
            return Error(Failure('Need an instance id to fetch any information about a guest'))

        r_output = self._show_instance(logger, instance_id)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        pool_data = guest_request.pool_data.mine(self, IBMCloudPoolData)

        status = output['status'].lower()
        instance_name = output['serverName']
        logger.info(f'current instance status {pool_data.instance_id}:{status}')

        # Let's try to tag the instance
        r_assigned_tags = self.get_instance_tags(logger, instance_name)

        if r_assigned_tags.is_error:
            return Error(r_assigned_tags.unwrap_error())

        if not r_assigned_tags.unwrap():
            # No tags have been assigned yet, time to do that.
            r_tags = self.get_guest_tags(logger, session, guest_request)

            if r_tags.is_error:
                return Error(r_tags.unwrap_error())
            # Here comes the actual tagging attempt
            r_tag_instance = self.tag_instance(logger=logger, instance_name=instance_name, tags=r_tags.unwrap())

            if r_tag_instance.is_error:
                return Error(Failure.from_failure('Tagging instance failed', r_tag_instance.unwrap_error()))

        if status == 'build':
            return Ok(ProvisioningProgress(state=ProvisioningState.PENDING, pool_data=pool_data))

        if status == 'active':
            # Will be taking ip of the network interface for the pool config network
            ip_address = next(
                (
                    addr['ipAddress']
                    for addr in output['addresses']
                    if addr['networkID'] == self.pool_config['subnet-id']
                ),
                None,
            )

            if not ip_address:
                return Error(Failure('VM has reached active state but no ip address can be retrieved'))

            return Ok(ProvisioningProgress(state=ProvisioningState.COMPLETE, pool_data=pool_data, address=ip_address))

        PoolMetrics.inc_error(self.poolname, IBMCloudPowerErrorCauses.UNEXPECTED_INSTANCE_STATE)

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=pool_data,
                pool_failures=[Failure(f'instance ended up in an unexpected state "{status}"')],
            )
        )

    def _show_instance(self, logger: gluetool.log.ContextAdapter, instance_id: str) -> Result[dict[str, Any], Failure]:
        with IBMCloudPowerSession(logger, self) as session:
            r_instance_info = session.run(
                logger, ['pi', 'instance', 'get', instance_id, '--json'], commandname='ibmcloud.pi.vm-show'
            )

            if r_instance_info.is_error:
                return Error(
                    Failure.from_failure('failed to fetch instance information', r_instance_info.unwrap_error())
                )

            res = cast(dict[str, Any], r_instance_info.unwrap())

            return Ok(res)

    def list_instances(self, logger: gluetool.log.ContextAdapter) -> Result[list[IBMCloudPowerInstance], Failure]:
        with IBMCloudPowerSession(logger, self) as session:
            r_instances_list = session.run(
                logger, ['pi', 'instance', 'list', '--json'], commandname='ibmcloud.pi.vm-list'
            )

            if r_instances_list.is_error:
                return Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

            res = []
            for instance in cast(dict[str, Any], r_instances_list.unwrap())['pvmInstances']:
                created_at = self.timestamp_to_datetime(instance['creationDate'])
                if created_at.is_error:
                    return Error(
                        Failure.from_failure(
                            'Could not parse instance timestamp',
                            created_at.unwrap_error(),
                            instance=instance['id'],
                        )
                    )

                res.append(
                    IBMCloudPowerInstance(
                        id=instance['id'],
                        name=instance['name'],
                        created_at=created_at.unwrap(),
                        status=instance['status'],
                    )
                )

            return Ok(res)

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, IBMCloudPoolData)

        if not pool_data:
            return Ok(None)

        # Will be focusing only on the instance from pool data, no possible leftovers cleanup is performed.
        self.dispatch_resource_cleanup(
            logger,
            session,
            IBMCloudPoolResourcesIDs(instance_id=pool_data.instance_id),
            guest_request=guest_request,
        )

        return Ok(None)

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = IBMCloudPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.instance_id is not None:
            with IBMCloudPowerSession(logger, self) as session:
                self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

                r_delete_instance = session.run(
                    logger,
                    ['pi', 'instance', 'delete', resource_ids.instance_id],
                    json_format=False,
                    commandname='ibmcloud.pi.instance-delete',
                )
                if r_delete_instance.is_error:
                    return Error(
                        Failure.from_failure(
                            f'Failed to cleanup instance {resource_ids.instance_id}', r_delete_instance.unwrap_error()
                        )
                    )

        return Ok(ReleasePoolResourcesState.RELEASED)

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        pool_data = guest_request.pool_data.mine(self, IBMCloudPoolData)

        assert pool_data.instance_id is not None

        with IBMCloudPowerSession(logger, self) as session:
            r_output = session.run(
                logger,
                ['pi', 'instance', 'action', '-o', 'hard-reboot', pool_data.instance_id],
                commandname='ibmcloud.pi.vm-reboot',
            )

        if r_output.is_error:
            return Error(Failure.from_failure('failed to trigger instance reboot', r_output.unwrap_error()))

        return Ok(None)

    def _do_fetch_console(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest
    ) -> Result[Optional[JSONType], Failure]:
        # NOTE(ivasilev) Code duplication, nearly identical to openstack driver, another candidate for technical debt
        # epic
        pool_data = guest_request.pool_data.mine(self, IBMCloudPoolData)

        if not pool_data.instance_id:
            return Error(Failure('cannot fetch console without instance ID'))

        with IBMCloudPowerSession(logger, self) as session:
            r_output = session.run(
                logger,
                ['pi', 'instance', 'console', 'get', pool_data.instance_id, '--json'],
                commandname='ibmcloud.pi.get-console-url',
                json_format=True,
            )
        if r_output.is_error:
            failure = r_output.unwrap_error()
            # Detect "instance not ready".
            if (
                failure.command_output
                and ibm_cloud_power_error_cause_extractor(failure.command_output)
                == IBMCloudPowerErrorCauses.INSTANCE_NOT_READY
            ):
                return Ok(None)

        return r_output

    @guest_log_updater('ibmcloud-power', 'console:interactive', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_url(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Update console.interactive/url guest log.
        """

        r_output = self._do_fetch_console(logger, guest_request)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()

        if output is None:
            return Ok(GuestLogUpdateProgress(state=GuestLogState.IN_PROGRESS))

        return Ok(
            GuestLogUpdateProgress(
                state=GuestLogState.COMPLETE,
                url=cast(dict[str, str], output)['consoleURL'],
                expires=datetime.datetime.utcnow() + datetime.timedelta(seconds=KNOB_CONSOLE_URL_EXPIRES.value),
            )
        )


PoolDriver._drivers_registry['ibmcloud-power'] = IBMCloudPowerDriver
