# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
import re
from collections.abc import Iterator
from re import Pattern
from typing import Any, Optional, TypedDict, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from tmt.hardware import UNITS

from tft.artemis.drivers import PoolDriver, PoolImageInfo
from tft.artemis.drivers.ibmcloud import (
    IBMCloudDriver,
    IBMCloudFlavor,
    IBMCloudPoolData,
    IBMCloudPoolResourcesIDs,
    IBMCloudSession,
)

from ... import Failure, JSONType, log_dict_yaml
from ...db import GuestRequest
from ...environment import (
    Flavor,
    FlavorBoot,
    FlavorCpu,
    FlavorDisk,
    FlavorDisks,
    FlavorNetwork,
    FlavorNetworks,
    FlavorVirtualization,
    SizeType,
)
from ...knobs import Knob
from ...metrics import PoolMetrics, PoolNetworkResources, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from .. import (
    PoolErrorCauses,
    PoolImageSSHInfo,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
    create_tempfile,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'ibmcloud.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-ibmcloud-vpc.yaml',
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'ibmcloud.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}',
)

IBMCLOUD_RESOURCE_TYPE: dict[str, ResourceType] = {
    'instance': ResourceType.VIRTUAL_MACHINE,
    'subnet': ResourceType.VIRTUAL_NETWORK,
    'volume': ResourceType.DISK,
    'floating-ip': ResourceType.STATIC_IP,
    'security-group': ResourceType.SECURITY_GROUP,
}


class IBMCloudVPCErrorCauses(PoolErrorCauses):
    NONE = 'none'

    UNEXPECTED_INSTANCE_STATE = 'unexpected-instance-state'


class APIImageType(TypedDict):
    name: str
    crn: str
    id: str
    visibility: str
    user_data_format: str
    status: str
    operating_system: dict[str, Any]


ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'visibility': str,
        'owner-type': str,
        'status': str,
        'user-data-format': str,
        'name-regex': str,
        'arch-regex': str,
    },
    total=False,
)


@dataclasses.dataclass(repr=False)
class IBMCloudVPCPoolImageInfo(PoolImageInfo):
    # A super long identifier like
    # crn:v1:bluemix:public:is:us-east:a/4207b73c20f249499b08ed2136bb1818::image:IMAGE_ID
    crn: str
    # TODO: all three fields below SHOULD be enums
    # One of available, obsolete, deprecated
    status: str
    # public or private
    visibility: str
    # One of ipxe, esxi_kickstart, cloud_init
    user_data_format: str


class IBMCloudVPCDriver(IBMCloudDriver):
    drivername = 'ibmcloud-vpc'

    image_info_class = IBMCloudVPCPoolImageInfo
    flavor_info_class = IBMCloudFlavor
    pool_data_class = IBMCloudPoolData

    _image_map_hook_name = 'IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE'

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)

    def fetch_pool_image_info(self) -> Result[list[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[list[PoolImageInfo], Failure]:
            name_pattern: Optional[Pattern[str]] = None
            arch_pattern: Optional[Pattern[str]] = None

            logger = self.logger

            # NOTE(ivasilev) Due to the newly discovered issue with ibmcloud cli crashing on listing 500+
            # images without resource_group filter passed let's pass one now.
            # That is not a great solution, but without this cache population and ibmcloud usage is paralyzed,
            # so passing resource group it is.
            resource_group = self.pool_config.get('resource-group', 'Default')

            list_images_cmd = ['is', 'images', '--output', 'json', '--resource-group-name', resource_group]

            def _process_regex_filter(filter_name: str, filters: ConfigImageFilter) -> Optional[Pattern[Any]]:
                if filter_name not in filters:
                    return None
                return re.compile(filters[filter_name])  # type: ignore[literal-required]

            if filters:
                if 'visibility' in filters:
                    list_images_cmd.extend(['--visibility', filters['visibility']])
                if 'owner-type' in filters:
                    list_images_cmd.extend(['--owner-type', filters['owner-type']])
                if 'status' in filters:
                    list_images_cmd.extend(['--status', filters['status']])
                if 'user-data-format' in filters:
                    list_images_cmd.extend(['--user-data-format', filters['user-data-format']])

                try:
                    name_pattern = _process_regex_filter('name-regex', filters)
                    arch_pattern = _process_regex_filter('arch-regex', filters)
                except re.error as exc:
                    return Error(Failure.from_exc('failed to compile regex', exc))

            with IBMCloudSession(logger, self) as session:
                r_images_list = session.run(logger, list_images_cmd, commandname='ibmcloud.vm-image-list')

                if r_images_list.is_error:
                    return Error(
                        Failure.from_failure('failed to fetch image information', r_images_list.unwrap_error())
                    )

            images: list[PoolImageInfo] = []
            for image in cast(list[APIImageType], r_images_list.unwrap()):
                try:
                    # Apply wild-card filter if specified, unfortunately no way to filter by name or regex via cli
                    if name_pattern and not name_pattern.match(image['name']):
                        continue

                    arch = image['operating_system']['architecture']
                    if arch_pattern and not arch_pattern.match(arch):
                        continue
                    images.append(
                        IBMCloudVPCPoolImageInfo(
                            crn=image['crn'],
                            id=image['id'],
                            name=image['name'],
                            status=image['status'],
                            visibility=image['visibility'],
                            user_data_format=image['user_data_format'],
                            arch=arch,
                            boot=FlavorBoot(),
                            ssh=PoolImageSSHInfo(),
                            supports_kickstart=False,
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

    def fetch_pool_flavor_info(self) -> Result[list[Flavor], Failure]:
        # See https://cloud.ibm.com/docs/vpc?topic=vpc-vs-profiles&interface=cli for more info

        def _fetch(logger: gluetool.log.ContextAdapter) -> Result[list[dict[str, Any]], Failure]:
            with IBMCloudSession(self.logger, self) as session:
                r_flavors_list = session.run(
                    self.logger,
                    ['is', 'instance-profiles', '--output', 'json'],
                    commandname='ibmcloud.is-instance-profiles',
                )

                if r_flavors_list.is_error:
                    return Error(
                        Failure.from_failure('failed to fetch flavors information', r_flavors_list.unwrap_error())
                    )

            return Ok(cast(list[dict[str, Any]], r_flavors_list.unwrap()))

        def _constructor(
            logger: gluetool.log.ContextAdapter, raw_flavor: dict[str, Any]
        ) -> Iterator[Result[Flavor, Failure]]:
            raw_disks = cast(list[Any], raw_flavor.get('disks', []))

            if not raw_disks:
                # Yep, surprizingly enough ibmcloud has flavors with no disks, like bx2-2x8
                disks: list[FlavorDisk] = []

            else:
                # diskspace is reported in GB
                disks = [FlavorDisk(size=UNITS.Quantity(int(raw_disks[0]['size']['value']), UNITS.gigabytes))]

                if len(raw_disks) > 1:
                    disks.append(FlavorDisk(is_expansion=True, max_additional_items=len(raw_disks) - 1))

            networks = [FlavorNetwork(type='eth')]
            nic_limit = int(raw_flavor['max_nics'])

            if nic_limit > 1:
                networks.append(FlavorNetwork(type='eth', is_expansion=True, max_additional_items=nic_limit - 1))

            # Now that is awkward - looks like technically there can be multiple arch versions in a flavor, but
            # currently all flavors have exactly one arch if defined. Artemis Flavor.arch was designed to
            # contain one arch only, so let's begin by taking the first value in the os_architecture.values list.
            # We should not be taking the default value as the cli has (surprize!) amd64 default set for some
            # s390x-specific flavors like bz2e-1x4
            arch = raw_flavor['os_architecture'].get('values', [None])[0]

            yield Ok(
                IBMCloudFlavor(
                    name=raw_flavor['name'],
                    id=raw_flavor['name'],
                    cpu=FlavorCpu(processors=int(raw_flavor['vcpu_count']['value'])),
                    memory=UNITS.Quantity(int(raw_flavor['memory']['value']), UNITS.gibibytes),
                    disk=FlavorDisks(disks),
                    network=FlavorNetworks(networks),
                    virtualization=FlavorVirtualization(),
                    arch=arch,
                    numa_count=int(raw_flavor['numa_count'].get('value', 0)),
                )
            )

        return self.do_fetch_pool_flavor_info(
            self.logger, _fetch, lambda raw_flavor: cast(str, raw_flavor['name']), _constructor
        )

    def fetch_pool_resources_metrics(
        self, logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        subnet_id = self.pool_config['subnet-id']

        with IBMCloudSession(logger, self) as session:
            # Resource usage - instances and flavors
            def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[list[dict[str, Any]], Failure]:
                r_list_instances = session.run(
                    logger, ['is', 'instances', '--json'], commandname='ibm.is.instances-list'
                )

                if r_list_instances.is_error:
                    return Error(Failure.from_failure('Could not list instances', r_list_instances.unwrap_error()))

                return Ok(
                    [
                        raw_instance
                        for raw_instance in cast(list[dict[str, Any]], r_list_instances.unwrap())
                        if subnet_id
                        in [nics.get('subnet', {}).get('id') for nics in raw_instance.get('network_interfaces', [])]
                    ]
                )

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

                # ibmcloud is doesn't have info about cores per instance, but rather vcpus per instance. Anyway, will
                # be storing this info under cores
                usage.cores += int(raw_instance.get('vcpu', {}).get('count', 0))

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
                logger, ['is', 'subnet', subnet_id, '--json'], commandname='ibmcloud.is.show-network'
            )
            if r_show_network.is_error:
                return Error(Failure.from_failure('Could not get network metrics', r_show_network.unwrap_error()))

            network = cast(dict[str, Any], r_show_network.unwrap())

            # drop network address and broadcast
            resources.limits.networks[subnet_id] = PoolNetworkResources(
                addresses=int(network['total_ipv4_address_count']) - 2
            )
            # It's expected that used addresses won't precisely match number of instances on this network, as some
            # ips from the subnet range are additionally reserved for dns/dhcp/etc
            resources.usage.networks[subnet_id] = PoolNetworkResources(
                addresses=int(network['total_ipv4_address_count']) - int(network['available_ipv4_address_count'])
            )

        return Ok(resources)

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        # FIXME Again, that is massive code duplication -> same flavor/image pairs choosing algo is happeing in
        # other drivers.

        r_image_flavor_pairs = self._collect_image_flavor_pairs(logger, session, guest_request)

        if r_image_flavor_pairs.is_error:
            return Error(r_image_flavor_pairs.unwrap_error())

        can_acquire, pairs = r_image_flavor_pairs.unwrap()

        if not can_acquire.can_acquire:
            assert can_acquire.reason is not None

            return Error(Failure(can_acquire.reason.message))

        image, flavor = pairs[0]

        self.log_acquisition_attempt(logger, session, guest_request, flavor=flavor, image=image)

        r_tags = self.get_guest_tags(logger, session, guest_request)

        if r_tags.is_error:
            return Error(r_tags.unwrap_error())

        tags = r_tags.unwrap()

        # A combination of ArtemisGuestLabel-ArtemisGuestName doesn't pass the ibmcloud max name length, so let's cut
        # ArtemisGuestName to the first section and use this fragment together with ArtemisGuestLabel. This way the
        # result is definitely unique even on multiple simultaneous create requests for the same pool
        instance_name = f'{tags["ArtemisGuestLabel"]}-{tags["ArtemisGuestName"].split("-")[0]}'

        def _create(user_data_file: Optional[str] = None) -> Result[JSONType, Failure]:
            # get VPC id
            with IBMCloudSession(logger, self) as session:
                r_subnet_show = session.run(
                    logger,
                    ['is', 'subnet', self.pool_config['subnet-id'], '--output', 'json'],
                    commandname='ibmcloud-show-subnet',
                )
                if r_subnet_show.is_error:
                    return Error(
                        Failure.from_failure(
                            'Failed to execute show subnet details command', r_subnet_show.unwrap_error()
                        )
                    )

                try:
                    vpc_id = cast(dict[str, Any], r_subnet_show.unwrap())['vpc']['id']
                except KeyError:
                    return Error(Failure('Subnet details have no vpc information'))

                root_disk_size: Optional[SizeType] = None
                # If disk size is defined in flavor -> let's use it, otherwise take defaults from pool config
                if flavor.disk and flavor.disk[0].size is not None:
                    root_disk_size = flavor.disk[0].size
                else:
                    # let's take boot partition size from the driver config
                    if 'default-root-disk-size' in self.pool_config:
                        root_disk_size = UNITS.Quantity(self.pool_config['default-root-disk-size'], UNITS.gibibytes)

                # Now we are all set to create an instance
                create_cmd_args = [
                    'is',
                    'instance-create',
                    instance_name,
                    vpc_id,
                    self.pool_config['zone'],
                    flavor.id,
                    self.pool_config['subnet-id'],
                    '--image',
                    image.id,
                    '--allow-ip-spoofing=false',
                    '--keys',
                    self.pool_config['master-key-name'],
                    '--output',
                    'json',
                ]
                # If root_disk_size is specified will be passing specific --volume details
                if root_disk_size:
                    boot_volume_specs = {
                        'name': instance_name,
                        'volume': {
                            'capacity': int(root_disk_size.to('GiB').magnitude),
                            'profile': {'name': 'general-purpose'},
                        },
                    }
                    create_cmd_args += ['--boot-volume', json.dumps(boot_volume_specs)]

                if user_data_file:
                    create_cmd_args += ['--user-data', f'@{user_data_file}']

                r_instance_create = session.run(logger, create_cmd_args, commandname='ibmcloud.instance-create')

                if r_instance_create.is_error:
                    return Error(Failure.from_failure('Instance creation failed', r_instance_create.unwrap_error()))
                return r_instance_create

        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return Error(
                Failure.from_failure('Could not generate post-install script', r_post_install_script.unwrap_error())
            )

        post_install_script = r_post_install_script.unwrap()
        if post_install_script:
            with create_tempfile(file_contents=post_install_script) as user_data_file:
                r_output = _create(user_data_file)
        else:
            r_output = _create()

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        created = cast(dict[str, Any], r_output.unwrap())

        if not created['id']:
            return Error(Failure('Instance id not found'))

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=IBMCloudPoolData(instance_id=created['id'], instance_name=created['name']),
                ssh_info=image.ssh,
            )
        )

    def _show_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[Any, Failure]:
        instance_id = guest_request.pool_data.mine(self, IBMCloudPoolData).instance_id
        res: dict[str, Any] = {}

        if not instance_id:
            return Error(Failure('Need an instance ID to fetch any information about a guest'))

        with IBMCloudSession(logger, self) as session:
            r_instance_info = session.run(
                logger, ['is', 'instance', instance_id, '--output', 'json'], commandname='ibmcloud.vm-show'
            )

            if r_instance_info.is_error:
                return Error(
                    Failure.from_failure('failed to fetch instance information', r_instance_info.unwrap_error())
                )

            res = cast(dict[str, Any], r_instance_info.unwrap())

            # Now send another request to resource api to retrieve tags information
            r_resource_info = session.run(logger, ['resource', 'search', f'name:{res["name"]}', '--output', 'json'])

            if r_resource_info.is_error:
                return Error(
                    Failure.from_failure('failed to fetch resource information', r_resource_info.unwrap_error())
                )

            res['tags'] = cast(dict[str, Any], r_resource_info.unwrap()).get('tags')

        return Ok(res)

    def update_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """

        r_output = self._show_guest(logger, guest_request)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        pool_data = guest_request.pool_data.mine(self, IBMCloudPoolData)

        if not output['tags']:
            # No tags have been assigned yet, time to do that.
            # Tag the created instance. Unfortunately ibmcloud doesn't allow passing tags directly to the image
            # create command, and updating the instance via resource api during guest acquisition seems prone to
            # 'The resource is not found' errors. So will be tagging the instance that has no tags yet

            r_tags = self.get_guest_tags(logger, session, guest_request)

            if r_tags.is_error:
                return Error(r_tags.unwrap_error())

            r_tag_instance = self.tag_instance(instance_name=output['name'], tags=r_tags.unwrap(), logger=logger)

            if r_tag_instance.is_error:
                return Error(Failure.from_failure('Tagging instance failed', r_tag_instance.unwrap_error()))

        status = output['status'].lower()
        logger.info(f'current instance status {pool_data.instance_id}:{status}')

        if status == 'starting':
            return Ok(ProvisioningProgress(state=ProvisioningState.PENDING, pool_data=pool_data))

        if status == 'running':
            # Currently there is no support for public ips, so just taking primary ip
            ip_address = output['primary_network_interface']['primary_ip'].get('address')

            return Ok(ProvisioningProgress(state=ProvisioningState.COMPLETE, pool_data=pool_data, address=ip_address))

        # Let's consider all other states as something unexpected and thus a failure
        PoolMetrics.inc_error(self.poolname, IBMCloudVPCErrorCauses.UNEXPECTED_INSTANCE_STATE)

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=pool_data,
                pool_failures=[Failure(f'instance ended up in an unexpected state "{status}"')],
            )
        )

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, IBMCloudPoolData)

        if not pool_data:
            return Ok(None)

        return self.dispatch_resource_cleanup(
            logger, session, IBMCloudPoolResourcesIDs(instance_id=pool_data.instance_id), guest_request=guest_request
        )

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = IBMCloudPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.instance_id is not None:
            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

            with IBMCloudSession(logger, self) as session:
                r_delete_instance = session.run(
                    logger,
                    ['is', 'instance-delete', resource_ids.instance_id, '-f'],
                    json_format=False,
                    commandname='ibmcloud.instance-delete',
                )
                if r_delete_instance.is_error:
                    return Error(Failure.from_failure('Failed to cleanup instance', r_delete_instance.unwrap_error()))

        return Ok(ReleasePoolResourcesState.RELEASED)

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        pool_data = guest_request.pool_data.mine(self, IBMCloudPoolData)

        assert pool_data.instance_id is not None

        with IBMCloudSession(logger, self) as session:
            r_output = session.run(
                logger,
                ['is', 'instance-reboot', pool_data.instance_id, '--force', '--now-wait'],
                commandname='ibmcloud.instance-reboot',
            )

        if r_output.is_error:
            return Error(Failure.from_failure('failed to trigger instance reboot', r_output.unwrap_error()))

        return Ok(None)


PoolDriver._drivers_registry['ibmcloud-vpc'] = IBMCloudVPCDriver
