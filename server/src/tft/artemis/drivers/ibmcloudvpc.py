# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Pattern, Tuple, TypedDict, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from tft.artemis.drivers import CLISessionPermanentDir, PoolData, PoolDriver, PoolImageInfo, PoolResourcesIDs

from .. import Failure, JSONType, log_dict_yaml
from ..db import GuestRequest
from ..environment import UNITS, Flavor, FlavorBoot, FlavorCpu, FlavorDisk, FlavorDisks, FlavorNetwork, \
    FlavorNetworks, FlavorVirtualization
from ..knobs import Knob
from ..metrics import PoolNetworkResources, PoolResourcesMetrics, ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, HookImageInfoMapper, PoolImageSSHInfo, ProvisioningProgress, \
    ProvisioningState, SerializedPoolResourcesIDs, create_tempfile

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'ibmcloud.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-ibmcloud-vpc.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'ibmcloud.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

IBMCLOUD_RESOURCE_TYPE: Dict[str, ResourceType] = {
    'instance': ResourceType.VIRTUAL_MACHINE,
    'subnet': ResourceType.VIRTUAL_NETWORK,
    'volume': ResourceType.DISK,
    'floating-ip': ResourceType.STATIC_IP,
    'security-group': ResourceType.SECURITY_GROUP
}


class APIImageType(TypedDict):
    name: str
    crn: str
    id: str
    visibility: str
    user_data_format: str
    status: str
    operating_system: Dict[str, Any]


ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'visibility': str,
        'owner-type': str,
        'status': str,
        'user-data-format': str,
        'name-regex': str,
        'arch-regex': str
    },
    total=False
)


class IBMCloudSession(CLISessionPermanentDir):
    CLI_PREFIX = 'ibmcloud'
    CLI_CMD = 'ibmcloud'
    CLI_CONFIG_DIR_ENV_VAR = 'IBMCLOUD_HOME'

    PLUGINS_DIR = '.bluemix/plugins'

    def _login(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        assert self.pool.pool_config['api-key']
        r_login = self._run_cmd(
            logger,
            [
                'login',
                '--apikey', self.pool.pool_config['api-key'],
                '-r', self.pool.pool_config['default-region'],
                # Do not ask if existing plugins need update, trust the process
                '-q'
            ],
            json_format=False,
            commandname='ibmcloud.login'
        )
        if r_login.is_error:
            return Error(Failure.from_failure('failed to log into tenant', r_login.unwrap_error()))

        return Ok(None)

    def _prepare_session_dir(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        plugins_abspath = os.path.join(self.session_dir_path, self.PLUGINS_DIR)
        # If there is no plugins in the session dir -> need to install some for driver to work. Plugins directory will
        # be created after a call to login, but it will be holding just a configuration file. To make sure there
        # are plugins there we'll need to check for subdirectories in the plugins dir.
        try:
            if next(os.walk(plugins_abspath))[1]:
                return Ok(None)
        except StopIteration:
            # Well, the plugins directory is not there at all - definitely need to install something
            pass

        # Make sure pool configuration has installed-plugins-dir defined, then copy its contents under plugins_dir
        # as is
        assert self.pool.pool_config['installed-plugins-dir']
        try:
            shutil.copytree(self.pool.pool_config['installed-plugins-dir'], plugins_abspath)
        except (shutil.Error, OSError) as exc:
            return Error(Failure.from_exc('failed to copy plugins from pool config dir', exc))

        return Ok(None)


@dataclasses.dataclass
class IBMCloudPoolData(PoolData):
    instance_id: Optional[str] = None
    instance_name: Optional[str] = None


@dataclasses.dataclass
class IBMCloudPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    assorted_resource_ids: Optional[List[Dict[str, str]]] = None


@dataclasses.dataclass
class IBMCloudFlavor(Flavor):
    numa_count: Optional[int] = None


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


class IBMCloudVPCDriver(PoolDriver):
    drivername = 'ibmcloud-vpc'

    image_info_class = IBMCloudVPCPoolImageInfo
    flavor_info_class = IBMCloudFlavor
    pool_data_class = IBMCloudPoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)

    # TODO: return value does not match supertype - it should, it does, but mypy ain't happy: why?
    @property
    def image_info_mapper(self) -> HookImageInfoMapper[IBMCloudVPCPoolImageInfo]:  # type: ignore[override]
        return HookImageInfoMapper(self, 'IBMCLOUD_VPC_ENVIRONMENT_TO_IMAGE')

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[List[PoolImageInfo], Failure]:
            name_pattern: Optional[Pattern[str]] = None
            arch_pattern: Optional[Pattern[str]] = None

            logger = self.logger
            list_images_cmd = ['is', 'images', '--output', 'json']

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
                r_images_list = session.run(
                    logger,
                    list_images_cmd,
                    commandname='ibmcloud.vm-image-list'
                )

                if r_images_list.is_error:
                    return Error(Failure.from_failure(
                        'failed to fetch image information',
                        r_images_list.unwrap_error()
                    ))

            images: List[PoolImageInfo] = []
            for image in cast(List[APIImageType], r_images_list.unwrap()):
                try:
                    # Apply wild-card filter if specified, unfortunately no way to filter by name or regex via cli
                    if name_pattern and not name_pattern.match(image['name']):
                        continue

                    arch = image['operating_system']['architecture']
                    if arch_pattern and not arch_pattern.match(arch):
                        continue
                    images.append(IBMCloudVPCPoolImageInfo(
                        crn=image['crn'],
                        id=image['id'],
                        name=image['name'],
                        status=image['status'],
                        visibility=image['visibility'],
                        user_data_format=image['user_data_format'],
                        arch=arch,
                        boot=FlavorBoot(),
                        ssh=PoolImageSSHInfo(),
                        supports_kickstart=False
                    ))
                except KeyError as exc:
                    return Error(Failure.from_exc(
                        'malformed image description',
                        exc,
                        image_info=r_images_list.unwrap()
                    ))

            log_dict_yaml(self.logger.debug, 'image filters', filters)
            log_dict_yaml(self.logger.debug, 'found images', [image.name for image in images])

            return Ok(images)

        images: List[PoolImageInfo] = []
        image_filters = cast(List[ConfigImageFilter], self.pool_config.get('image-filters', []))

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

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
        # See https://cloud.ibm.com/docs/vpc?topic=vpc-vs-profiles&interface=cli for more info

        with IBMCloudSession(self.logger, self) as session:
            r_flavors_list = session.run(
                self.logger,
                ['is', 'instance-profiles', '--output', 'json'],
                commandname='ibmcloud.is-instance-profiles'
            )

            if r_flavors_list.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch flavors information',
                    r_flavors_list.unwrap_error()))

        flavors = r_flavors_list.unwrap()

        flavor_name_pattern: Optional[Pattern[str]] = None
        if self.pool_config.get('flavor-regex'):
            try:
                flavor_name_pattern = re.compile(self.pool_config['flavor-regex'])
            except re.error as exc:
                return Error(Failure.from_exc('failed to compile regex', exc))

        ibmcloud_flavors: List[Flavor] = []

        for flavor in cast(List[Dict[str, Any]], flavors):
            try:
                if flavor_name_pattern is not None and not flavor_name_pattern.match(flavor['name']):
                    continue
                max_data_disk_count = len(flavor.get('disks', []))
                if not max_data_disk_count:
                    # Yep, surprizingly enough ibmcloud has flavors with no disks, like bx2-2x8
                    disks = []
                else:
                    # diskspace is reported in GB
                    disks = [FlavorDisk(size=UNITS.Quantity(int(flavor['disks'][0]['size']['value']),
                                                            UNITS.gigabytes))]
                    if max_data_disk_count > 1:
                        disks.append(FlavorDisk(is_expansion=True, max_additional_items=max_data_disk_count - 1))

                networks = [FlavorNetwork(type='eth')]
                nic_limit = int(flavor['max_nics'])

                if nic_limit > 1:
                    networks.append(FlavorNetwork(type='eth', is_expansion=True, max_additional_items=nic_limit - 1))

                # Now that is awkward - looks like technically there can be multiple arch versions in a flavor, but
                # currently all flavors have exactly one arch if defined. Artemis Flavor.arch was designed to
                # contain one arch only, so let's begin by taking the first value in the os_architecture.values list.
                # We should not be taking the default value as the cli has (surprize!) amd64 default set for some
                # s390x-specific flavors like bz2e-1x4
                arch = flavor['os_architecture'].get('values', [None])[0]

                ibmcloud_flavors.append(
                    IBMCloudFlavor(
                        name=flavor['name'],
                        id=flavor['name'],
                        cpu=FlavorCpu(
                            processors=int(flavor['vcpu_count']['value'])
                        ),
                        memory=UNITS.Quantity(int(flavor['memory']['value']), UNITS.gibibytes),
                        disk=FlavorDisks(disks),
                        network=FlavorNetworks(networks),
                        virtualization=FlavorVirtualization(),
                        arch=arch,
                        numa_count=int(flavor['numa_count'].get('value', 0)),
                    )
                )
            except KeyError as exc:
                return Error(Failure.from_exc(
                    'malformed flavor description',
                    exc,
                    flavor_info=flavors
                ))

        return Ok(ibmcloud_flavors)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        resources.usage.instances = 0
        resources.usage.cores = 0
        resources.usage.memory = 0

        subnet_id = self.pool_config['subnet-id']

        with IBMCloudSession(logger, self) as session:
            # Let's count instances on pool network
            r_list_instances = session.run(
                logger,
                ['is', 'instances', '--json'],
                commandname='ibm.is.instances-list'
            )
            if r_list_instances.is_error:
                return Error(Failure.from_failure('Could not list instances', r_list_instances.unwrap_error()))

            instances = cast(List[Dict[str, Any]], r_list_instances.unwrap())
            for instance in instances:
                # Filter out instances not on pool network
                if subnet_id not in [nic.get('subnet', {}).get('id')
                                     for nic in instance.get('network_interfaces', [])]:
                    continue

                resources.usage.instances += 1
                # ibmcloud is doesn't have info about cores per instance, but rather vcpus per instance. Anyway, will
                # be storing this info under cores
                resources.usage.cores += int(instance.get('vcpu', {}).get('count', 0))
                # Instance memory is in GB
                resources.usage.memory += int(instance['memory']) * 1073741824

            # Get pool network metrics
            r_show_network = session.run(
                logger,
                ['is', 'subnet', subnet_id, '--json'],
                commandname='ibmcloud.is.show-network'
            )
            if r_show_network.is_error:
                return Error(Failure.from_failure('Could not get network metrics', r_show_network.unwrap_error()))

            network = cast(Dict[str, Any], r_show_network.unwrap())

            # drop network address and broadcast
            resources.limits.networks[subnet_id] = PoolNetworkResources(
                addresses=int(network['total_ipv4_address_count']) - 2)
            # It's expected that used addresses won't precisely match number of instances on this network, as some
            # ips from the subnet range are additionally reserved for dns/dhcp/etc
            resources.usage.networks[subnet_id] = PoolNetworkResources(
                addresses=int(network['total_ipv4_address_count']) - int(network['available_ipv4_address_count']))

        return Ok(resources)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[Tuple[bool, Optional[str]], Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """

        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap()[0] is False:
            return r_answer

        if guest_request.environment.has_hw_constraints is True:
            return Ok((False, 'HW constraints are not supported'))

        r_images = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if not images:
            return Ok((False, 'compose not supported'))

        return Ok((True, None))

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def _env_to_instance_type(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        image: IBMCloudVPCPoolImageInfo
    ) -> Result[IBMCloudFlavor, Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = cast(List[IBMCloudFlavor], r_suitable_flavors.unwrap())

        suitable_flavors = self.filter_flavors_image_arch(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        # NOTE(ivasilev) hardware requirements not supported atm so skipping all related flavor filtering

        # FIXME The whole default flavor dance is identical between Azure / aws / openstack / now ibmcloud and is
        # the candidate for generalization.
        if not suitable_flavors:
            if self.pool_config.get('use-default-flavor-when-no-suitable', True):
                guest_request.log_warning_event(
                    logger,
                    session,
                    'no suitable flavors, using default',
                    poolname=self.poolname
                )

                r_default_flavor = self._map_environment_to_flavor_info_by_cache_by_name_or_none(
                    logger,
                    self.pool_config['default-flavor']
                )

                if r_default_flavor.is_error:
                    return Error(r_default_flavor.unwrap_error())

                return Ok(cast(IBMCloudFlavor, r_default_flavor.unwrap()))

            guest_request.log_warning_event(
                logger,
                session,
                'no suitable flavors',
                poolname=self.poolname
            )

            return Error(Failure('no suitable flavor'))

        if self.pool_config['default-flavor'] in [flavor.name for flavor in suitable_flavors]:
            logger.info('default flavor among suitable ones, using it')

            return Ok([
                flavor
                for flavor in suitable_flavors
                if flavor.name == self.pool_config['default-flavor']
            ][0])

        return Ok(suitable_flavors[0])

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

        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        return self._do_acquire_guest(
            logger,
            session,
            guest_request,
        )

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:

        # FIXME Again, that is massive code duplication -> same flavor/image pairs choosing algo is happeing in
        # other drivers.
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_images = self.image_info_mapper.map(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()
        pairs: List[Tuple[IBMCloudVPCPoolImageInfo, IBMCloudFlavor]] = []

        for image in images:
            r_instance_type = self._env_to_instance_type(logger, session, guest_request, image)
            if r_instance_type.is_error:
                return Error(r_instance_type.unwrap_error())

            pairs.append((image, r_instance_type.unwrap()))

        if not pairs:
            return Error(Failure('no suitable image/flavor combination found'))

        log_dict_yaml(logger.info, 'available image/flavor combinations', [
            {
                'flavor': flavor.serialize(),
                'image': image.serialize()
            } for image, flavor in pairs
        ])

        image, instance_type = pairs[0]

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
            flavor=instance_type,
            image=image
        )

        tags = self._get_instance_tags(logger, session, guest_request)
        if not tags:
            return Error(Failure('Could not determine instance name from tags'))

        # A combination of ArtemisGuestLabel-ArtemisGuestName doesn't pass the ibmcloud max name length, so let's cut
        # ArtemisGuestName to the first section and use this fragment together with ArtemisGuestLabel. This way the
        # result is definitely unique even on multiple simultaneous create requests for the same pool
        instance_name = f"{tags['ArtemisGuestLabel']}-{tags['ArtemisGuestName'].split('-')[0]}"

        def _create(user_data_file: Optional[str] = None) -> Result[JSONType, Failure]:
            # get VPC id
            with IBMCloudSession(logger, self) as session:
                r_subnet_show = session.run(
                    logger,
                    ['is', 'subnet', self.pool_config['subnet-id'], '--output', 'json'],
                    commandname='ibmcloud-show-subnet'
                )
                if r_subnet_show.is_error:
                    return Error(Failure.from_failure('Failed to execute show subnet details command',
                                                      r_subnet_show.unwrap_error()))

                try:
                    vpc_id = cast(Dict[str, Any], r_subnet_show.unwrap())['vpc']['id']
                except KeyError:
                    return Error(Failure('Subnet details have no vpc information'))

                # Now we are all set to create an instance
                create_cmd_args = [
                    'is', 'instance-create',
                    instance_name,
                    vpc_id,
                    self.pool_config['zone'],
                    instance_type.name,
                    self.pool_config['subnet-id'],
                    '--image', image.id,
                    '--allow-ip-spoofing=false',
                    '--keys', self.pool_config['master-key-name'],
                    '--output', 'json'
                ]
                if user_data_file:
                    create_cmd_args += ['--user-data', f'@{user_data_file}']

                r_instance_create = session.run(
                    logger,
                    create_cmd_args,
                    commandname='ibmcloud.instance-create'
                )

                if r_instance_create.is_error:
                    return Error(Failure.from_failure('Instance creation failed', r_instance_create.unwrap_error()))
                return r_instance_create

        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return Error(Failure.from_failure('Could not generate post-install script',
                                              r_post_install_script.unwrap_error()))

        post_install_script = r_post_install_script.unwrap()
        if post_install_script:
            with create_tempfile(file_contents=post_install_script) as user_data_file:
                r_output = _create(user_data_file)
        else:
            r_output = _create()

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        created = cast(Dict[str, Any], r_output.unwrap())

        if not created['id']:
            return Error(Failure('Instance id not found'))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=IBMCloudPoolData(instance_id=created['id'], instance_name=created['name']),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

    def _show_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[Any, Failure]:
        instance_id = IBMCloudPoolData.unserialize(guest_request).instance_id
        res: Dict[str, Any] = {}

        if not instance_id:
            return Error(Failure('Need an instance ID to fetch any information about a guest'))

        with IBMCloudSession(logger, self) as session:
            r_instance_info = session.run(
                logger,
                ['is', 'instance', instance_id, '--output', 'json'],
                commandname='ibmcloud.vm-show')

            if r_instance_info.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch instance information',
                    r_instance_info.unwrap_error()
                ))

            res = cast(Dict[str, Any], r_instance_info.unwrap())

            # Now send another request to resource api to retrieve tags information
            r_resource_info = session.run(
                logger,
                ['resource', 'search', f'name:{res["name"]}', '--output', 'json']
            )

            if r_resource_info.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch resource information',
                    r_resource_info.unwrap_error()
                ))

            res['tags'] = cast(Dict[str, Any], r_resource_info.unwrap()).get('tags')

        return Ok(res)

    def _get_instance_tags(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Dict[str, str]:
        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return {}

        def _sanitize(a_tag: str) -> str:
            # NOTE(ivasilev) IBMCloud is petty about allowed characters in tags - only [A-Z][0-9] _-.: are allowed.
            # COLDSTORE_URL is the one of our typical tags that it doesn't play nice with, so will be replacing all
            # forbidden characters with prefixes.
            for char in [',', ':', '/']:
                a_tag = a_tag.replace(char, '_')
            return a_tag

        return {
            _sanitize(t): _sanitize(v) for t, v in r_base_tags.unwrap().items()
        }

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_output = self._show_guest(logger, guest_request)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        pool_data = IBMCloudPoolData.unserialize(guest_request)

        if not output['tags']:
            # No tags have been assigned yet, time to do that.
            # Tag the created instance. Unfortunately ibmcloud doesn't allow passing tags directly to the image
            # create command, and updating the instance via resource api during guest acquisition seems prone to
            # 'The resource is not found' errors. So will be tagging the instance that has no tags yet

            tags = self._get_instance_tags(logger, session, guest_request)
            if not tags:
                return Error(Failure('Could not determine instance tags'))

            # This tag links our VM and its resources, which comes handy when we want to remove everything
            # leaving no leaks.
            tags['uid'] = tags['ArtemisGuestLabel']

            with IBMCloudSession(logger, self) as ibm_session:
                r_tag_instance = ibm_session.run(
                    logger,
                    [
                        'resource', 'tag-attach',
                        '--tag-names', ','.join([f'{tag}:{value}' for tag, value in tags.items()]),
                        '--resource-name', output['name'],
                    ],
                    json_format=False,
                    commandname='ibmcloud.tag-attach'
                )

                if r_tag_instance.is_error:
                    return Error(Failure.from_failure('Tagging instance failed', r_tag_instance.unwrap_error()))

        status = output['status'].lower()
        logger.info(f'current instance status {pool_data.instance_id}:{status}')

        if status == 'starting':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=pool_data,
                delay_update=r_delay.unwrap()
            ))

        if status == 'running':
            # Currently there is no support for public ips, so just taking primary ip
            ip_address = output['primary_network_interface']['primary_ip'].get('address')

            return Ok(ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=pool_data,
                address=ip_address
            ))

        # Let's consider all other states as something unexpected and thus a failure
        return Ok(ProvisioningProgress(
            state=ProvisioningState.CANCEL,
            pool_data=pool_data,
            pool_failures=[Failure(f'instance ended up in an unexpected state "{status}"')]
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """
        if IBMCloudPoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = IBMCloudPoolData.unserialize(guest_request)

        with IBMCloudSession(logger, self) as session:
            r_tagged_resources = session.run(
                logger,
                [
                    'resource', 'search', f'tags:"uid:{pool_data.instance_name}"',
                    '--output', 'json'
                ],
                commandname='az.resource-list'
            )
            if r_tagged_resources.is_error:
                return Error(r_tagged_resources.unwrap_error())

        tagged_resources = r_tagged_resources.unwrap()

        # For now there is no resources to cleanup, keeping this here just for consistency with other drivers

        assorted_resource_ids = [
            res for res in cast(Dict[str, Any], tagged_resources)['items'] if res['resource_type'] != 'instance'
        ]

        r_cleanup = self._dispatch_resource_cleanup(
            logger,
            *assorted_resource_ids,
            instance_id=pool_data.instance_id,
            guest_request=guest_request
        )

        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())

        return Ok(True)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        *other_resources: Any,
        instance_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = IBMCloudPoolResourcesIDs(
            instance_id=instance_id,
            assorted_resource_ids=list(other_resources) if other_resources else None
        )

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:

        resource_ids = IBMCloudPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.instance_id is not None:
            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

            with IBMCloudSession(logger, self) as session:
                r_delete_instance = session.run(
                    logger,
                    ['is', 'instance-delete', resource_ids.instance_id, '-f'],
                    json_format=False,
                    commandname='ibmcloud.instance-delete'
                )
                if r_delete_instance.is_error:
                    return Error(Failure.from_failure('Failed to cleanup instance', r_delete_instance.unwrap_error()))

        return Ok(None)

    def trigger_reboot(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        pool_data = IBMCloudPoolData.unserialize(guest_request)

        assert pool_data.instance_id is not None

        with IBMCloudSession(logger, self) as session:
            r_output = session.run(
                logger,
                ['is', 'instance-reboot', pool_data.instance_id, '--force', '--now-wait'],
                commandname='ibmcloud.instance-reboot')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to trigger instance reboot',
                r_output.unwrap_error()
            ))

        return Ok(None)


PoolDriver._drivers_registry['ibmcloud-vpc'] = IBMCloudVPCDriver
