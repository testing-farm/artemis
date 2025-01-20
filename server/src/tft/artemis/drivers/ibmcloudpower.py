# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple, TypedDict, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from tft.artemis.drivers import PoolDriver, PoolImageInfo
from tft.artemis.drivers.ibmcloudvpc import IBMCloudPoolData, IBMCloudPoolResourcesIDs, IBMCloudSession

from .. import Failure, JSONType, log_dict_yaml
from ..db import GuestRequest
from ..environment import UNITS, And, Constraint, ConstraintBase, Flavor, FlavorBoot, SizeType
from ..knobs import Knob
from ..metrics import PoolNetworkResources, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from . import (
    KNOB_UPDATE_GUEST_REQUEST_TICK,
    HookImageInfoMapper,
    PoolCapabilities,
    PoolImageSSHInfo,
    ProvisioningProgress,
    ProvisioningState,
    SerializedPoolResourcesIDs,
    create_tempfile,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'ibmcloud-power.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-ibmcloud-power.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'ibmcloud-power.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'name-regex': str,
    },
    total=False
)


class APIImageType(TypedDict):
    name: str
    href: str
    imageID: str
    specifications: Dict[str, Any]


class IBMCloudPowerSession(IBMCloudSession):
    def _login(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        # Login can be reused from parent class as is but need to additionally set the target workspace

        login_result = super()._login(logger)
        if login_result.is_error:
            return login_result

        r_set_target_workspace = self._run_cmd(
            logger,
            [
                'pi', 'workspace',
                'target', self.pool.pool_config['workspace-crn']
            ],
            json_format=False,
            commandname='ibmcloud.workspace-target'
        )
        if r_set_target_workspace.is_error:
            return Error(Failure.from_failure('failed to set target workspace', r_set_target_workspace.unwrap_error()))

        return Ok(None)


@dataclasses.dataclass(repr=False)
class IBMCloudPowerPoolImageInfo(PoolImageInfo):
    # A super long identifier like
    # /pcloud/v1/cloud-instances/f60e5369884840cd85c1490f4fb506eb/images/b44fe39f-3ec4-4baa-ada5-cbd56acaec1d
    href: str


class IBMCloudPowerDriver(PoolDriver):
    drivername = 'ibmcloud-power'

    image_info_class = IBMCloudPowerPoolImageInfo
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
    def image_info_mapper(self) -> HookImageInfoMapper[IBMCloudPowerPoolImageInfo]:  # type: ignore[override]
        return HookImageInfoMapper(self, 'IBMCLOUD_POWER_ENVIRONMENT_TO_IMAGE')

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        return self._map_image_name_to_image_info_by_cache(logger, imagename)

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = False
        capabilities.supports_native_post_install_script = True

        return Ok(capabilities)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[List[PoolImageInfo], Failure]:
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
                    logger,
                    ['pi', 'image', 'list-catalog', '-s', '--json'],
                    commandname='ibmcloud.pi-image-list'
                )

                if r_images_list.is_error:
                    return Error(Failure.from_failure(
                        'failed to fetch image information',
                        r_images_list.unwrap_error()
                    ))

            images: List[PoolImageInfo] = []
            for image in cast(List[APIImageType], cast(Dict[str, Any], r_images_list.unwrap()).get('images', [])):
                try:
                    # Apply wild-card filter if specified, unfortunately no way to filter by name or regex via cli
                    if name_pattern and not name_pattern.match(image['name']):
                        continue

                    arch = image['specifications']['architecture']
                    if arch_pattern and not arch_pattern.match(arch):
                        continue

                    images.append(IBMCloudPowerPoolImageInfo(
                        href=image['href'],
                        id=image['imageID'],
                        name=image['name'],
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

    def _translate_constraints_to_cli_args(
        self,
        constraint: Optional[ConstraintBase],
    ) -> Result[List[str], Failure]:
        """
        Convert a given constraint to a set of filters that IBM Cloud supports (there are not many, mostly cpu / disk).
        """

        if not constraint:
            return Ok([])

        if isinstance(constraint, And):
            res: List[str] = []

            for child_constraint in constraint.constraints:
                r_child_element = self._translate_constraints_to_cli_args(child_constraint)

                if r_child_element.is_error:
                    return Error(r_child_element.unwrap_error())

                res += r_child_element.unwrap()

            return Ok(res)

        constraint = cast(Constraint, constraint)
        constraint_name = constraint.expand_name()

        # IBM cloud cli expects only list of strings - thus the str conversion of args
        if constraint_name.property == 'cpu':
            if constraint_name.child_property == 'cores':
                return Ok(['--virtual-cores', str(int(constraint.value))])
            if constraint_name.child_property == 'processors':
                return Ok(['--processors', str(float(constraint.value))])
            else:
                # other cpu properties, like ex. stepping, are not supported, so let's raise a clear error
                return Error(Failure('constraint not supported by driver', constraint=repr(constraint),
                                     constraint_name=constraint.name))
        elif constraint_name.property == 'memory':
            # Although not mentioned in the docs, there are minimal constraints here, the amount of memory cannot be
            # less than 2 GB. So need to take that into consideration.
            return Ok([
                '--memory',
                str(max(float(cast(SizeType, constraint.value).to('GB').magnitude), 2))
            ])
        else:
            # Nothing else is supported yet
            return Error(Failure('constraint not supported by driver', constraint=repr(constraint),
                                 constraint_name=constraint.name))

        return Ok(res)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[Tuple[bool, Optional[str]], Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.

        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bool, Failure]
        :returns: Ok with True if guest can be acquired.
        """

        # Largely borrowed code from beaker driver

        # First, check the parent class, maybe its tests already have the answer.
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap()[0] is False:
            return r_answer

        r_images = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if not images:
            return Ok((False, 'compose not supported'))

        # The driver does not support kickstart natively. Filter only images we can perform ks install on.
        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

            if not images:
                return Ok((False, 'compose does not support kickstart'))

        # Parent implementation does not care, but we still might: support for HW constraints is still
        # far from being complete and fully tested, therefore we should check whether we are able to
        # convert the constraints - if there are any - to a Beaker XML filter.

        if not guest_request.environment.has_hw_constraints:
            return Ok((True, None))

        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()

        # since `has_hw_constraints` was positive, there should be constraints...
        assert constraints is not None

        # TODO: copy helpers from tmt for this kind of filtering
        supported_constraints: List[str] = [
            'cpu.processors',
            'cpu.cores',
            'memory',
        ]

        for span in constraints.spans(logger):
            for constraint in span:
                if constraint.expand_name().spec_name not in supported_constraints:
                    return Ok((False, f'HW requirement {constraint.expand_name().spec_name} is not supported'))

        r_filter = self._translate_constraints_to_cli_args(constraints)

        if r_filter.is_error:
            return Error(r_filter.unwrap_error())

        return Ok((True, None))

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        subnet_id = self.pool_config['subnet-id']

        with IBMCloudPowerSession(logger, self) as session:
            # Resource usage - instances and flavors
            def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[List[Dict[str, Any]], Failure]:
                r_list_instances = session.run(
                    logger,
                    ['pi', 'instance', 'list', '--json'],
                    commandname='ibmcloud.power.instances-list'
                )

                if r_list_instances.is_error:
                    return Error(Failure.from_failure(
                        'Could not list instances',
                        r_list_instances.unwrap_error()
                    ))

                raw_instances: List[Dict[str, Any]] = []

                for raw_instance_entry in cast(
                    List[Dict[str, Any]],
                    cast(Dict[str, Any], r_list_instances.unwrap()).get('pwmInstances', [])
                ):
                    # To get network details need to additionally get instance details
                    r_show_instance = self._show_guest(logger, raw_instance_entry['id'])

                    if r_show_instance.is_error:
                        return Error(Failure.from_failure(
                            'Could not get instance details',
                            r_show_instance.unwrap_error(),
                            raw_instance_entry=raw_instance_entry
                        ))

                    raw_instance = r_show_instance.unwrap()

                    # Filter out instances not on pool network
                    if subnet_id not in raw_instance['networkIDs']:
                        continue

                    raw_instances.append(raw_instance)

                return Ok(raw_instances)

            def _update_instance_usage(
                logger: gluetool.log.ContextAdapter,
                usage: PoolResourcesUsage,
                raw_instance: Dict[str, Any],
                flavor: Optional[Flavor]
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
                _update_instance_usage
            )

            if r_instances_usage.is_error:
                return Error(r_instances_usage.unwrap_error())

            # Get pool network metrics
            r_show_network = session.run(
                logger,
                ['pi', 'subnet', 'get', subnet_id, '--json'],
                commandname='ibmcloud.power.show-network'
            )
            if r_show_network.is_error:
                return Error(Failure.from_failure('Could not get network metrics', r_show_network.unwrap_error()))

            network = cast(Dict[str, Any], r_show_network.unwrap())

            resources.limits.networks[subnet_id] = PoolNetworkResources(addresses=network['ipAddressMetrics']['total'])
            resources.usage.networks[subnet_id] = PoolNetworkResources(addresses=network['ipAddressMetrics']['used'])

        return Ok(resources)

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:

        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_images = self.image_info_mapper.map(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()

        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

        image = images[0]

        # In a typical driver there would be a flavor selection, but looks like ibmcloud power doesn't have a concept
        # of flavors, instead one is specifying the number of cores / memory (in Gb) requested.
        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        r_constraint_args = self._translate_constraints_to_cli_args(r_constraints.unwrap())
        if r_constraint_args.is_error:
            return Error(r_constraint_args.unwrap_error())

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
            image=image
        )

        # A combination of ArtemisGuestLabel-ArtemisGuestName doesn't pass the ibmcloud max name length, so let's cut
        # to just ArtemisGuestName that is definitely unique even on multiple simultaneous create requests for the same
        # pool
        r_base_tags = self.get_guest_tags(logger, session, guest_request)
        if r_base_tags.is_error:
            return Error(Failure('Could not determine instance name from tags'))

        tags = {
            **r_base_tags.unwrap(),
        }
        instance_name = f"{tags['ArtemisGuestLabel']}-{tags['ArtemisGuestName'].split('-')[0]}"

        def _create(user_data_file: Optional[str] = None) -> Result[JSONType, Failure]:
            with IBMCloudPowerSession(logger, self) as session:
                create_cmd_args = [
                    'pi', 'instance', 'create',
                    instance_name,
                    '--subnets', self.pool_config['subnet-id'],
                    '--image', image.id,
                    '--key-name', self.pool_config['master-key-name'],
                    '--json',
                ] + r_constraint_args.unwrap()
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

        created = cast(List[Dict[str, Any]], r_output.unwrap())[0]

        if not created.get('pvmInstanceID'):
            return Error(Failure('Instance id not found'))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=IBMCloudPoolData(instance_id=created['pvmInstanceID'], instance_name=created['serverName']),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))

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

        instance_id = IBMCloudPoolData.unserialize(guest_request).instance_id
        if not instance_id:
            return Error(Failure('Need an instance id to fetch any information about a guest'))

        r_output = self._show_guest(logger, instance_id)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        pool_data = IBMCloudPoolData.unserialize(guest_request)

        status = output['status'].lower()
        logger.info(f'current instance status {pool_data.instance_id}:{status}')

        if status == 'build':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=pool_data,
                delay_update=r_delay.unwrap()
            ))

        if status == 'active':
            # Will be taking ip of the network interface for the pool config network
            ip_address = next((addr['ipAddress'] for addr in output['addresses']
                               if addr['networkID'] == self.pool_config['subnet-id']), None)

            if not ip_address:
                return Error(Failure('VM has reached active state but no ip address can be retrieved'))

            return Ok(ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=pool_data,
                address=ip_address
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.CANCEL,
            pool_data=pool_data,
            pool_failures=[Failure(f'instance ended up in an unexpected state "{status}"')]
        ))

    def _show_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_id: str
    ) -> Result[Dict[str, Any], Failure]:
        with IBMCloudPowerSession(logger, self) as session:
            r_instance_info = session.run(
                logger,
                ['pi', 'instance', 'get', instance_id, '--json'],
                commandname='ibmcloud.pi.vm-show')

            if r_instance_info.is_error:
                return Error(Failure.from_failure(
                    'failed to fetch instance information',
                    r_instance_info.unwrap_error()
                ))

            res = cast(Dict[str, Any], r_instance_info.unwrap())

            # XXX FIXME God knows who has woken upon to a brilliant idea to NOT allow tagging instances upon creation,
            # but the VPC hack of tagging resources won't work here as pi instances are not shown in ibm resource list.
            # So leaving for now without any tags

            return Ok(res)

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        if IBMCloudPoolData.is_empty(guest_request):
            return Ok(None)

        pool_data = IBMCloudPoolData.unserialize(guest_request)

        # there should be a list of assorted vm resources, but given the fact there are no tags yet /
        # cumulative pi resources overview it will be empty
        # assorted_resource_ids: List[Dict[str, str]] = []

        return self.dispatch_resource_cleanup(
            logger,
            session,
            IBMCloudPoolResourcesIDs(instance_id=pool_data.instance_id),
            guest_request=guest_request
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:

        resource_ids = IBMCloudPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.instance_id is not None:
            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

            with IBMCloudPowerSession(logger, self) as session:
                r_delete_instance = session.run(
                    logger,
                    ['pi', 'instance', 'delete', resource_ids.instance_id],
                    json_format=False,
                    commandname='ibmcloud.pi.instance-delete'
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

        with IBMCloudPowerSession(logger, self) as session:
            r_output = session.run(
                logger,
                ['pi', 'instance', 'action', '-o', 'hard-reboot', pool_data.instance_id],
                commandname='ibmcloud.pi.vm-reboot')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to trigger instance reboot',
                r_output.unwrap_error()
            ))

        return Ok(None)


PoolDriver._drivers_registry['ibmcloud-power'] = IBMCloudPowerDriver
