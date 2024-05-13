# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import os
import re
import tempfile
import threading
from typing import Any, Dict, List, Optional, Pattern, Tuple, TypedDict, Union, cast

import gluetool.log
import gluetool.utils
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from tft.artemis.drivers.aws import awscli_error_cause_extractor

from .. import Failure, JSONType, log_dict_yaml, render_template
from ..db import GuestRequest, SnapshotRequest
from ..environment import UNITS, Flavor, FlavorBoot, FlavorCpu, FlavorDisk, FlavorDisks, FlavorNetwork, \
    FlavorNetworks, FlavorVirtualization, SizeType
from ..knobs import Knob
from ..metrics import ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, HookImageInfoMapper, PoolCapabilities, PoolData, PoolDriver, \
    PoolImageInfo, PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, ProvisioningState, \
    SerializedPoolResourcesIDs, create_tempfile, run_cli_tool, vm_info_to_ip

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'azure.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AZURE_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-azure.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'azure.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AZURE_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

KNOB_RESOURCE_GROUP_NAME_TEMPLATE: Knob[str] = Knob(
    'azure.mapping.resource-group-name.template',
    'A pattern for guest resource group name',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_AZURE_RESOURCE_GROUP_NAME_TEMPLATE',
    cast_from_str=str,
    default='{{ TAGS.ArtemisGuestLabel }}-{{ GUESTNAME }}'
)


AZURE_RESOURCE_TYPE: Dict[str, ResourceType] = {
    'Microsoft.Compute/virtualMachines': ResourceType.VIRTUAL_MACHINE,
    'Microsoft.Network/virtualNetworks': ResourceType.VIRTUAL_NETWORK,
    'Microsoft.Compute/disks': ResourceType.DISK,
    'Microsoft.Network/publicIPAddresses': ResourceType.STATIC_IP,
    'Microsoft.Network/networkInterfaces': ResourceType.NETWORK_INTERFACE,
    'Microsoft.Network/networkSecurityGroups': ResourceType.SECURITY_GROUP
}


ConfigImageFilter = TypedDict(
    'ConfigImageFilter',
    {
        'name-regex': str,
        'offer': str,
        'publisher': str,
        'sku': str
    },
    total=False
)


class APIImageType(TypedDict):
    name: Optional[str]
    architecture: str
    offer: str
    publisher: str
    sku: str
    urn: str
    version: str


@dataclasses.dataclass
class AzurePoolData(PoolData):
    instance_id: str
    instance_name: str
    resource_group: str


@dataclasses.dataclass
class AzurePoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    assorted_resource_ids: Optional[List[Dict[str, str]]] = None
    resource_group: Optional[str] = None


@dataclasses.dataclass(repr=False)
class AzurePoolImageInfo(PoolImageInfo):
    offer: str
    publisher: str
    sku: str
    urn: str
    version: str


@dataclasses.dataclass(repr=False)
class AzureFlavor(Flavor):
    resource_disk_size: Optional[SizeType] = None

    def serialize(self) -> Dict[str, Any]:
        serialized = super().serialize()

        # is not None comparison to successfully serialize 0 MB
        if self.resource_disk_size is not None:
            serialized['resource_disk_size'] = str(self.resource_disk_size)

        return serialized

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'AzureFlavor':
        flavor = cast(AzureFlavor, super().unserialize(serialized))

        if serialized['resource_disk_size'] is not None:
            flavor.resource_disk_size = UNITS(serialized['resource_disk_size'])

        return flavor


class AzureSession:
    """
    A representation of a authenticated Azure session.

    Because it's not possible to pass credentials to distinct ``az`` commands,
    one needs to authenticate (``az login``), and then all future commands
    share credentials ``az`` stores in a configuration directory.

    This class uses ``AZURE_CONFIG_DIR`` to store credentials in a dedicated
    directory, all commands executed by the session would then share these
    credentials, which in turn enables concurrent use of ``az`` for different
    pools and guest requests.
    """

    def __init__(self, logger: gluetool.log.ContextAdapter, pool: 'AzureDriver') -> None:
        self.pool = pool

        # Create a temporary directory to serve as az' config directory.
        self.session_directory = tempfile.TemporaryDirectory(prefix=f'azure-{self.pool.poolname}')

        # Log into the tenant, and since we cannot raise an exception, save the result.
        # If we fail, any call to `run_az()` would return this saved result.
        self._login_result = self._login(logger)

    def __enter__(self) -> 'AzureSession':
        return self

    def __exit__(self, *args: Any) -> None:
        if self.session_directory is not None:
            self.session_directory.cleanup()

    def _run_cmd(
        self,
        logger: gluetool.log.ContextAdapter,
        options: List[str],
        json_format: bool = True,
        commandname: Optional[str] = None
    ) -> Result[Union[JSONType, str], Failure]:
        environ = {
            **os.environ,
            'AZURE_CONFIG_DIR': self.session_directory.name
        }

        r_run = run_cli_tool(
            logger,
            ['az'] + options,
            env=environ,
            json_output=json_format,
            command_scrubber=lambda cmd: (['azure'] + options),
            poolname=self.pool.poolname,
            commandname=commandname,
            cause_extractor=awscli_error_cause_extractor
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        if json_format:
            return Ok(r_run.unwrap().json)

        return Ok(r_run.unwrap().stdout)

    def _login(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        if self.pool.pool_config['username'] and self.pool.pool_config['password']:
            login_cmd = [
                'login',
                '--username', self.pool.pool_config['username'],
                '--password', self.pool.pool_config['password']
            ]
            if self.pool.pool_config['login'] == 'service-principal':
                login_cmd.extend(['--service-principal', '--tenant', self.pool.pool_config['tenant']])

            r_login = self._run_cmd(logger, login_cmd, commandname='az.login')

            if r_login.is_error:
                return Error(Failure.from_failure(
                    'failed to log into tenant',
                    r_login.unwrap_error()
                ))

        return Ok(None)

    def run_az(
        self,
        logger: gluetool.log.ContextAdapter,
        options: List[str],
        json_format: bool = True,
        commandname: Optional[str] = None
    ) -> Result[Union[JSONType, str], Failure]:
        if self._login_result is not None and self._login_result.is_error:
            return Error(self._login_result.unwrap_error())

        return self._run_cmd(logger, options, json_format, commandname=commandname)


class AzureDriver(PoolDriver):
    drivername = 'azure'

    image_info_class = AzurePoolImageInfo
    flavor_info_class = AzureFlavor
    pool_data_class = AzurePoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)

    # TODO: return value does not match supertype - it should, it does, but mypy ain't happy: why?
    @property
    def image_info_mapper(self) -> HookImageInfoMapper[AzurePoolImageInfo]:  # type: ignore[override]
        return HookImageInfoMapper(self, 'AZURE_ENVIRONMENT_TO_IMAGE')

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = False
        capabilities.supports_native_post_install_script = True

        return Ok(capabilities)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        *other_resources: Any,
        instance_id: Optional[str] = None,
        resource_group: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = AzurePoolResourcesIDs(
            instance_id=instance_id,
            assorted_resource_ids=list(other_resources) if other_resources else None,
            resource_group=resource_group
        )

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

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
        image: AzurePoolImageInfo
    ) -> Result[AzureFlavor, Failure]:
        r_suitable_flavors = self._map_environment_to_flavor_info_by_cache_by_constraints(
            logger,
            guest_request.environment
        )

        if r_suitable_flavors.is_error:
            return Error(r_suitable_flavors.unwrap_error())

        suitable_flavors = cast(List[AzureFlavor], r_suitable_flavors.unwrap())

        suitable_flavors = self.filter_flavors_image_arch(
            logger,
            session,
            guest_request,
            image,
            suitable_flavors
        )

        # NOTE(ivasilev) hardware requirements not supported atm so skipping all related flavor filtering

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

                return Ok(cast(AzureFlavor, r_default_flavor.unwrap()))

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

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        # NOTE(ivasilev) As all of the vm resources belong to the same resource_group, removing it will effectively
        # clean everything up. Calls to iterative one-by-one resource listing are left here only for the purpose of
        # incurring costs

        resource_ids = AzurePoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.resource_group:
            # Actual removal
            with AzureSession(logger, self) as session:
                r_remove_resource_group = session.run_az(
                    logger,
                    ['group', 'delete', '--name', resource_ids.resource_group, '-y'],
                    commandname='az.group-delete',
                    json_format=False
                )
                if r_remove_resource_group.is_error:
                    return Error(Failure.from_failure('failed to remove resource group',
                                                      r_remove_resource_group.unwrap_error()))

        if resource_ids.instance_id is not None:
            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        if resource_ids.assorted_resource_ids is not None:
            for resource in resource_ids.assorted_resource_ids:
                self.inc_costs(logger, AZURE_RESOURCE_TYPE[resource['type']], resource_ids.ctime)

        return Ok(None)

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

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
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

        status = output['provisioningState'].lower()

        logger.info(f'current instance status {AzurePoolData.unserialize(guest_request).instance_id}:{status}')

        if status == 'failed':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=AzurePoolData.unserialize(guest_request),
                pool_failures=[Failure('instance ended up in "failed" state')]
            ))

        r_ip_address = vm_info_to_ip(output, 'publicIps')

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=AzurePoolData.unserialize(guest_request),
            address=r_ip_address.unwrap()
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """

        if AzurePoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = AzurePoolData.unserialize(guest_request)

        # NOTE(ivasilev) As Azure doesn't delete vm's resources (disk, secgroup, publicip) upon vm deletion
        # will need to delete stuff manually. Lifehack: query for tag uid=name used during vm creation
        with AzureSession(logger, self) as session:
            r_tagged_resources = session.run_az(
                logger,
                ['resource', 'list', '--tag', f'uid={pool_data.instance_name}'],
                commandname='az.resource-list'
            )

        if r_tagged_resources.is_error:
            return Error(r_tagged_resources.unwrap_error())

        tagged_resources = r_tagged_resources.unwrap()

        # delete vm first, resources second
        assorted_resource_ids = [
            res
            for res in cast(List[Dict[str, str]], tagged_resources)
            if res['type'] != 'Microsoft.Compute/virtualMachines'
        ]

        r_cleanup = self._dispatch_resource_cleanup(
            logger,
            *assorted_resource_ids,
            instance_id=pool_data.instance_id,
            resource_group=pool_data.resource_group,
            guest_request=guest_request
        )

        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())

        return Ok(True)

    def create_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Create snapshot of a guest.
        If the returned snapshot is not active, ``update_snapshot`` would be scheduled by Artemis core.

        :param SnapshotRequest snapshot_request: snapshot request to process
        :param Guest guest: a guest, which will be snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`artemis.snapshot.Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def update_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Update state of the snapshot.
        Called for unfinished snapshot.
        If snapshot status is active, snapshot request is evaluated as finished

        :param Snapshot snapshot: snapshot to update
        :param Guest guest: a guest, which was snapshoted
        :rtype: result.Result[Snapshot, Failure]
        :returns: :py:class:`result.result` with either :py:class:`artemis.snapshot.Snapshot`
            or specification of error.
        """
        raise NotImplementedError()

    def remove_snapshot(
        self,
        snapshot_request: SnapshotRequest,
    ) -> Result[bool, Failure]:
        """
        Remove snapshot from the pool.

        :param Snapshot snapshot: snapshot to remove
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """
        raise NotImplementedError()

    def restore_snapshot(
        self,
        guest_request: GuestRequest,
        snapshot_request: SnapshotRequest
    ) -> Result[bool, Failure]:
        """
        Restore the guest to the snapshot.

        :param SnapshotRequest snapshot_request: snapshot request to process
        :param Guest guest: a guest, which will be restored
        :rtype: result.Result[bool, Failure]
        :returns: :py:class:`result.result` with either `bool`
            or specification of error.
        """
        raise NotImplementedError()

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

        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        return self._do_acquire_guest(
            logger,
            session,
            guest_request,
            cancelled)

    def _show_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[Any, Failure]:
        with AzureSession(logger, self) as session:
            r_output = session.run_az(
                logger,
                ['vm', 'show', '-d', '--ids', AzurePoolData.unserialize(guest_request).instance_id],
                commandname='az.vm-show')

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to fetch instance information',
                r_output.unwrap_error()
            ))
        return Ok(r_output.unwrap())

    def fetch_pool_flavor_info(self) -> Result[List[Flavor], Failure]:
        # Flavors are described by az cli as
        # {
        #     "maxDataDiskCount": int,
        #     "memoryInMB": int,
        #     "name": str,
        #     "numberOfCores": int,
        #     "osDiskSizeInMB": int,
        #     "resourceDiskSizeInMB": int
        # }

        logger = self.logger
        list_flavors_cmd = ['vm', 'list-sizes', '--location', self.pool_config['default-location']]
        with AzureSession(logger, self) as session:
            r_flavors_list = session.run_az(
                logger,
                list_flavors_cmd,
                commandname='az.vm-flavors-list'
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

        azure_flavors: List[Flavor] = []

        for flavor in cast(List[Dict[str, str]], flavors):
            try:
                if flavor_name_pattern is not None and not flavor_name_pattern.match(flavor['name']):
                    continue
                max_data_disk_count = int(flavor['maxDataDiskCount'])
                # diskspace is reported in MB
                disks = [FlavorDisk(size=UNITS.Quantity(int(flavor['osDiskSizeInMB']), UNITS.megabytes))]
                if max_data_disk_count > 1:
                    disks.append(FlavorDisk(is_expansion=True, max_additional_items=max_data_disk_count - 1))
                azure_flavors.append(
                    AzureFlavor(
                        name=flavor['name'],
                        id=flavor['name'],
                        cpu=FlavorCpu(
                            processors=int(flavor['numberOfCores'])
                        ),
                        # memory is reported in MB
                        memory=UNITS.Quantity(int(flavor['memoryInMB']), UNITS.megabytes),
                        disk=FlavorDisks(disks),
                        resource_disk_size=UNITS.Quantity(int(flavor['resourceDiskSizeInMB']), UNITS.megabytes),
                        network=FlavorNetworks([FlavorNetwork(type='eth')]),
                        virtualization=FlavorVirtualization()
                    )
                )
            except KeyError as exc:
                return Error(Failure.from_exc(
                    'malformed flavor description',
                    exc,
                    flavor_info=flavors
                ))

        return Ok(azure_flavors)

    def fetch_pool_image_info(self) -> Result[List[PoolImageInfo], Failure]:
        def _fetch_images(filters: Optional[ConfigImageFilter] = None) -> Result[List[PoolImageInfo], Failure]:
            name_pattern: Optional[Pattern[str]] = None

            # AzureSession needs a logger but fetch_pool_image_info doesn't pass one along
            # This will take the logger from the gluetool.log.LoggerMixin, is there a better way?
            logger = self.logger
            list_images_cmd = ['vm', 'image', 'list', '--all']

            if filters:
                if 'offer' in filters:
                    list_images_cmd.extend(['--offer', filters['offer']])
                if 'sku' in filters:
                    list_images_cmd.extend(['--sku', filters['sku']])
                if 'publisher' in filters:
                    list_images_cmd.extend(['--publisher', filters['publisher']])
                if 'name-regex' in filters:
                    try:
                        name_pattern = re.compile(filters['name-regex'])
                    except re.error as exc:
                        return Error(Failure.from_exc('failed to compile regex', exc))

            with AzureSession(logger, self) as session:
                r_images_list = session.run_az(
                    logger,
                    list_images_cmd,
                    commandname='az.vm-image-list'
                )

                if r_images_list.is_error:
                    return Error(Failure.from_failure(
                        'failed to fetch image information',
                        r_images_list.unwrap_error()
                    ))

            images: List[PoolImageInfo] = []
            for image in cast(List[APIImageType], r_images_list.unwrap()):
                try:
                    # Apply wild-card filter if specified, unfortunately no way to filter by urn via azure cli
                    if name_pattern and not name_pattern.match(image['urn']):
                        continue
                    images.append(AzurePoolImageInfo(
                        name=image['urn'],
                        id=image['urn'],
                        urn=image['urn'],
                        offer=image['offer'],
                        publisher=image['publisher'],
                        sku=image['sku'],
                        version=image['version'],
                        arch=image['architecture'],
                        boot=FlavorBoot(),
                        ssh=PoolImageSSHInfo()
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

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_images = self.image_info_mapper.map(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()
        pairs: List[Tuple[AzurePoolImageInfo, AzureFlavor]] = []

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

        r_base_tags = self.get_guest_tags(logger, session, guest_request)

        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        tags = {
            **r_base_tags.unwrap(),
        }

        # This tag links our VM and its resources, which comes handy when we want to remove everything
        # leaving no leaks.
        tags['uid'] = tags['ArtemisGuestLabel']

        r_output = None

        def _create(resource_group: str, custom_data_filename: str) -> Result[JSONType, Failure]:
            """
            The actual call to the azure cli guest create command is happening here.
            If custom_data_filename is an empty string then the guest vm is booted with no user-data.
            The vm will be created under a distinct resource_group so that a cleanup later will be smooth and easy.
            """

            # According to `az` documentation, `--tags` accepts `space-separated tags`, but that's not really true.
            # Space-separated, yes, but not passed as one value after `--tags` option:
            #
            # NO:  --tags "foo=bar baz=79"
            # NO:  '--tags foo=bar baz=79'
            # YES: --tags foo=bar baz=79
            #
            # As you can see, `baz=79` in the valid example is not a space-separated bit of a `--tags` argument,
            # but rather a stand-alone command-line item that is consumed by `--tags`.
            tags_options = []
            if tags:
                tags_options = [
                    '--tags'
                ] + [
                    f'{tag}={value}'
                    for tag, value in tags.items()
                ]

            # First let's create a resource group for this vm
            with AzureSession(logger, self) as session:
                az_options = [
                    'group', 'create', '--location', self.pool_config['default-location'],
                    '--name', resource_group
                ] + tags_options
                r_create_resource_group = session.run_az(logger, az_options, commandname='az.vm-create')

                if r_create_resource_group.is_error:
                    return Error(Failure.from_failure('failed to create resource group',
                                                      r_create_resource_group.unwrap_error()))

            # Resource group pre-created, time to create a vm
            az_options = [
                'vm',
                'create',
                '--resource-group', resource_group,
                '--image', image.id,
                '--name', tags['ArtemisGuestLabel'],
                '--custom-data', custom_data_filename,
                '--size', instance_type.name
            ] + tags_options

            with AzureSession(logger, self) as session:
                return session.run_az(
                    logger,
                    az_options,
                    commandname='az.vm-create'
                )

        r_resource_group_template = KNOB_RESOURCE_GROUP_NAME_TEMPLATE.get_value(entityname=self.poolname)
        if r_resource_group_template.is_error:
            return Error(Failure('Could not get resource_group_name template'))

        r_rendered = render_template(
            r_resource_group_template.unwrap(),
            GUESTNAME=guest_request.guestname,
            ENVIRONMENT=guest_request.environment,
            TAGS=tags
        )
        if r_resource_group_template.is_error:
            return Error(Failure('Could not render resource_group_name template'))

        resource_group = r_rendered.unwrap()

        if guest_request.post_install_script:
            # user has specified custom script to execute, contents stored as post_install_script
            with create_tempfile(file_contents=guest_request.post_install_script) as custom_data_filename:
                r_output = _create(resource_group, custom_data_filename)
        else:
            # using post_install_script setting from the pool config
            r_output = _create(resource_group, self.pool_config.get('post-install-script', ''))

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = cast(Dict[str, Any], r_output.unwrap())
        if not output['id']:
            return Error(Failure('Instance id not found'))

        status = output['powerState'].lower()

        logger.info(f'acquired instance status {output["id"]}:{status}')

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=AzurePoolData(
                instance_id=output['id'],
                instance_name=tags['ArtemisGuestLabel'],
                resource_group=resource_group
            ),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))


PoolDriver._drivers_registry['azure'] = AzureDriver
