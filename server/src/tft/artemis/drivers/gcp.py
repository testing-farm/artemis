# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import re
import threading
from functools import cached_property
from typing import Any, Dict, List, Optional, Tuple, cast

import gluetool.log
import google.api_core
import google.api_core.exceptions
import proto
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from google.cloud import compute_v1

from .. import Failure, log_dict_yaml
from ..db import GuestRequest, SnapshotRequest
from ..environment import UNITS, FlavorBoot, SizeType
from ..knobs import Knob
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, HookImageInfoMapper, PoolCapabilities, PoolData, PoolDriver, \
    PoolImageInfo, PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, ProvisioningState, \
    SerializedPoolResourcesIDs

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='configuration/artemis-image-map-gcp.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

DEFAULT_DISK_SIZE: SizeType = UNITS('20 GiB')


@dataclasses.dataclass
class GCPPoolData(PoolData):
    name: str
    id: int
    project: str
    zone: str


@dataclasses.dataclass
class GCPPoolResourcesIDs(PoolResourcesIDs):
    name: Optional[str] = None
    project: Optional[str] = None
    zone: Optional[str] = None


class GCPDriver(PoolDriver):
    drivername = 'gcp'

    pool_data_class = GCPPoolData

    def __init__(self,
                 logger: gluetool.log.ContextAdapter,
                 poolname: str,
                 pool_config: Dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
        return HookImageInfoMapper(self, 'GCP_ENVIRONMENT_TO_IMAGE')

    @property
    def _instances_client(self) -> compute_v1.InstancesClient:
        return cast(
            compute_v1.InstancesClient,
            compute_v1.InstancesClient.from_service_account_info(self._service_account_info)
        )

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supported_architectures = ['x86_64']
        capabilities.supports_snapshots = False
        capabilities.supports_console_url = False
        capabilities.supports_spot_instances = False
        capabilities.supports_native_post_install_script = False
        capabilities.supported_guest_logs = []
        capabilities.supports_hostnames = False
        capabilities.supports_kickstart = False
        return Ok(capabilities)

    @cached_property
    def _service_account_info(self) -> Any:
        return self.pool_config['service-account-info']

    def map_image_name_to_image_info(self,
                                     logger: gluetool.log.ContextAdapter,
                                     image_name: str) -> Result[PoolImageInfo, Failure]:

        image_project = self.pool_config['image-project']

        try:
            images_client = compute_v1.ImagesClient.from_service_account_info(self._service_account_info)
            image_description = images_client.get_from_family(project=image_project, family=image_name)
        except google.api_core.exceptions.NotFound as exc:
            return Error(Failure.from_exc('The given imagename was not found.', exc, imagename=image_name))

        ssh_info = PoolImageSSHInfo(username='artemis')
        image_info = PoolImageInfo(name=image_description.name,
                                   id=image_description.self_link,
                                   arch=image_description.architecture,
                                   boot=FlavorBoot(),
                                   ssh=ssh_info)

        return Ok(image_info)

    def can_acquire(self,
                    logger: gluetool.log.ContextAdapter,
                    session: sqlalchemy.orm.session.Session,
                    guest_request: GuestRequest) -> Result[Tuple[bool, Optional[str]], Failure]:
        """
        Check whether this driver can provision a guest that would satisfy the given environment.
        """

        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        answer = r_answer.unwrap()
        if answer[0] is False:
            return r_answer

        r_images = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_images.is_error:
            return Error(r_images.unwrap_error())

        images = r_images.unwrap()
        if not images:
            return Ok((False, 'compose not supported'))

        if guest_request.environment.has_hw_constraints:
            return Ok((False, 'HW constraints are not supported by the GCP driver'))

        return Ok((True, None))

    def _query_instance_id(self, instance_name: str, project: str, zone: str) -> Result[int, Failure]:
        """ Perform API call to GCP, asking about the given instance """
        request = compute_v1.GetInstanceRequest()
        request.instance = instance_name
        request.project = project
        request.zone = zone

        try:
            instance_info = self._instances_client.get(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc(f'Failed to locate instance {request.instance}',
                                       exc,
                                       recoverable=False,
                                       fail_guest_request=False)
            return Error(failure)

        return Ok(instance_info.id)

    def update_guest(self,
                     logger: gluetool.log.ContextAdapter,
                     session: sqlalchemy.orm.session.Session,
                     guest_request: GuestRequest,
                     cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        pool_data = GCPPoolData.unserialize(guest_request)

        request = compute_v1.GetInstanceRequest()
        request.instance = pool_data.name
        request.project = pool_data.project
        request.zone = pool_data.zone

        try:
            instance_info = self._instances_client.get(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc(f'Failed to locate instance {request.instance}',
                                       exc,
                                       recoverable=False,
                                       fail_guest_request=False)
            return Error(failure)

        instance_status = instance_info.status.lower()

        if instance_status == 'failed':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=pool_data,
                pool_failures=[Failure('instance ended up in the "failed" state')]
            ))

        ip_address = self._get_ip_from_instance(instance_info)
        if ip_address:
            return Ok(ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=GCPPoolData.unserialize(guest_request),
                address=ip_address
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=GCPPoolData.unserialize(guest_request),
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        if GCPPoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = GCPPoolData.unserialize(guest_request)

        resource = GCPPoolResourcesIDs(name=pool_data.name, project=pool_data.project, zone=pool_data.zone)
        r_cleanup = self.dispatch_resource_cleanup(logger, resource, guest_request=guest_request)
        if r_cleanup.is_error:
            return Error(r_cleanup.unwrap_error())
        return Ok(True)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = GCPPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        request = compute_v1.DeleteInstanceRequest(instance=resource_ids.name,
                                                   project=resource_ids.project,
                                                   zone=resource_ids.zone)
        try:
            self._instances_client.delete(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc('Instance to delete was not found',
                                       exc,
                                       recoverable=False,
                                       fail_guest_request=False)
            return Error(failure)
        return Ok(None)

    def _create_boot_disk_for_image_link(self,
                                         image_link: str,
                                         size: Optional[SizeType] = None,
                                         zone: Optional[str] = None,
                                         disk_type: str = 'pd-standard') -> compute_v1.AttachedDisk:

        disk_type = f'zones/{zone}/diskTypes/{disk_type}'

        size = size or DEFAULT_DISK_SIZE

        if not zone:
            zone = self.pool_config['zone']

        boot_disk = compute_v1.AttachedDisk()
        initialize_params = compute_v1.AttachedDiskInitializeParams()
        initialize_params.source_image = image_link
        initialize_params.disk_size_gb = int(size.to('GiB').magnitude)
        initialize_params.disk_type = disk_type
        boot_disk.initialize_params = initialize_params
        boot_disk.auto_delete = True
        boot_disk.boot = True

        return boot_disk

    def _ensure_machine_type_is_canonical(self, machine_type: str, zone: str) -> str:
        if re.match(r"^zones/[a-z\d\-]+/machineTypes/[a-z\d\-]+$", machine_type):
            return machine_type
        return f'zones/{zone}/machineTypes/{machine_type}'

    def _create_instance(self,
                         client: compute_v1.InstancesClient,
                         image: PoolImageInfo,
                         ssh_pubkey: str,
                         project_id: str,
                         zone: str,
                         instance_name: str,
                         disks: List[compute_v1.AttachedDisk],
                         machine_type: Optional[str] = None,
                         network_link: Optional[str] = None,
                         delete_protection: bool = False) -> Result[compute_v1.Instance, Failure]:

        network_link = network_link or self.pool_config['network-resourceurl']
        machine_type = machine_type or self.pool_config['default-flavor']

        network_interface = compute_v1.NetworkInterface()
        network_interface.network = network_link

        # Configure external access - external IP will be auto assigned
        access = compute_v1.AccessConfig()
        access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name  # type: ignore[attr-defined]
        access.name = "External NAT"
        access.network_tier = access.NetworkTier.PREMIUM.name  # type: ignore[attr-defined]
        network_interface.access_configs = [access]

        # Collect information into the Instance object.
        instance = compute_v1.Instance()
        instance.network_interfaces = [network_interface]
        instance.name = instance_name
        instance.disks = disks

        instance.machine_type = self._ensure_machine_type_is_canonical(zone=zone, machine_type=machine_type)

        # Add a ssh-key to the file
        ssh_key = compute_v1.Items()
        ssh_key.key = 'ssh-keys'
        ssh_key.value = f'{image.ssh.username}:{ssh_pubkey}'
        instance.metadata.items.append(ssh_key)

        instance.scheduling = compute_v1.Scheduling()

        if delete_protection:
            instance.deletion_protection = True

        # Prepare the request to insert an instance.
        request = compute_v1.InsertInstanceRequest()
        request.zone = zone
        request.project = project_id
        request.instance_resource = instance

        try:
            client.insert(request=request)
        except google.api_core.exceptions.BadRequest as exc:
            return Error(Failure.from_exc('Failed to create a GCP instance', exc))
        except google.api_core.exceptions.Conflict as exc:
            return Error(Failure.from_exc('Failed to create a GCP instance', exc))

        try:
            created_instance = client.get(project=project_id, zone=zone, instance=instance_name)
        except google.api_core.exceptions.NotFound as exc:
            return Error(
                Failure.from_exc('Failed to query information about the freshly created instance', exc)
            )
        return Ok(created_instance)

    def acquire_guest(self,
                      logger: gluetool.log.ContextAdapter,
                      session: sqlalchemy.orm.session.Session,
                      guest_request: GuestRequest,
                      cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        delay_cfg_option_read_result = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)
        if delay_cfg_option_read_result.is_error:
            return Error(delay_cfg_option_read_result.unwrap_error())

        map_request_to_image_result = self.image_info_mapper.map(logger, guest_request)
        if map_request_to_image_result.is_error:
            return Error(map_request_to_image_result.unwrap_error())
        image = map_request_to_image_result.unwrap()[0]

        self.log_acquisition_attempt(logger, session, guest_request, image=image)

        r_base_tags = self.get_guest_tags(logger, session, guest_request)
        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())

        # As guest IDs (names) can start with a number, add 'artemis-' prefix to make sure the instance nam
        # will start with a letter
        instance_name = f'artemis-{guest_request.guestname}'

        project_id = self.pool_config['project']
        zone = self.pool_config['zone']

        boot_disk = self._create_boot_disk_for_image_link(image.id, zone=zone)  # Image.id contains self_link

        from ..tasks import _get_ssh_key  # Late import as top-level import leads to circular imports
        r_ssh_key = _get_ssh_key(guest_request.ownername, guest_request.ssh_keyname)
        if r_ssh_key.is_error:
            return Error(Failure.from_failure(
                'failed to get SSH key',
                r_ssh_key.unwrap_error(),
                keyname=guest_request.ssh_keyname
            ))

        ssh_key = r_ssh_key.unwrap()
        if not ssh_key:
            return Error(Failure('failed to get SSH key', keyname=guest_request.ssh_keyname))

        r_instance = self._create_instance(self._instances_client, image, ssh_key.public,
                                           project_id, zone, instance_name, disks=[boot_disk])
        if r_instance.is_error:
            failure = r_instance.unwrap_error()
            if not failure.exc_info:
                return Error(failure)

            exc_instance = failure.exc_info[1]
            if isinstance(exc_instance, google.api_core.exceptions.AlreadyExists):
                # The instance already exists, do not try creating it again
                r_instance_id = self._query_instance_id(instance_name, project_id, zone)
                if r_instance_id.is_error:
                    return Error(r_instance_id.unwrap_error())

                return Ok(ProvisioningProgress(
                    state=ProvisioningState.PENDING,  # Check the VM state again - schedule update_guest()
                    pool_data=GCPPoolData(
                        id=r_instance_id.unwrap(),
                        project=project_id,
                        name=instance_name,
                        zone=zone
                    ),
                    delay_update=delay_cfg_option_read_result.ok,
                    ssh_info=image.ssh,
                    address=None
                ))

            return Error(r_instance.unwrap_error())

        instance = r_instance.unwrap()

        log_dict_yaml(logger.info, 'created instance', proto.Message.to_dict(instance))

        # It is unlikely that the machine would be up and running
        provisioninig_state = ProvisioningState.PENDING

        return Ok(ProvisioningProgress(
            state=provisioninig_state,
            pool_data=GCPPoolData(
                id=instance.id,
                project=project_id,
                name=instance_name,
                zone=zone
            ),
            delay_update=delay_cfg_option_read_result.ok,
            ssh_info=image.ssh,
            address=None
        ))

    def _get_ip_from_instance(self, instance: compute_v1.Instance) -> Optional[str]:
        access_configs = instance.network_interfaces[0].access_configs
        if access_configs:
            return access_configs[0].nat_i_p
        return None

    def create_snapshot(self,
                        guest_request: GuestRequest,
                        snapshot_request: SnapshotRequest) -> Result[ProvisioningProgress, Failure]:
        raise NotImplementedError()

    def update_snapshot(self,
                        guest_request: GuestRequest,
                        snapshot_request: SnapshotRequest,
                        start_again: bool = True) -> Result[ProvisioningProgress, Failure]:
        raise NotImplementedError()

    def remove_snapshot(self, snapshot_request: SnapshotRequest) -> Result[bool, Failure]:
        raise NotImplementedError()

    def restore_snapshot(self, guest_request: GuestRequest, snapshot_request: SnapshotRequest) -> Result[bool, Failure]:
        raise NotImplementedError()


PoolDriver._drivers_registry['gcp'] = GCPDriver
