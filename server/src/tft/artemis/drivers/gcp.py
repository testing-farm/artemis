# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import threading
from typing import Any, Dict, List, Optional, Union, Tuple
import json
import re

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from google.cloud import compute_v1
import google.api_core

from .. import Failure, JSONType, log_dict_yaml
from ..db import GuestRequest, SnapshotRequest
from ..environment import FlavorBoot
from ..knobs import Knob
from ..metrics import ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, HookImageInfoMapper, PoolCapabilities, PoolData, PoolDriver, \
    PoolImageInfo, PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, ProvisioningState, \
    SerializedPoolResourcesIDs, create_tempfile, run_cli_tool, vm_info_to_ip

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


@dataclasses.dataclass
class GCPPoolData(PoolData):
    name: str
    id: str
    project: str
    zone: str


@dataclasses.dataclass
class GCPPoolResourcesIDs(PoolResourcesIDs):
    name: str = ''
    project: str = ''
    zone: str = ''


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

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        return Ok(capabilities)

    def _get_service_account_info(self):
        sa_info = self.pool_config['service_account_info']
        return sa_info

    def map_image_name_to_image_info(self,
                                     logger: gluetool.log.ContextAdapter,
                                     image_name: str) -> Result[PoolImageInfo, Failure]:
        sa_info = self._get_service_account_info()
        client = compute_v1.ImagesClient.from_service_account_info(sa_info)

        request = compute_v1.GetImageRequest()
        request.project = 'rhel-cloud'

        try:
            image_description = client.get_from_family(project='rhel-cloud', family=image_name)
        except google.api_core.exceptions.NotFound as image_not_found:
            return Error(Failure.from_exc('The given imagename was not found:', image_not_found))

        image_info = PoolImageInfo(name=image_description.name,
                                   id=image_description.self_link,
                                   arch=image_description.architecture,
                                   boot=FlavorBoot(),
                                   ssh=PoolImageSSHInfo())

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

        can_acquire, dummy = r_answer.unwrap()
        if can_acquire is False:
            return Ok((can_acquire, dummy))

        can_acquire = guest_request.environment.has_hw_constraints is not True
        return Ok((can_acquire, None))

    def update_guest(self,
                     logger: gluetool.log.ContextAdapter,
                     session: sqlalchemy.orm.session.Session,
                     guest_request: GuestRequest,
                     cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        pool_data = GCPPoolData.unserialize(guest_request)

        client = compute_v1.InstancesClient.from_service_account_info(self._get_service_account_info())

        request = compute_v1.GetInstanceRequest()
        request.instance = pool_data.name
        request.project = pool_data.project
        request.zone = pool_data.zone

        try:
            instance_info = client.get(request=request)
        except google.api_core.exceptions.NotFound as instance_not_found:
            return Error(Failure.from_exc(f'Failed to locate instance {request.instance}', instance_not_found))

        instance_status = instance_info.status.lower()

        if instance_status == 'failed':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=pool_data,
                pool_failures=[Failure('instance ended up in "failed" state')]
            ))

        ip_address = self._get_ip_from_instance(instance_info)

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=GCPPoolData.unserialize(guest_request),
            address=ip_address
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
        raw_resource_ids: SerializedPoolResourcesIDs) -> Result[None, Failure]:
        resource_ids = GCPPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        request = compute_v1.DeleteInstanceRequest(instance=resource_ids.name,
                                                   project=resource_ids.project,
                                                   zone=resource_ids.zone)
        sa_info = self._get_service_account_info()
        instance_client = compute_v1.InstancesClient.from_service_account_info(sa_info)

        try:
            instance_client.delete(request=request)
        except google.api_core.exceptions.NotFound as instance_not_found:
            return Error(Failure.from_exc('Instance to delete was not found', instance_not_found))

    def _create_boot_disk_for_image_link(self,
                                         image_link: str,
                                         size_gb: int = 30,
                                         zone: str = 'us-west3-b',
                                         disk_type: str = 'pd-standard') -> compute_v1.AttachedDisk:

        disk_type = 'zones/{zone}/diskTypes/{type}'.format(zone=zone, type=disk_type)

        boot_disk = compute_v1.AttachedDisk()
        initialize_params = compute_v1.AttachedDiskInitializeParams()
        initialize_params.source_image = image_link
        initialize_params.disk_size_gb = size_gb
        initialize_params.disk_type = disk_type
        boot_disk.initialize_params = initialize_params
        boot_disk.auto_delete = True
        boot_disk.boot = True

        return boot_disk


    def _ensure_machine_type_is_canonical(self, machine_type: str, zone: str) -> str:
        if re.match(r"^zones/[a-z\d\-]+/machineTypes/[a-z\d\-]+$", machine_type):
            return machine_type
        return 'zones/{zone}/machineTypes/{machine_type}'.format(zone=zone, machine_type=machine_type)


    def _create_instance(self,
                         client: compute_v1.InstancesClient,
                         image: PoolImageInfo,
                         ssh_pub_key: str,
                         project_id: str,
                         zone: str,
                         instance_name: str,
                         disks: List[compute_v1.AttachedDisk],
                         machine_type: str = "n1-standard-1",
                         network_link: str = "global/networks/default",
                         delete_protection: bool = False) -> Result[compute_v1.Instance, Failure]:

        network_interface = compute_v1.NetworkInterface()
        network_interface.network = network_link

        # Configure external access - external IP will be auto assigned
        access = compute_v1.AccessConfig()
        access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name
        access.name = "External NAT"
        access.network_tier = access.NetworkTier.PREMIUM.name
        network_interface.access_configs = [access]

        # Collect information into the Instance object.
        instance = compute_v1.Instance()
        instance.network_interfaces = [network_interface]
        instance.name = instance_name
        instance.disks = disks

        instance.machine_type = self._ensure_machine_type_is_canonical(zone=zone, machine_type=machine_type)

        # Add a ssh-key to the file
        username = image.ssh.username
        ssh_key = compute_v1.Items()
        ssh_key.key = 'ssh-keys'
        ssh_key.value = f'{username}:{ssh_pub_key}'
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
        except google.api_core.exceptions.BadRequest as bad_request:
            return Error(Failure.from_exc('Failed to create a GCP instance', bad_request))
        except google.api_core.exceptions.Conflict as instance_with_name_exits:
            return Error(Failure.from_exc('Failed to create a GCP instance', instance_with_name_exits))

        try:
            created_instance = client.get(project=project_id, zone=zone, instance=instance_name)
        except google.api_core.exceptions.NotFound as instance_not_found:
            return Error(
                Failure.from_exc('Failed to query information about the fresly created instance', instance_not_found)
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
        tags = r_base_tags.unwrap()

        # As guest IDs (names) can start with a number, add 'artemis-' prefix to make sure the instance name will start with a letter
        instance_name = f'artemis-{guest_request.guestname}'

        service_account_info = self.pool_config['service_account_info']
        project_id = self.pool_config['project']
        zone = self.pool_config['zone']

        instances_client = compute_v1.InstancesClient.from_service_account_info(service_account_info)
        boot_disk = self._create_boot_disk_for_image_link(image.id, zone=zone)  # Image.id contains self_link

        instance_r = self._create_instance(instances_client, image, self.pool_config['ssh_key'],
                                           project_id, zone, instance_name, disks=[boot_disk])
        if instance_r.is_error:
            return Error(instance_r.unwrap_error())
        instance = instance_r.unwrap()

        # It is unlikely that the machine would be up and running
        provisioninig_state = ProvisioningState.PENDING

        return Ok(ProvisioningProgress(
            state=provisioninig_state,
            pool_data=GCPPoolData(
                id=instance.id,
                project=project_id,
                name=instance.name,
                zone=instance.zone
            ),
            delay_update=delay_cfg_option_read_result.ok,
            ssh_info=image.ssh,
            address=self._get_ip_from_instance(instance)
        ))

    def _get_ip_from_instance(self, instance: compute_v1.Instance) -> Optional[str]:
        access_configs = instance.network_interfaces[0].access_configs
        if len(access_configs) > 0:
            return access_configs[0].nat_i_p
        return None

    def create_snapshot(self,
                        guest_request: GuestRequest,
                        snapshot_request: SnapshotRequest) -> Result[ProvisioningProgress, Failure]:
        raise NotImplementedError()

    def update_snapshot(self,
                        guest_request: GuestRequest,
                        snapshot_request: SnapshotRequest,
                        canceled: Optional[threading.Event] = None,
                        start_again: bool = True) -> Result[ProvisioningProgress, Failure]:
        raise NotImplementedError()

    def remove_snapshot(self, snapshot_request: SnapshotRequest) -> Result[bool, Failure]:
        raise NotImplementedError()

    def restore_snapshot(self, guest_request: GuestRequest, snapshot_request: SnapshotRequest) -> Result[bool, Failure]:
        raise NotImplementedError()


PoolDriver._drivers_registry['gcp'] = GCPDriver
