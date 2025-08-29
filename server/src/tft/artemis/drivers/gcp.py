# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import re
import threading
from functools import cached_property
from typing import Any, Optional, cast

import gluetool.log
import google.api_core
import google.api_core.exceptions
import proto
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from google.cloud import compute_v1
from returns.result import Result as _Result, Success as _Ok
from tmt.hardware import UNITS

from .. import Failure, log_dict_yaml
from ..db import GuestRequest
from ..environment import UNITS, Flavor, FlavorBoot, SizeType
from ..knobs import Knob
from ..metrics import PoolResourcesMetrics, PoolResourcesUsage
from . import (
    CanAcquire,
    ConfigImageFilter,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolImageInfo,
    PoolImageSSHInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='configuration/artemis-image-map-gcp.yaml',
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}',
)

DEFAULT_DISK_SIZE: SizeType = UNITS('20 GiB')

GCP_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'


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

    datetime_format = GCP_DATETIME_FORMAT

    _image_map_hook_name = 'GCP_ENVIRONMENT_TO_IMAGE'

    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str, pool_config: dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)

    @property
    def _instances_client(self) -> compute_v1.InstancesClient:
        return cast(
            compute_v1.InstancesClient, compute_v1.InstancesClient.from_service_account_info(self._service_account_info)
        )

    @classmethod
    def timestamp_to_datetime(cls, timestamp: str) -> Result[datetime.datetime, Failure]:
        try:
            return Ok(datetime.datetime.strptime(timestamp, GCP_DATETIME_FORMAT))
        except Exception as exc:
            return Error(
                Failure.from_exc(
                    'failed to parse timestamp', exc, timestamp=timestamp, strptime_format=GCP_DATETIME_FORMAT
                )
            )

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> _Result[PoolCapabilities, Failure]:
        capabilities.supported_architectures = ['x86_64']
        capabilities.supports_console_url = False
        capabilities.supports_spot_instances = False
        capabilities.supports_native_post_install_script = False
        capabilities.supported_guest_logs = []
        capabilities.supports_hostnames = False
        return _Ok(capabilities)

    @cached_property
    def _service_account_info(self) -> dict[Any, Any]:
        # The type is validated using pool's jsonschema (object)
        return cast(dict[Any, Any], self.pool_config['service-account-info'])

    def image_name_to_image_info(
        self, logger: gluetool.log.ContextAdapter, image_name: str
    ) -> Result[PoolImageInfo, Failure]:
        image_project = self.pool_config['image-project']

        try:
            images_client = compute_v1.ImagesClient.from_service_account_info(self._service_account_info)
            image_description = images_client.get_from_family(project=image_project, family=image_name)
        except google.api_core.exceptions.NotFound as exc:
            return Error(Failure.from_exc('The given imagename was not found.', exc, imagename=image_name))

        ssh_info = PoolImageSSHInfo(username='artemis')
        ctime = self.timestamp_to_datetime(image_description.creation_timestamp)
        if ctime.is_error:
            return Error(
                Failure.from_failure(
                    'Could not parse image create timestamp',
                    ctime.unwrap_error(),
                    image=image_description.self_link,
                    strptime_format=GCP_DATETIME_FORMAT,
                )
            )

        image_info = PoolImageInfo(
            name=image_description.name,
            id=image_description.self_link,
            arch=image_description.architecture,
            boot=FlavorBoot(),
            ssh=ssh_info,
            supports_kickstart=False,
            created_at=ctime.unwrap(),
        )

        return Ok(image_info)

    def can_acquire(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        answer = r_answer.unwrap()
        if answer.can_acquire is False:
            return r_answer

        r_images: Result[list[PoolImageInfo], Failure] = self._guest_request_to_image_or_none(
            logger, session, guest_request
        )
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

        if guest_request.environment.has_hw_constraints:
            return Ok(CanAcquire.cannot('HW constraints are not supported by the GCP driver'))

        return Ok(CanAcquire())

    def _query_instance_id(self, instance_name: str, project: str, zone: str) -> Result[int, Failure]:
        """Perform API call to GCP, asking about the given instance"""
        request = compute_v1.GetInstanceRequest()
        request.instance = instance_name
        request.project = project
        request.zone = zone

        try:
            instance_info = self._instances_client.get(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc(
                f'Failed to locate instance {request.instance}', exc, recoverable=False, fail_guest_request=False
            )
            return Error(failure)

        return Ok(instance_info.id)

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None,
    ) -> Result[ProvisioningProgress, Failure]:
        pool_data = guest_request.pool_data.mine(self, GCPPoolData)

        request = compute_v1.GetInstanceRequest()
        request.instance = pool_data.name
        request.project = pool_data.project
        request.zone = pool_data.zone

        try:
            instance_info = self._instances_client.get(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc(
                f'Failed to locate instance {request.instance}', exc, recoverable=False, fail_guest_request=False
            )
            return Error(failure)

        instance_status = instance_info.status.lower()

        if instance_status == 'failed':
            return Ok(
                ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=pool_data,
                    pool_failures=[Failure('instance ended up in the "failed" state')],
                )
            )

        ip_address = self._get_ip_from_instance(instance_info)
        if ip_address:
            return Ok(
                ProvisioningProgress(
                    state=ProvisioningState.COMPLETE,
                    pool_data=guest_request.pool_data.mine(self, GCPPoolData),
                    address=ip_address,
                )
            )

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=guest_request.pool_data.mine(self, GCPPoolData),
            )
        )

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, GCPPoolData)

        if not pool_data:
            return Ok(None)

        return self.dispatch_resource_cleanup(
            logger,
            session,
            GCPPoolResourcesIDs(name=pool_data.name, project=pool_data.project, zone=pool_data.zone),
            guest_request=guest_request,
        )

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = GCPPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        request = compute_v1.DeleteInstanceRequest(
            instance=resource_ids.name, project=resource_ids.project, zone=resource_ids.zone
        )
        try:
            self._instances_client.delete(request=request)
        except google.api_core.exceptions.NotFound as exc:
            failure = Failure.from_exc(
                'Instance to delete was not found', exc, recoverable=False, fail_guest_request=False
            )
            return Error(failure)
        return Ok(ReleasePoolResourcesState.RELEASED)

    def _create_boot_disk_for_image_link(
        self,
        image_link: str,
        size: Optional[SizeType] = None,
        zone: Optional[str] = None,
        disk_type: str = 'pd-standard',
    ) -> compute_v1.AttachedDisk:
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
        if re.match(r'^zones/[a-z\d\-]+/machineTypes/[a-z\d\-]+$', machine_type):
            return machine_type
        return f'zones/{zone}/machineTypes/{machine_type}'

    def _create_instance(
        self,
        client: compute_v1.InstancesClient,
        image: PoolImageInfo,
        ssh_pubkey: str,
        project_id: str,
        zone: str,
        instance_name: str,
        disks: list[compute_v1.AttachedDisk],
        machine_type: Optional[str] = None,
        network_link: Optional[str] = None,
        *,
        delete_protection: bool = False,
    ) -> Result[compute_v1.Instance, Failure]:
        network_link = network_link or self.pool_config['network-resource-url']
        machine_type = machine_type or self.pool_config['default-flavor']

        network_interface = compute_v1.NetworkInterface()
        network_interface.network = network_link

        # Configure external access - external IP will be auto assigned
        access = compute_v1.AccessConfig()
        access.type_ = compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name  # type: ignore[attr-defined]
        access.name = 'External NAT'
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
            return Error(Failure.from_exc('Failed to query information about the freshly created instance', exc))
        return Ok(created_instance)

    def list_images(
        self, logger: gluetool.log.ContextAdapter, filters: Optional[ConfigImageFilter] = None
    ) -> Result[list[PoolImageInfo], Failure]:
        """
        This method will issue a cloud guest list command and return a list of pool image info objects for this
        particular cloud.
        Filters argument contains optional filtering options to be applied on the cloud side.
        """
        image_project = self.pool_config['image-project']

        images_client = compute_v1.ImagesClient.from_service_account_info(self._service_account_info)
        request_list_images = compute_v1.ListImagesRequest(project=image_project)

        def _from_image(image: compute_v1.types.compute.Image) -> Result[PoolImageInfo, Failure]:
            try:
                created_at = self.timestamp_to_datetime(image.creation_timestamp)
                if created_at.is_error:
                    return Error(
                        Failure.from_failure(
                            'Could not parse image create timestamp', created_at.unwrap_error(), image=image.self_link
                        )
                    )
                ssh_info = PoolImageSSHInfo(username='artemis')

                return Ok(
                    PoolImageInfo(
                        name=image.name,
                        id=image.self_link,
                        arch=image.architecture,
                        boot=FlavorBoot(),
                        ssh=ssh_info,
                        supports_kickstart=False,
                        created_at=created_at.unwrap(),
                    )
                )
            except KeyError as exc:
                return Error(Failure.from_exc('malformed image description', exc, image_info=image))

        res = []
        for image in images_client.list(request_list_images):
            r_image = _from_image(image)
            if r_image.is_error:
                return Error(
                    Failure.from_failure(
                        'Failed converting image data to a PoolImageInfo object', r_image.unwrap_error()
                    )
                )
            res.append(r_image.unwrap())

        return Ok(res)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None,
    ) -> Result[ProvisioningProgress, Failure]:
        map_request_to_image_result: Result[list[PoolImageInfo], Failure] = self._guest_request_to_image(
            logger, session, guest_request
        )
        if map_request_to_image_result.is_error:
            return Error(map_request_to_image_result.unwrap_error())

        images = map_request_to_image_result.unwrap()

        if guest_request.environment.has_ks_specification:
            images = [image for image in images if image.supports_kickstart is True]

        image = images[0]

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
            return Error(
                Failure.from_failure(
                    'failed to get SSH key', r_ssh_key.unwrap_error(), keyname=guest_request.ssh_keyname
                )
            )

        ssh_key = r_ssh_key.unwrap()
        if not ssh_key:
            return Error(Failure('failed to get SSH key', keyname=guest_request.ssh_keyname))

        r_instance = self._create_instance(
            self._instances_client, image, ssh_key.public, project_id, zone, instance_name, disks=[boot_disk]
        )
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

                return Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.PENDING,  # Check the VM state again - schedule update_guest()
                        pool_data=GCPPoolData(
                            id=r_instance_id.unwrap(), project=project_id, name=instance_name, zone=zone
                        ),
                        ssh_info=image.ssh,
                        address=None,
                    )
                )

            return Error(r_instance.unwrap_error())

        instance = r_instance.unwrap()

        log_dict_yaml(logger.info, 'created instance', proto.Message.to_dict(instance))

        # It is unlikely that the machine would be up and running
        provisioninig_state = ProvisioningState.PENDING

        return Ok(
            ProvisioningProgress(
                state=provisioninig_state,
                pool_data=GCPPoolData(id=instance.id, project=project_id, name=instance_name, zone=zone),
                ssh_info=image.ssh,
                address=None,
            )
        )

    def _get_ip_from_instance(self, instance: compute_v1.Instance) -> Optional[str]:
        access_configs = instance.network_interfaces[0].access_configs
        if access_configs:
            return access_configs[0].nat_i_p
        return None

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        """
        Trigger hard reboot of a GCP instance.
        """
        pool_data = guest_request.pool_data.mine_or_none(self, GCPPoolData)

        if not pool_data:
            return Ok(None)

        request = compute_v1.ResetInstanceRequest(
            instance=pool_data.name, project=pool_data.project, zone=pool_data.zone
        )

        try:
            self._instances_client.reset(request=request)
        except google.api_core.exceptions.NotFound as exc:
            return Error(Failure.from_exc('Instance to reboot was not found', exc))
        except google.api_core.exceptions.ClientError as exc:
            return Error(Failure.from_exc('Failed to reboot instance', exc))

        return Ok(None)

    def fetch_pool_resources_metrics(
        self, logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        # Resource usage - instances and flavors
        def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[list[compute_v1.Instance], Failure]:
            return Ok(
                list(self._instances_client.list(project=self.pool_config['project'], zone=self.pool_config['zone']))
            )

        def _update_instance_usage(
            logger: gluetool.log.ContextAdapter,
            usage: PoolResourcesUsage,
            raw_instance: compute_v1.Instance,
            flavor: Optional[Flavor],
        ) -> Result[None, Failure]:
            assert usage.instances is not None  # narrow type

            usage.instances += 1

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

        return Ok(resources)


PoolDriver._drivers_registry['gcp'] = GCPDriver
