# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import functools
import re
import string
import threading
from collections.abc import Iterator
from typing import Any, Optional, cast

import gluetool.log
import google.api_core
import google.api_core.exceptions
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from google.cloud import compute_v1
from returns.pipeline import is_successful
from returns.result import Failure as _Error, Result as _Result, Success as _Ok
from tmt.hardware import UNITS
from typing_extensions import TypeAlias, override

from .. import Failure, rewrap_to_gluetool
from ..db import GuestRequest
from ..environment import Flavor, FlavorBoot, FlavorCpu, FlavorNetworks, FlavorVirtualization, SizeType
from ..knobs import Knob
from ..metrics import PoolResourcesMetrics, PoolResourcesUsage
from . import (
    CanAcquire,
    CommonErrorCauses,
    ConfigImageFilter,
    ConsoleUrlData,
    FlavorBasedPoolDriver,
    Instance,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolImageCompatible,
    PoolImageInfo,
    PoolImageSSHInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    ResourceCreationOutcome,
    ResourceCreationRequest,
    ResourceManager,
    SerializedPoolResourcesIDs,
    Tags,
    create_error_cause_extractor,
    create_sanitize_tags,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-gcp.yaml',
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


GCPErrorCauses = CommonErrorCauses

error_cause_extractor = create_error_cause_extractor(GCPErrorCauses)

# GCP label constraints
# https://cloud.google.com/compute/docs/labeling-resources#requirements
LABEL_KEY_MAX_LENGTH = 63
LABEL_VALUE_MAX_LENGTH = 63
LABEL_ALLOWED_CHARACTERS = string.ascii_lowercase + string.digits + '_-'

_sanitize_tags = create_sanitize_tags(
    allowed_charset=LABEL_ALLOWED_CHARACTERS,
    max_key_length=LABEL_KEY_MAX_LENGTH,
    max_value_length=LABEL_VALUE_MAX_LENGTH,
)


@dataclasses.dataclass(repr=False)
class GCPFlavor(Flavor): ...


def _serialize_tags(tags: Tags) -> dict[str, str]:
    """
    Serialize tags to make them acceptable as GCP labels.

    GCP labels are key-value pairs. Keys must start with a lowercase letter,
    contain only lowercase letters, digits, underscores, and dashes, and be
    at most 63 characters. Values follow the same character rules.

    See https://cloud.google.com/compute/docs/labeling-resources#requirements
    """

    # Lowercase before sanitizing so uppercase letters don't get replaced with underscores
    lowered_tags: Tags = {k.lower(): v.lower() if v else v for k, v in tags.items()}

    labels: dict[str, str] = {}

    for name, value in _sanitize_tags(lowered_tags):
        value = value or ''

        # GCP keys must start with a lowercase letter
        if name and not name[0].isalpha():
            name = f'l-{name}'
            name = name[:LABEL_KEY_MAX_LENGTH]

        if name:
            labels[name] = value

    return labels


BackendFlavor: TypeAlias = dict[str, Any]


@dataclasses.dataclass
class GCPPoolData(PoolData):
    instance_name: Optional[str] = None
    instance_id: Optional[int] = None


@dataclasses.dataclass
class GCPPoolResourcesIDs(PoolResourcesIDs):
    instance_name: Optional[str] = None


@dataclasses.dataclass
class GCPInstance(Instance):
    status: str
    created_at: datetime.datetime

    def __post_init__(self) -> None:
        self.status = self.status.lower()

    @override
    @functools.cached_property
    def is_ready(self) -> bool:
        return self.status == 'running'

    @override
    @functools.cached_property
    def is_error(self) -> bool:
        return self.status == 'failed'

    @override
    @functools.cached_property
    def is_pending(self) -> bool:
        return not self.is_ready and not self.is_error

    @override
    def to_pool_resource_ids(self) -> GCPPoolResourcesIDs:
        return GCPPoolResourcesIDs(instance_name=self.name)

    def serialize(self) -> dict[str, Any]:
        serialized = super().serialize()

        if self.created_at:
            serialized['created_at'] = self.created_at.strftime(GCP_DATETIME_FORMAT)

        return serialized

    @classmethod
    def unserialize(cls, serialized: dict[str, Any]) -> 'GCPInstance':
        instance = super().unserialize(serialized)

        if serialized['created_at']:
            instance.created_at = datetime.datetime.strptime(serialized['created_at'], GCP_DATETIME_FORMAT)

        return instance


@dataclasses.dataclass
class InstanceCreationRequest(ResourceCreationRequest):
    image: PoolImageInfo
    flavor: GCPFlavor
    tags: Optional[Tags] = None


@dataclasses.dataclass
class InstanceCreationOutcome(ResourceCreationOutcome[GCPInstance]):
    image: PoolImageInfo
    flavor: GCPFlavor


class GCPDriver(FlavorBasedPoolDriver[GCPErrorCauses, PoolImageInfo, GCPFlavor, BackendFlavor, Instance]):
    drivername = 'gcp'

    pool_data_class = GCPPoolData

    flavor_info_class = GCPFlavor

    error_cause_extractor = staticmethod(error_cause_extractor)

    datetime_format = GCP_DATETIME_FORMAT

    _image_map_hook_name = 'GCP_ENVIRONMENT_TO_IMAGE'

    _flavor_filter_hook_name = 'GCP_FLAVOR_FILTERS'

    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str, pool_config: dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)

        self.instance_resource_manager: ResourceManager[
            GCPInstance, InstanceCreationRequest, InstanceCreationOutcome
        ] = ResourceManager(
            logger=logger,
            pool=self,
            resource_type='instance',
            list_resources=self._query_instances_by_guest_request,
            resource_name=self._render_instance_name,
            create_resource_request=self._create_instance_request,
            create_resource=self._create_instance,
            reuse_resource=self._reuse_instance,
        )

    @property
    def _instances_client(self) -> compute_v1.InstancesClient:
        return cast(
            compute_v1.InstancesClient, compute_v1.InstancesClient.from_service_account_info(self._service_account_info)
        )

    @property
    def _flavors_client(self) -> compute_v1.MachineTypesClient:
        return cast(
            compute_v1.MachineTypesClient,
            compute_v1.MachineTypesClient.from_service_account_info(self._service_account_info),
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
        capabilities.supports_console_url = False
        capabilities.supports_spot_instances = False
        capabilities.supports_confidential_computing = False
        capabilities.supports_native_post_install_script = False
        capabilities.supported_guest_logs = []
        capabilities.supports_hostnames = False
        return _Ok(capabilities)

    @functools.cached_property
    def _service_account_info(self) -> dict[Any, Any]:
        # The type is validated using pool's jsonschema (object)
        return cast(dict[Any, Any], self.pool_config['service-account-info'])

    def image_name_to_image_info(
        self, logger: gluetool.log.ContextAdapter, image_name: str
    ) -> Result[PoolImageInfo, Failure]:
        image_project = self.pool_config['image-project']

        try:
            images_client = compute_v1.ImagesClient.from_service_account_info(self._service_account_info)
            image_description = images_client.get(project=image_project, image=image_name)
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
            compatible=PoolImageCompatible(),
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

    @override
    def _query_backend_flavors(self, logger: gluetool.log.ContextAdapter) -> _Result[list[BackendFlavor], Failure]:
        project = self.pool_config['project']
        zone = self.pool_config['zone']

        try:
            flavors = self._flavors_client.list(project=project, zone=zone)
        except Exception as exc:
            return _Error(Failure.from_exc('failed to list flavors', exc))

        return _Ok([compute_v1.types.MachineType.to_dict(flavor) for flavor in flavors])

    def list_instances(self, logger: gluetool.log.ContextAdapter) -> Result[list[GCPInstance], Failure]:
        project = self.pool_config['project']
        zone = self.pool_config['zone']

        try:
            raw_instances = list(self._instances_client.list(project=project, zone=zone))
        except Exception as exc:
            return Error(Failure.from_exc('failed to list instances', exc))

        res = []
        for raw_instance in raw_instances:
            r_created_at = self.timestamp_to_datetime(raw_instance.creation_timestamp)
            if r_created_at.is_error:
                return Error(
                    Failure.from_failure(
                        'Could not parse instance timestamp',
                        r_created_at.unwrap_error(),
                        instance=raw_instance.name,
                    )
                )

            res.append(
                GCPInstance(
                    id=str(raw_instance.id),
                    name=raw_instance.name,
                    status=raw_instance.status,
                    created_at=r_created_at.unwrap(),
                )
            )

        return Ok(res)

    def _query_instances_by_guest_request(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest
    ) -> _Result[list[GCPInstance], Failure]:
        r_instances_list = self.list_instances(logger)
        if r_instances_list.is_error:
            return _Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

        r_expected_name = self._render_instance_name(guest_request)
        if not is_successful(r_expected_name):
            return _Error(Failure.from_failure('failed to get expected instance name', r_expected_name.failure()))
        expected_name = r_expected_name.unwrap()

        res = [instance for instance in r_instances_list.unwrap() if instance.name.startswith(expected_name)]

        try:
            res = sorted(res, key=lambda x: x.created_at)
        except ValueError as exc:
            return _Error(Failure.from_exc('Double check time format, could not convert time data', exc))

        return _Ok(res)

    @override
    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None,
    ) -> Result[ProvisioningProgress, Failure]:
        pool_data = guest_request.pool_data.mine(self, GCPPoolData)

        if not pool_data.instance_id:
            return Error(Failure('Need instance ID to fetch guest info'))

        request = compute_v1.GetInstanceRequest(
            instance=str(pool_data.instance_id),
            project=self.pool_config['project'],
            zone=self.pool_config['zone'],
        )

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

    @override
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
            GCPPoolResourcesIDs(instance_name=pool_data.instance_name),
            guest_request=guest_request,
        )

    @override
    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = GCPPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        request = compute_v1.DeleteInstanceRequest(
            instance=resource_ids.instance_name,
            project=self.pool_config['project'],
            zone=self.pool_config['zone'],
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
        labels: Optional[dict[str, str]] = None,
    ) -> compute_v1.AttachedDisk:
        disk_type = f'zones/{zone}/diskTypes/{disk_type}'

        size = size or DEFAULT_DISK_SIZE

        if not zone:
            zone = self.pool_config['zone']

        initialize_params = compute_v1.AttachedDiskInitializeParams(
            source_image=image_link,
            disk_size_gb=int(size.to('GiB').magnitude),
            disk_type=disk_type,
        )

        if labels:
            initialize_params.labels = labels

        return compute_v1.AttachedDisk(
            initialize_params=initialize_params,
            auto_delete=True,
            boot=True,
        )

    def _ensure_machine_type_is_canonical(self, machine_type: str, zone: str) -> str:
        if re.match(r'^zones/[a-z\d\-]+/machineTypes/[a-z\d\-]+$', machine_type):
            return machine_type
        return f'zones/{zone}/machineTypes/{machine_type}'

    def _create_instance_request(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
    ) -> _Result[InstanceCreationRequest, Failure]:
        r_image_flavor_pairs = self._collect_image_flavor_pairs(logger, session, guest_request)

        if r_image_flavor_pairs.is_error:
            return _Error(r_image_flavor_pairs.unwrap_error())

        can_acquire, pairs = r_image_flavor_pairs.unwrap()

        if not can_acquire.can_acquire:
            assert can_acquire.reason is not None

            return _Error(Failure(can_acquire.reason.message))

        image = pairs[0][0]

        flavor = pairs[0][1]

        r_base_tags = self.get_guest_tags(logger, session, guest_request)
        if r_base_tags.is_error:
            return _Error(r_base_tags.unwrap_error())

        return _Ok(
            InstanceCreationRequest(
                image=image,
                flavor=flavor,
                tags=r_base_tags.unwrap(),
            )
        )

    def _create_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_name: str,
        instance_request: InstanceCreationRequest,
    ) -> _Result[InstanceCreationOutcome, Failure]:
        from ..tasks import _get_ssh_key

        project_id = self.pool_config['project']
        zone = self.pool_config['zone']
        network_link = self.pool_config['network-resource-url']
        machine_type = instance_request.flavor.id

        r_ssh_key = _get_ssh_key(guest_request.ownername, guest_request.ssh_keyname)
        if r_ssh_key.is_error:
            return _Error(
                Failure.from_failure(
                    'failed to get SSH key', r_ssh_key.unwrap_error(), keyname=guest_request.ssh_keyname
                )
            )

        ssh_key = r_ssh_key.unwrap()
        if not ssh_key:
            return _Error(Failure('failed to get SSH key', keyname=guest_request.ssh_keyname))

        labels = _serialize_tags(instance_request.tags) if instance_request.tags else {}

        boot_disk = self._create_boot_disk_for_image_link(instance_request.image.id, zone=zone, labels=labels)

        access = compute_v1.AccessConfig(
            type_=compute_v1.AccessConfig.Type.ONE_TO_ONE_NAT.name,  # type: ignore[attr-defined]
            name='External NAT',
            network_tier=compute_v1.AccessConfig.NetworkTier.PREMIUM.name,  # type: ignore[attr-defined]
        )

        network_interface = compute_v1.NetworkInterface(
            network=network_link,
            access_configs=[access],
        )

        ssh_metadata = compute_v1.Items(
            key='ssh-keys',
            value=f'{instance_request.image.ssh.username}:{ssh_key.public}',
        )

        instance = compute_v1.Instance(
            network_interfaces=[network_interface],
            name=instance_name,
            disks=[boot_disk],
            machine_type=self._ensure_machine_type_is_canonical(zone=zone, machine_type=machine_type),
            scheduling=compute_v1.Scheduling(),
        )

        if instance_request.tags:
            instance.labels = labels

        instance.metadata.items.append(ssh_metadata)

        request = compute_v1.InsertInstanceRequest(
            zone=zone,
            project=project_id,
            instance_resource=instance,
        )

        client = self._instances_client

        try:
            operation = client.insert(request=request)
        except google.api_core.exceptions.BadRequest as exc:
            return _Error(Failure.from_exc('Failed to create a GCP instance', exc))
        # NOTE(ivasilev) this should not happen anymore with ResourceManager approach
        except google.api_core.exceptions.Conflict as exc:
            return _Error(Failure.from_exc('Failed to create a GCP instance because of a conflict', exc))
        except google.api_core.exceptions.PreconditionFailed as exc:
            return _Error(Failure.from_exc('Instance creation failed due to policy', exc))

        return _Ok(
            InstanceCreationOutcome(
                resource=GCPInstance(
                    id=str(operation.target_id),
                    name=instance_name,
                    status='',
                    created_at=datetime.datetime.now(tz=datetime.timezone.utc),
                ),
                image=instance_request.image,
                flavor=instance_request.flavor,
            )
        )

    def _reuse_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_request: InstanceCreationRequest,
        instance: GCPInstance,
    ) -> _Result[InstanceCreationOutcome, Failure]:
        return _Ok(
            InstanceCreationOutcome(resource=instance, image=instance_request.image, flavor=instance_request.flavor)
        )

    @override
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
                        # NOTE(ivasilev) gcp outputs all arches as uppercase, like AMD64 or X86_64
                        arch=image.architecture.lower(),
                        boot=FlavorBoot(),
                        ssh=ssh_info,
                        supports_kickstart=False,
                        compatible=PoolImageCompatible(),
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

    @override
    @rewrap_to_gluetool
    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None,
    ) -> _Result[ProvisioningProgress, Failure]:
        return (
            self.instance_resource_manager.acquire(logger, guest_request, session)
            .bind(
                lambda instance_outcome: _Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.PENDING,
                        pool_data=GCPPoolData(
                            instance_id=int(instance_outcome.resource.id),
                            instance_name=instance_outcome.resource.name,
                        ),
                        ssh_info=instance_outcome.image.ssh,
                    )
                )
            )
            .lash(
                lambda failure: _Error(failure)
                if failure.recoverable
                else _Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=GCPPoolData(),
                        pool_failures=[failure],
                    )
                )
            )
        )

    def _get_ip_from_instance(self, instance: compute_v1.Instance) -> Optional[str]:
        access_configs = instance.network_interfaces[0].access_configs
        if access_configs:
            return access_configs[0].nat_i_p
        return None

    @override
    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        """
        Trigger hard reboot of a GCP instance.
        """
        pool_data = guest_request.pool_data.mine_or_none(self, GCPPoolData)

        if not pool_data:
            return Ok(None)

        request = compute_v1.ResetInstanceRequest(
            instance=pool_data.instance_name, project=self.pool_config['project'], zone=self.pool_config['zone']
        )

        try:
            self._instances_client.reset(request=request)
        except google.api_core.exceptions.NotFound as exc:
            return Error(Failure.from_exc('Instance to reboot was not found', exc))
        except google.api_core.exceptions.ClientError as exc:
            return Error(Failure.from_exc('Failed to reboot instance', exc))

        return Ok(None)

    @override
    def fetch_pool_flavor_info(self) -> Result[list[GCPFlavor], Failure]:
        def _constructor(
            logger: gluetool.log.ContextAdapter, raw_flavor: dict[str, Any]
        ) -> Iterator[Result[GCPFlavor, Failure]]:
            yield Ok(
                GCPFlavor(
                    name=raw_flavor['name'],
                    # The id will be the flavor name the cloud expects to see for provisioning
                    id=raw_flavor['name'],
                    boot=FlavorBoot(),
                    cpu=FlavorCpu(processors=int(raw_flavor['guest_cpus'])),
                    memory=UNITS.Quantity(int(raw_flavor['memory_mb']), UNITS.megabytes),
                    network=FlavorNetworks(),
                    virtualization=FlavorVirtualization(),
                )
            )

        return self._construct_pool_flavor_infos(
            self.logger, self._query_backend_flavors, lambda raw_flavor: cast(str, raw_flavor['name']), _constructor
        )

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

    # The following are necessary implementations of abstract methods the driver does not have use for. They are
    # required, but we will remove them in the future.
    @override
    def acquire_console_url(
        self, logger: gluetool.log.ContextAdapter, guest: GuestRequest
    ) -> Result[ConsoleUrlData, Failure]:
        return Error(Failure('unsupported driver method', poolname=self.poolname, method='acquire_console_url'))


PoolDriver._drivers_registry['gcp'] = GCPDriver
