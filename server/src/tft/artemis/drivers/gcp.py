# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import threading
from typing import Any, Dict, List, Optional, Union, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from tft.artemis.drivers.aws import awscli_error_cause_extractor

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
    per_pool=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='configuration/artemis-image-map-gcp.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'gcp.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_GCP_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)


@dataclasses.dataclass
class GCPPoolData(PoolData):
    name: str
    id: str
    zone: str


class GCPDriver(PoolDriver):
    drivername = 'gcp'

    pool_data_class = GCPPoolData

    def __init__(self,
                 logger: gluetool.log.ContextAdapter,
                 poolname: str,
                 pool_config: Dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)

        gcloud_auth_cmd = ['gcloud',
                           'auth',
                           'activate-service-account', self.pool_config['account'],
                           '--key-file', self.pool_config['key_file'],
                           '--format=json']
        gcloud_auth_cmd_exec_result = run_cli_tool(self.logger, gcloud_auth_cmd, json_output=True)
        assert gcloud_auth_cmd_exec_result.is_ok

        posix_username_result = self.retrieve_posix_username_for_service_account(self.pool_config['account'])
        assert posix_username_result.is_ok
        self.posix_username = posix_username_result.ok

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
        return HookImageInfoMapper(self, 'GCP_ENVIRONMENT_TO_IMAGE')

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        return Ok(capabilities)

    def map_image_name_to_image_info(self,
                                     logger: gluetool.log.ContextAdapter,
                                     imagename: str) -> Result[PoolImageInfo, Failure]:

        gcloud_describe_img_subcmd = ['images', 'describe', imagename]
        # We need to pass in a project that owns the images instead of the usual one from config that will own the instances
        image_description_result = self.run_gcloud_compute_subcommand(gcloud_describe_img_subcmd, project='rhel-cloud')
        if image_description_result.is_error:
            return Error(Failure.from_failure('Failed to fetch image information', image_description_result.unwrap_error()))

        image_description = image_description_result.unwrap()
        image_info = PoolImageInfo(name=image_description['name'],
                                   id=image_description['id'],
                                   arch=image_description['architecture'],
                                   boot=FlavorBoot(),
                                   ssh=PoolImageSSHInfo())

        return Ok(image_info)

    def release_pool_resources(self,
                               logger: gluetool.log.ContextAdapter,
                               raw_resource_ids: SerializedPoolResourcesIDs) -> Result[None, Failure]:
        raise NotImplementedError()
        return Ok(None)

    def can_acquire(self,
                    logger: gluetool.log.ContextAdapter,
                    session: sqlalchemy.orm.session.Session,
                    guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Check whether this driver can provision a guest that would satisfy the given environment.
        """

        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        return Ok(guest_request.environment.has_hw_constraints is not True)

    def update_guest(self,
                     logger: gluetool.log.ContextAdapter,
                     session: sqlalchemy.orm.session.Session,
                     guest_request: GuestRequest,
                     cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        """
        Called to query instance information described by ``guest_request`` to check whether the provisioning is done.

        The provisioning is considered done, when the ProvisioningProgress contains an external IP. If the IP is not a part
        of the returned `ProvisioningProgress`, the call to this method will be repeated.
        """
        instance_info_result = self._query_instance_info(guest_request)
        if instance_info_result.is_error:
            return Error(Failure('no such guest'))

        instance_info = instance_info_result.unwrap()
        if not instance_info:
            return Error(Failure('Server show commmand output is empty'))

        status = instance_info['status'].lower()
        pool_data = GCPPoolData.unserialize(guest_request)

        if status == 'failed':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=GCPPoolData.unserialize(guest_request),
                pool_failures=[Failure('instance ended up in "failed" state')]
            ))

        ip_address = instance_info['networkInterfaces'][0]['accessConfigs'][0]['natIP']

        return Ok(ProvisioningProgress(
            state=ProvisioningState.COMPLETE,
            pool_data=GCPPoolData.unserialize(guest_request),
            address=ip_address
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        if GCPPoolData.is_empty(guest_request):
            return Ok(True)

        pool_data = GCPPoolData.unserialize(guest_request)
        delete_instance_cmd_result = self.run_gcloud_compute_subcommand(['instances', 'delete', f'{pool_data.name}', f'--zone={pool_data.zone}'])
        if delete_instance_cmd_result.is_error:
            return Error(delete_instance_cmd_result.unwrap_error())
        return Ok(True)

    def retrieve_posix_username_for_service_account(self, account_email: str) -> Result[str, Failure]:
        iam_describe_service_account_cmd = ['gcloud', 'iam', 'service-accounts', 'describe', account_email, '--format=json']
        describe_service_cmd_result = run_cli_tool(self.logger, iam_describe_service_account_cmd, json_output=True)
        if describe_service_cmd_result.is_error:
            failure = Failure.from_failure('failed to get service account description', describe_service_cmd_result.unwrap_error())
            return Error(failure)

        service_account_id = cast(Dict[Any, Any], describe_service_cmd_result.unwrap().json)['uniqueId']
        posix_username = f'sa_{service_account_id}'
        return Ok(posix_username)


    def acquire_guest(self,
                      logger: gluetool.log.ContextAdapter,
                      session: sqlalchemy.orm.session.Session,
                      guest_request: GuestRequest,
                      cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        # 1. Read some 'knob' configuration about delay before updating the acquired guest
        # 2. Map the request onto the image that should be spawned
        # 3. Collect and add tags - for resource management
        # 4. Call the CLI to create the VM as requested
        # 5. Read & return creation output

        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        delay_cfg_option_read_result = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)
        if delay_cfg_option_read_result.is_error:
            return Error(delay_cfg_option_read_result.unwrap_error())

        map_request_to_image_result = self.image_info_mapper.map(logger, guest_request)
        if map_request_to_image_result.is_error:
            return Error(map_request_to_image_result.unwrap_error())
        image = map_request_to_image_result.unwrap()

        self.log_acquisition_attempt(logger, session, guest_request, image=image)

        r_base_tags = self.get_guest_tags(logger, session, guest_request)
        if r_base_tags.is_error:
            return Error(r_base_tags.unwrap_error())
        tags = r_base_tags.unwrap()

        # As guest IDs (names) can start with a number, add 'artemis-' prefix to make sure the instance name will start with a letter
        instance_name = f'artemis-{guest_request.guestname}'

        gcloud_create_instance_subcmd = ['instances',
                                         'create',
                                         instance_name,
                                         f'--metadata=ssh-keys=:{guest_request.ssh_key.public}']

        create_instance_cmd_result = self.run_gcloud_compute_subcommand(gcloud_create_instance_subcmd, specify_zone=True)

        if create_instance_cmd_result.is_error:
            return Error(create_instance_cmd_result.unwrap_error())

        created_instance_description = create_instance_cmd_result.unwrap()

        instance_id = created_instance_description['id']
        status = created_instance_description['status'].lower()
        name = created_instance_description['name']

        if status == 'running':
            provisioninig_state = ProvisioningState.COMPLETE
        else:
            provisioninig_state = ProvisioningState.PENDING

        # GCP creates used based on the service account used to spawn the VM - patch the default accordingly.
        image.ssh.username = cast(str, self.posix_username)

        return Ok(ProvisioningProgress(
            state=provisioninig_state,
            pool_data=GCPPoolData(
                id=created_instance_description['name'],
                name=created_instance_description['name'],
                zone=created_instance_description['zone']
            ),
            delay_update=delay_cfg_option_read_result.ok,
            ssh_info=image.ssh,
            address=created_instance_description['networkInterfaces'][0]['accessConfigs'][0]['natIP']
        ))

    def run_gcloud_compute_subcommand(self,
                                      gcloud_compute_subcmd: List[str],
                                      project: Optional[str] = None,
                                      specify_zone: bool = False) -> Result[Dict[Any, Any], Failure]:
        if not project:
            project = self.pool_config['project']
        zone = self.pool_config['zone']

        gcloud_common_cmd_prefix = ['gcloud', 'compute', f'--project={project}', '--format=json']
        zone_suffix = [f'--zone={zone}'] if specify_zone else []
        command_exec_result = run_cli_tool(self.logger,
                                           gcloud_common_cmd_prefix + gcloud_compute_subcmd + zone_suffix,
                                           poolname=self.poolname,
                                           cause_extractor=awscli_error_cause_extractor,
                                           json_output=True)

        if command_exec_result.is_error:
            return Error(command_exec_result.unwrap_error())

        return Ok(cast(Dict[Any, Any], command_exec_result.unwrap().json))

    def _query_instance_info(self, guest_request: GuestRequest) -> Result[Any, Failure]:
        pool_item = GCPPoolData.unserialize(guest_request)
        instance_info_subcmd = ['instances', 'describe', f'{pool_item.name}']
        info_cmd_result = self.run_gcloud_compute_subcommand(instance_info_subcmd, specify_zone=True)

        if info_cmd_result.is_error:
            error = info_cmd_result.unwrap_error()
            return Error(Failure.from_failure('Failed to fetch instance information', error))

        instance_info = info_cmd_result.unwrap()
        return Ok(instance_info)

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
