# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple, Union, cast

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


AZURE_RESOURCE_TYPE: Dict[str, ResourceType] = {
    'Microsoft.Compute/virtualMachines': ResourceType.VIRTUAL_MACHINE,
    'Microsoft.Network/virtualNetworks': ResourceType.VIRTUAL_NETWORK,
    'Microsoft.Compute/disks': ResourceType.DISK,
    'Microsoft.Network/publicIPAddresses': ResourceType.STATIC_IP,
    'Microsfot.Network/networkInterfaces': ResourceType.NETWORK_INTERFACE
}


@dataclasses.dataclass
class AzurePoolData(PoolData):
    instance_id: str
    instance_name: str
    resource_group: str


@dataclasses.dataclass
class AzurePoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    assorted_resource_ids: Optional[List[Dict[str, str]]] = None


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
        r_run = run_cli_tool(
            logger,
            ['az'] + options,
            env={
                'AZURE_CONFIG_DIR': str(self.session_directory)
            },
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
            r_login = self._run_cmd(
                logger,
                [
                    'login',
                    '--username', self.pool.pool_config['username'],
                    '--password', self.pool.pool_config['password']
                ],
                commandname='az.login'
            )

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

    pool_data_class = AzurePoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
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
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = AzurePoolResourcesIDs(
            instance_id=instance_id,
            assorted_resource_ids=list(other_resources) if other_resources else None
        )

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        with AzureSession(logger, self) as session:
            r_images_show = session.run_az(
                logger,
                ['vm', 'image', 'show', '--urn', imagename],
                commandname='az.vm-image-show'
            )

        if r_images_show.is_error:
            return Error(Failure.from_failure(
                'failed to fetch image information',
                r_images_show.unwrap_error()
            ))

        return Ok(PoolImageInfo(
            name=imagename,
            id=imagename,
            arch=None,
            boot=FlavorBoot(),
            ssh=PoolImageSSHInfo()
        ))

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        # NOTE(ivasilev) As Azure doesn't delete vm's resources (disk, secgroup, publicip) upon vm deletion
        # will need to delete stuff manually. Lifehack: query for tag uid=name used during vm creation

        # delete vm first, resources second

        resource_ids = AzurePoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        def _delete_resource(res_id: str) -> Any:
            with AzureSession(logger, self) as session:
                return session.run_az(
                    logger,
                    ['resource', 'delete', '--ids', res_id],
                    json_format=False,
                    commandname='az.resource-delete'
                )

        if resource_ids.instance_id is not None:
            r_delete = _delete_resource(resource_ids.instance_id)

            if r_delete.is_error:
                return Error(r_delete.unwrap_error())

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        if resource_ids.assorted_resource_ids is not None:
            for resource in resource_ids.assorted_resource_ids:
                r_delete = _delete_resource(resource['id'])

                if r_delete.is_error:
                    return Error(Failure.from_failure(
                        'failed to terminate instance',
                        r_delete.unwrap_error()
                    ))

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
        image = images[0]

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
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

        def _create(custom_data_filename: str) -> Result[JSONType, Failure]:
            """
            The actual call to the azure cli guest create command is happening here.
            If custom_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            az_options = [
                'vm',
                'create',
                '--resource-group', self.pool_config['resource-group'],
                '--image', image.id,
                '--name', tags['ArtemisGuestLabel'],
                '--custom-data', custom_data_filename
            ]

            # According to `az` documentation, `--tags` accepts `space-separated tags`, but that's not really true.
            # Space-separated, yes, but not passed as one value after `--tags` option:
            #
            # NO:  --tags "foo=bar baz=79"
            # NO:  '--tags foo=bar baz=79'
            # YES: --tags foo=bar baz=79
            #
            # As you can see, `baz=79` in the valid example is not a space-separated bit of a `--tags` argument,
            # but rather a stand-alone command-line item that is consumed by `--tags`.
            if tags:
                az_options += [
                    '--tags'
                ] + [
                    f'{tag}={value}'
                    for tag, value in tags.items()
                ]

            with AzureSession(logger, self) as session:
                return session.run_az(
                    logger,
                    az_options,
                    commandname='az.vm-create'
                )

        if guest_request.post_install_script:
            # user has specified custom script to execute, contents stored as post_install_script
            with create_tempfile(file_contents=guest_request.post_install_script) as custom_data_filename:
                r_output = _create(custom_data_filename)
        else:
            # using post_install_script setting from the pool config
            r_output = _create(self.pool_config.get('post-install-script', ''))

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
                resource_group=self.pool_config['resource-group']
            ),
            delay_update=r_delay.unwrap(),
            ssh_info=image.ssh
        ))


PoolDriver._drivers_registry['azure'] = AzureDriver
