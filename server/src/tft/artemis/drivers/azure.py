import dataclasses
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure, Knob
from ..db import GuestRequest, SnapshotRequest, SSHKey
from ..environment import Environment
from ..script import hook_engine
from . import PoolData, PoolDriver, PoolImageInfoType, PoolResourcesIDsType, ProvisioningProgress, create_tempfile, \
    run_cli_tool, vm_info_to_ip

#: A delay, in seconds, between two calls of `update-guest-request` checking provisioning progress.
KNOB_UPDATE_TICK: Knob[int] = Knob(
    'azure.update.tick',
    has_db=False,
    envvar='ARTEMIS_AZURE_UPDATE_TICK',
    envvar_cast=int,
    default=30
)


@dataclasses.dataclass
class AzurePoolData(PoolData):
    instance_id: str
    instance_name: str
    resource_group: str


class AzureDriver(PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any],
    ) -> None:
        super(AzureDriver, self).__init__(logger, poolname, pool_config)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        *other_resources: Any,
        instance_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids: PoolResourcesIDsType = {}

        if instance_id is not None:
            resource_ids['instance_id'] = instance_id

        if other_resources:
            resource_ids['assorted_resource_ids'] = other_resources

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def image_info_by_name(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfoType, Failure]:
        r_images_show = self._run_cmd_with_auth(['vm', 'image', 'show', '--urn', imagename])

        if r_images_show.is_error:
            return Error(r_images_show.unwrap_error())

        return Ok(PoolImageInfoType(
            name=imagename,
            id=imagename
        ))

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_ids: PoolResourcesIDsType
    ) -> Result[None, Failure]:
        # NOTE(ivasilev) As Azure doesn't delete vm's resources (disk, secgroup, publicip) upon vm deletion
        # will need to delete stuff manually. Lifehack: query for tag uid=name used during vm creation

        # delete vm first, resources second

        def _delete_resource(res_id: str) -> Any:
            options = ['resource', 'delete', '--ids', res_id]
            return self._run_cmd_with_auth(options, json_format=False)

        if 'instance_id' in resource_ids:
            r_delete = _delete_resource(resource_ids.pop('instance_id'))

            if r_delete.is_error:
                return Error(r_delete.unwrap_error())

        if 'assorted_resource_ids' in resource_ids:
            for resource_id in cast(List[str], resource_ids.pop('assorted_resource_ids')):
                r_delete = _delete_resource(resource_id)

                if r_delete.is_error:
                    return Error(r_delete.unwrap_error())

        return Ok(None)

    def can_acquire(
        self,
        environment: Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """
        return Ok(True)

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """

        r_output = self._show_guest(guest_request)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        status = output['provisioningState'].lower()

        logger.info('current instance status {}:{}'.format(
            AzurePoolData.unserialize(guest_request).instance_id,
            status
        ))

        if status == 'failed':
            logger.warning('Instance ended up in failed state')

            r_acquire = self._do_acquire_guest(logger, session, guest_request, environment, master_key)

            if r_acquire.is_ok:
                logger.info('successfully reprovisioned, releasing the broken instance')

                # We can schedule release only when acquire succeeded. Only successfull acquire
                # let's us update guest request pool data with new instance ID. If acquire failed,
                # we keep our broken instance, and enter update guest task later, trying again
                # to either update or reschedule and drop the failed one.
                self.release_guest(logger, guest_request)

            return r_acquire

        r_ip_address = vm_info_to_ip(output, 'publicIps', r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*')

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())

        return Ok(ProvisioningProgress(
            is_acquired=True,
            pool_data=AzurePoolData.unserialize(guest_request),
            address=r_ip_address.unwrap()
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """

        pool_data = AzurePoolData.unserialize(guest_request)

        # NOTE(ivasilev) As Azure doesn't delete vm's resources (disk, secgroup, publicip) upon vm deletion
        # will need to delete stuff manually. Lifehack: query for tag uid=name used during vm creation
        cmd = ['resource', 'list', '--tag', 'uid={}'.format(pool_data.instance_name)]
        resources_by_tag = self._run_cmd_with_auth(cmd).unwrap()

        def _delete_resource(res_id: str) -> Any:
            options = ['resource', 'delete', '--ids', res_id]
            return self._run_cmd_with_auth(options, json_format=False)

        # delete vm first, resources second
        assorted_resource_ids = []

        for res in [r for r in resources_by_tag if r["type"] != "Microsoft.Compute/virtualMachines"]:
            assorted_resource_ids.append(res['id'])

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
        environment: Environment,
        master_key: SSHKey,
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
        return self._do_acquire_guest(
            logger,
            session,
            guest_request,
            environment,
            master_key,
            cancelled)

    def _run_cmd(self, options: List[str], json_format: bool = True) -> Result[Any, Failure]:
        r_run = run_cli_tool(
            self.logger,
            ['az'] + options,
            json_output=json_format,
            command_scrubber=lambda cmd: (['azure'] + options)
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        if json_format:
            json_output, _ = r_run.unwrap()

            return Ok(json_output)

        output_stdout, _ = r_run.unwrap()

        return Ok(output_stdout)

    def _run_cmd_with_auth(self, options: List[str], json_format: bool = True,
                           login: bool = True) -> Result[Any, Failure]:
        if login:
            login_output = self._login()
            if login_output.is_error:
                return Error(login_output.value)
        return self._run_cmd(options, json_format)

    def _login(self) -> Result[Any, Failure]:
        # login if credentials have been passed -> try to login
        if self.pool_config['username'] and self.pool_config['password']:
            login_output = self._run_cmd(['login', '--username', self.pool_config['username'],
                                          '--password', self.pool_config['password']])
            if login_output.is_error:
                return Error(login_output.value)
        return Ok(True)

    def _show_guest(
        self,
        guest_request: GuestRequest
    ) -> Result[Any, Failure]:

        login_output = self._login()
        if login_output.is_error:
            return Error(login_output.value)

        r_output = self._run_cmd_with_auth([
            'vm',
            'show',
            '-d',
            '--ids', AzurePoolData.unserialize(guest_request).instance_id
        ])

        if r_output.is_error:
            return Error(r_output.value)
        return Ok(r_output.unwrap())

    # NOTE(ivasilev) Borrowed as is with cosmetic changes from openstack driver.
    # Should land into the hooks library one day.
    def _env_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[PoolImageInfoType, Failure]:
        r_engine = hook_engine('AZURE_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image: Result[PoolImageInfoType, Failure] = engine.run_hook(
            'AZURE_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )

        if r_image.is_error:
            failure = r_image.unwrap_error()
            failure.update(environment=environment)

            return Error(failure)

        return r_image

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:

        name = 'artemis-guest-{}'.format(datetime.now().strftime('%d-%m-%Y-%H-%M-%S'))
        r_image = self._env_to_image(logger, environment)
        if r_image.is_error:
            return Error(r_image.unwrap_error())

        image = r_image.unwrap()

        logger.info('provisioning from image {}'.format(image))

        r_output = None

        def _create(custom_data_filename: str) -> Result[Any, Failure]:
            """
            The actual call to the azure cli guest create command is happening here.
            If custom_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            r_base_tags = self.get_guest_tags(session, guest_request)

            if r_base_tags.is_error:
                return Error(r_base_tags.unwrap_error())

            tags = {
                **r_base_tags.unwrap(),
                **{
                    # This tag links our VM and its resources, which comes handy when we want to remove everything
                    # leaving no leaks.
                    'uid': name
                }
            }

            az_options = [
                'vm',
                'create',
                '--resource-group', self.pool_config['resource-group'],
                '--image', image.id,
                '--name', name,
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
                    '{}={}'.format(tag, value)
                    for tag, value in tags.items()
                ]

            return self._run_cmd_with_auth(az_options)

        if guest_request.post_install_script:
            # user has specified custom script to execute, contents stored as post_install_script
            with create_tempfile(file_contents=guest_request.post_install_script) as custom_data_filename:
                r_output = _create(custom_data_filename)
        else:
            # using post_install_script setting from the pool config
            r_output = _create(self.pool_config.get('post-install-script', ''))

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        output = r_output.unwrap()
        if not output['id']:
            return Error(Failure('Instance id not found'))

        status = output['powerState'].lower()

        logger.info('acquired instance status {}:{}'.format(
            output['id'],
            status
        ))

        # There is no chance that the guest will be ready in this step
        return Ok(ProvisioningProgress(
            is_acquired=False,
            pool_data=AzurePoolData(
                instance_id=output['id'],
                instance_name=name,
                resource_group=self.pool_config['resource-group']
            ),
            delay_update=KNOB_UPDATE_TICK.value
        ))
