from datetime import datetime
import json
import threading

import gluetool.log
from gluetool.result import Result, Error, Ok

from . import PoolDriver, vm_info_to_ip, create_tempfile, run_cli_tool
from .. import Failure
from ..db import GuestRequest, SnapshotRequest, SSHKey
from ..environment import Environment
from ..guest import Guest, SSHInfo
from ..snapshot import Snapshot

from typing import Any, Dict, List, Optional


class AzureGuest(Guest):
    def __init__(
        self,
        guestname: str,
        instance_id: str,
        instance_name: str,
        resource_group: str,
        address: Optional[str] = None,
        ssh_info: Optional[SSHInfo] = None
    ) -> None:
        super(AzureGuest, self).__init__(guestname, address, ssh_info)

        self.instance_id = instance_id
        self.instance_name = instance_name
        self.resource_group = resource_group

    def __repr__(self) -> str:
        return '<AzureGuest: az_instance={}, instance_name={}, resource_group={}, address={}, ssh_info={}>'.format(
            self.instance_id,
            self.instance_name,
            self.resource_group,
            self.address,
            self.ssh_info
        )

    @property
    def pool_data(self) -> Dict[str, Any]:
        return {
            'instance_id': self.instance_id,
            'instance_name': self.instance_name,
            'resource_group': self.resource_group
        }


class AzureDriver(PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any],
    ) -> None:
        super(AzureDriver, self).__init__(logger, poolname, pool_config)

    def snapshot_factory(
        self,
        snapshpt_request: SnapshotRequest
    ) -> Result[Snapshot, Failure]:
        raise NotImplementedError()

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
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
        """

        assert guest_request.poolname

        r_guest = self.guest_factory(guest_request, ssh_key=master_key)

        if r_guest.is_error:
            return Error(r_guest.unwrap_error())
        guest = r_guest.unwrap()

        assert isinstance(guest, AzureGuest)

        r_output = self._show_guest(guest.instance_id)

        if r_output.is_error:
            return Error(Failure('no such guest'))

        output = r_output.unwrap()

        if not output:
            return Error(Failure('Server show commmand output is empty'))

        status = output['provisioningState'].lower()

        logger.info('instance status is {}'.format(status))

        if status == 'failed':
            self.release_guest(
                logger,
                AzureGuest(
                    guest.guestname,
                    guest.instance_id,
                    guest.instance_name,
                    guest.resource_group,
                    address=None,
                    ssh_info=None
                )
            )
            logger.warning('Instance ended up in failed state. NOT provisioning a new one')

            return self._do_acquire_guest(logger, guest_request, environment, master_key)

        r_ip_address = vm_info_to_ip(output, 'publicIps', r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}).*')

        if r_ip_address.is_error:
            return Error(r_ip_address.unwrap_error())
        ip_address = r_ip_address.unwrap()

        guest.address = ip_address

        return Ok(guest)

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest: Guest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """

        if not isinstance(guest, AzureGuest):
            return Error(Failure('guest is not an AzureGuest guest'))

        # NOTE(ivasilev) As Azure doesn't delete vm's resources (disk, secgroup, publicip) upon vm deletion
        # will need to delete stuff manually. Lifehack: query for tag uid=name used during vm creation
        cmd = ['resource', 'list', '--tag', 'uid={}'.format(guest.instance_name)]
        resources_by_tag = self._run_cmd_with_auth(cmd).unwrap()

        def _delete_resource(res_id: str) -> Any:
            options = ['resource', 'delete', '--ids', res_id]
            return self._run_cmd_with_auth(options, json_format=False)

        # delete vm first, resources second
        del_output = [_delete_resource(guest.instance_id)]
        for res in [r for r in resources_by_tag if r["type"] != "Microsoft.Compute/virtualMachines"]:
            del_output.append(_delete_resource(res['id']))
        del_errors = [x._value.details['command_output'].stderr for x in del_output if x.is_error]
        if del_errors:
            return Error(Failure('The following resources were not cleaned up: {}'.format(
                b'\n'.join(del_errors))))

        return Ok(True)

    def create_snapshot(
        self,
        snapshot_request: SnapshotRequest,
        guest: Guest
    ) -> Result[Snapshot, Failure]:
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
        snapshot: Snapshot,
        guest: Guest,
        canceled: Optional[threading.Event] = None,
        start_again: bool = True
    ) -> Result[Snapshot, Failure]:
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
        snapshot: Snapshot,
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
        snapshot_request: SnapshotRequest,
        guest: Guest
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
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
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
            guest_request,
            environment,
            master_key,
            cancelled)

    def guest_factory(
        self,
        guest_request: GuestRequest,
        ssh_key: SSHKey
    ) -> Result[Guest, Failure]:
        if not guest_request.pool_data:
            return Error(Failure('invalid pool data'))

        pool_data = json.loads(guest_request.pool_data)

        if 'instance_id' not in pool_data:
            return Error(Failure('no guest was provisioned for request'))

        r_output = self._show_guest(pool_data['instance_id'])

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        return Ok(
            AzureGuest(
                guest_request.guestname,
                pool_data['instance_id'],
                pool_data['instance_name'],
                pool_data['resource_group'],
                address=guest_request.address,
                ssh_info=SSHInfo(port=guest_request.ssh_port,
                                 username=guest_request.ssh_username,
                                 key=ssh_key),
            )
        )

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
        instance_id: str,
    ) -> Result[Any, Failure]:

        login_output = self._login()
        if login_output.is_error:
            return Error(login_output.value)
        r_output = self._run_cmd_with_auth(['vm', 'show', '-d', '--ids', instance_id])
        if r_output.is_error:
            return Error(r_output.value)
        return Ok(r_output.unwrap())

    def _do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:

        name = 'artemis-guest-{}'.format(datetime.now().strftime('%d-%m-%Y-%H-%M-%S'))
        # XXX FIXME not using hooks for the moment, transfer to a hook some time later
        if environment.pool:
            image = environment.os.compose
        else:
            raise NotImplementedError("Compose mapping not implemented for azure yet")

        r_output = None

        def _create(custom_data_filename: str) -> Result[Any, Failure]:
            """
            The actual call to the azure cli guest create command is happening here.
            If custom_data_filename is an empty string then the guest vm is booted with no user-data.
            """

            az_options = [
                'vm',
                'create',
                '--resource-group', self.pool_config['resource-group'],
                '--image', image,
                '--name', name,
                '--tags', 'uid={}'.format(name),
                '--custom-data', custom_data_filename,
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
        logger.info('instance status is {}'.format(status))

        # There is no chance that the guest will be ready in this step
        # Return the guest with no ip and check it in the next update_guest event
        return Ok(
            AzureGuest(
                guest_request.guestname,
                output['id'],
                name,
                self.pool_config['resource-group'],
                address=None,
                ssh_info=None
            )
        )
