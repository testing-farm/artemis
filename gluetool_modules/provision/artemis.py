# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import re
import six
import sys
import os

import gluetool
import gluetool_modules.libs
import requests

from gluetool import GlueError, GlueCommandError, SoftGlueError
from gluetool.log import log_dict, LoggerMixin
from gluetool.result import Result
from gluetool.utils import Command, dump_yaml, treat_url, normalize_multistring_option, wait, normalize_path
from gluetool_modules.libs.guest import NetworkedGuest

from gluetool_modules.libs.testing_environment import TestingEnvironment

from typing import Any, Dict, List, Optional, Tuple, cast, Union  # noqa

DEFAULT_PRIORIY_GROUP = 'default-priority'
DEFAULT_READY_TIMEOUT = 300
DEFAULT_READY_TICK = 3
DEFAULT_ACTIVATION_TIMEOUT = 240
DEFAULT_ACTIVATION_TICK = 5
DEFAULT_API_CALL_TIMEOUT = 60
DEFAULT_API_CALL_TICK = 1
DEFAULT_ECHO_TIMEOUT = 240
DEFAULT_ECHO_TICK = 10
DEFAULT_BOOT_TIMEOUT = 240
DEFAULT_BOOT_TICK = 10
DEFAULT_SSH_OPTIONS = ['UserKnownHostsFile=/dev/null', 'StrictHostKeyChecking=no']
DEFAULT_SNAPSHOT_READY_TIMEOUT = 600
DEFAULT_SNAPSHOT_READY_TICK = 10

#: Artemis provisioner capabilities.
#: Follows :doc:`Provisioner Capabilities Protocol </protocols/provisioner-capabilities>`.
ProvisionerCapabilities = collections.namedtuple('ProvisionerCapabilities', ['available_arches'])


class ArtemisResourceError(GlueError):
    def __init__(self):
        # type: () -> None
        super(ArtemisResourceError, self).__init__("Artemis resource ended in 'error' state")


class ArtemisAPIError(SoftGlueError):
    def __init__(self, response, error=None):
        # type: (Any, Optional[str]) -> None

        self.status_code = response.status_code
        self.json = {}  # type: Dict[str, str]
        self.text = response.text.encode('ascii', 'replace')  # type: str
        self._errors = error

        # We will look at response's headers to try to guess if response's content is json serializable
        # If yes, we will expect it to either have 'message' or 'errors' key, it's value could be used in exception
        # If no, we will use raw text in exception instead
        headers = {key.lower(): response.headers[key] for key in response.headers}

        if headers.get('content-type') and 'application/json' in headers['content-type']:
            try:
                self.json = response.json()
            except Exception as exc:
                self.json['errors'] = str(exc)

        super(ArtemisAPIError, self).__init__(
            'Call to Artemis API failed, HTTP {}: {}'.format(
                self.status_code, self.errors))

    @property
    def errors(self):
        # type: () -> str

        if self._errors:
            return self._errors

        if self.json.get('message'):
            return self.json['message']

        if self.json.get('errors'):
            return self.json['errors']

        return self.text


class ArtemisAPI(object):
    ''' Class that allows RESTful communication with Artemis API '''

    def __init__(self, module, api_url, timeout, tick):
        # type: (gluetool.Module, str, int, int) -> None

        self.module = module
        self.url = treat_url(api_url)
        self.timeout = timeout
        self.tick = tick
        self.check_if_artemis()

    def api_call(self, endpoint, method='GET', expected_status_code=200, data=None):
        # type: (str, str, Union[int, List[int]], Optional[Dict[str, Any]]) -> Any

        if not isinstance(expected_status_code, list):
            expected_status_code = [expected_status_code]

        def _api_call():
            # type: () -> Result[Any, str]

            _request = getattr(requests, method.lower(), None)
            if _request is None:
                return Result.Error('Unknown HTTP method {}'.format(method))

            try:
                response = _request('{}{}'.format(self.url, endpoint), json=data)
            except requests.exceptions.ConnectionError as error:
                error_string = str(error)
                # Artemis API can go down in the middle of the request sending, and that
                # might be unavoidable, we need to retry. In this case request
                # raises ConnectionError with 'Connection aborted' string in the message.
                # https://urllib3.readthedocs.io/en/latest/reference/#urllib3.exceptions.ProtocolError
                if 'Connection aborted' in error_string:
                    return Result.Error('Connecton aborted: {}'.format(error_string))
                six.reraise(*sys.exc_info())

            assert isinstance(expected_status_code, list)
            if response.status_code in expected_status_code:
                return Result.Ok(response)

            return Result.Error('Artemis API error: {}'.format(ArtemisAPIError(response)))

        try:
            response = wait('api_call', _api_call, timeout=self.timeout, tick=self.tick)

        except GlueError as exc:
            raise GlueError('Artemis API call failed: {}'.format(exc))

        return response

    def check_if_artemis(self):
        # type: () -> None
        '''
        Checks if `url` actually points to ArtemisAPI by calling '/guests' endpoint (which should always return a list)
        '''

        def error(response):
            # type: (Any) -> ArtemisAPIError
            err_msg = 'URL {} does not point to Artemis API. Expected list, got {}' \
                .format(self.url, response.text.encode('ascii', 'replace'))
            err = ArtemisAPIError(response, error=err_msg)
            return err

        response = self.api_call('guests/')

        if not isinstance(response.json(), list):
            raise error(response)

    def create_guest(self,
                     environment,  # type: TestingEnvironment
                     pool=None,   # type: Optional[str]
                     keyname=None,  # type: Optional[str]
                     priority=None,  # type: Optional[str]
                     user_data=None,  # type: Optional[Dict[str,Any]]
                     post_install_script=None  # type: Optional[str]
                     ):
        # type: (...) -> Any
        '''
        Submits a guest request to Artemis API.

        :param tuple environment: description of the environment caller wants to provision.
            Follows :doc:`Testing Environment Protocol </protocols/testing-environment>`.

        :param str pool: name of the pool

        :param str keyname: name of key stored in Artemis configuration.

        :param str priority: Priority group of the guest request.
            See Artemis API docs for more.

        :rtype: dict
        :returns: Artemis API response serialized as dictionary or ``None`` in case of failure.
        '''

        compose = environment.compose
        snapshots = environment.snapshots

        post_install_script_contents = None
        if post_install_script:
            with open(normalize_path(post_install_script)) as f:
                post_install_script_contents = f.read()

        data = {
            'keyname': keyname,
            'environment': {
                'arch': environment.arch,
                'os': {},
                'snapshots': snapshots
            },
            'priority_group': priority,
            'post_install_script': post_install_script_contents
        }  # type: Dict[str, Any]

        if pool:
            data['environment']['pool'] = pool

        data['environment']['os']['compose'] = compose

        data['user_data'] = user_data

        return self.api_call('guests/', method='POST', expected_status_code=201, data=data).json()

    def inspect_guest(self, guest_id):
        # type: (str) -> Any
        '''
        Requests Artemis API for data about a specific guest.

        :param str guest_id: Artemis guestname (or guest id).
            See Artemis API docs for more.

        :rtype: dict
        :returns: Artemis API response serialized as dictionary or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}'.format(guest_id)).json()

    def inspect_guest_events(self, guest_id):
        # type: (str) -> Any
        '''
        Requests Artemis API for data about a specific guest's events.

        :param str guest_id: Artemis guestname (or guest id).
            See Artemis API docs for more.

        :rtype: list
        :returns: Artemis API response serialized as list or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}/events'.format(guest_id)).json()

    def cancel_guest(self, guest_id):
        # type: (str) -> Any
        '''
        Requests Artemis API to cancel guest provision (or, in case a guest os already provisioned, return the guest).

        :param str guest_id: Artemis guestname (or guest id).
            See Artemis API docs for more.

        :rtype: Response
        :returns: Artemis API response or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}'.format(guest_id), method='DELETE', expected_status_code=[200, 204])

    def create_snapshot(self, guest_id, start_again=True):
        # type: (str, bool) -> Any
        '''
        Requests Aremis API to create a snapshot of a guest.

        :param str guest_id: Artemis guestname (or guest_id).
            See Artemis API docs for more.

        :param bool start_again: If true artemis will start a guest after snapshot creating

        :rtype: dict
        :returns: Artemis API response serialized as dictionary or ``None`` in case of failure.
        '''

        data = {'start_again': start_again}

        return self.api_call('guests/{}/snapshots'.format(guest_id),
                             method='POST',
                             data=data,
                             expected_status_code=201
                             ).json()

    def inspect_snapshot(self, guest_id, snapshot_id):
        # type: (str, str) -> Any
        '''
        Requests Artemis API for data about a specific snapshot.

        :param str guest_id: Artemis guestname (or guest id).
        :param str snaphsot_id: Artemis snapshotname (or snapshot id).
            See Artemis API docs for more.

        :rtype: dict
        :returns: Artemis API response serialized as dictionary or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}/snapshots/{}'.format(guest_id, snapshot_id)).json()

    def restore_snapshot(self, guest_id, snapshot_id):
        # type: (str, str) -> Any
        '''
        Requests Artemis API to restore a guest to a snapshot.

        :param str guest_id: Artemis guestname (or guest id).
        :param str snaphsot_id: Artemis snapshotname (or snapshot id).
            See Artemis API docs for more.

        :rtype: dict
        :returns: Artemis API response serialized as dictionary or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}/snapshots/{}/restore'.format(guest_id, snapshot_id),
                             method='POST',
                             expected_status_code=201
                             ).json()

    def cancel_snapshot(self, guest_id, snapshot_id):
        # type: (str, str) -> Any
        '''
        Requests Artemis API to cancel snapshot creating
        (or, in case a snapshot is already provisioned, delete the snapshot).

        :param str guest_id: Artemis guestname (or guest id).
        :param str snaphsot_id: Artemis snapshotname (or snapshot id).
            See Artemis API docs for more.

        :rtype: Response
        :returns: Artemis API response or ``None`` in case of failure.
        '''

        return self.api_call('guests/{}/snapshots/{}'.format(guest_id, snapshot_id),
                             method='DELETE',
                             expected_status_code=[200, 204])


class ArtemisSnapshot(LoggerMixin):
    def __init__(self,
                 module,  # type: ArtemisProvisioner
                 name,  # type: str
                 guest  # type: ArtemisGuest
                 ):
        # type: (...) -> None
        super(ArtemisSnapshot, self).__init__(module.logger)

        self._module = module
        self.name = name
        self.guest = guest

    def __repr__(self):
        # type: () -> str
        return '<ArtemisSnapshot(name="{}")>'.format(self.name)

    def wait_snapshot_ready(self, timeout, tick):
        # type: (int, int) -> None

        try:
            wait('snapshot_ready', self._check_snapshot_ready, timeout=timeout, tick=tick)

        except GlueError as exc:
            raise GlueError("Snapshot couldn't be ready: {}".format(exc))

    def _check_snapshot_ready(self):
        # type: () -> Result[bool, str]

        snapshot_state = None

        try:
            snapshot_data = self._module.api.inspect_snapshot(self.guest.artemis_id, self.name)

            snapshot_state = snapshot_data['state']

            if snapshot_state == 'ready':
                return Result.Ok(True)

            if snapshot_state == 'error':
                raise ArtemisResourceError()

        except ArtemisResourceError as e:
            six.reraise(*sys.exc_info())

        except Exception as e:
            self.warn('Exception raised: {}'.format(e))

        return Result.Error("Couldn't get snapshot {}".format(self.name))

    def release(self):
        # type: () -> None
        self._module.api.cancel_snapshot(self.guest.artemis_id, self.name)


class ArtemisGuest(NetworkedGuest):

    def __init__(self,
                 module,  # type: ArtemisProvisioner
                 guestname,  # type: str
                 hostname,  # type: str
                 environment,  # type: TestingEnvironment
                 port=None,  # type: Optional[int]
                 username=None,  # type: Optional[str]
                 key=None,  # type: Optional[str]
                 options=None,  # type: Optional[List[str]]
                 **kwargs   # type: Optional[Dict[str, Any]]
                 ):

        super(ArtemisGuest, self).__init__(module,
                                           hostname,
                                           environment=environment,
                                           name=guestname,
                                           port=port,
                                           username=username,
                                           key=key,
                                           options=options)
        self.artemis_id = guestname
        self._snapshots = []  # type: List[ArtemisSnapshot]

    def __str__(self):
        # type: () -> str
        return 'ArtemisGuest({}, {}@{}, {})'.format(self.artemis_id, self.username, self.hostname, self.environment)

    def _check_ip_ready(self):
        # type: () -> Result[bool, str]

        def dump_events(events, filename):
            # type: (List[Any], str) -> None
            dump_yaml(events, '{}.tmp'.format(filename))
            command = ['mv', '{}.tmp'.format(filename), filename]
            try:
                Command(command).run()
            except GlueCommandError:
                pass

        try:
            guest_data = cast(ArtemisProvisioner, self._module).api.inspect_guest(self.artemis_id)
            guest_state = guest_data['state']
            guest_address = guest_data['address']

            if guest_state == 'ready':
                if guest_address:
                    return Result.Ok(True)

            if guest_state == 'error':
                raise ArtemisResourceError()

            guest_events_list = cast(ArtemisProvisioner, self._module).api.inspect_guest_events(self.artemis_id)
            dump_events(guest_events_list, '{}-artemis-guest-log.yaml'.format(self.artemis_id))

            error_guest_events_list = [event for event in guest_events_list if event['eventname'] == 'error']
            if error_guest_events_list:
                # There was/were error(s) while provisioning
                last_error = sorted(error_guest_events_list, key=lambda event: event['updated'], reverse=True)[0]
                err_msg = "Guest provisioning error(s) from Artemis, newest error: {}".format(
                    last_error['details']['error']
                )
                self.debug(err_msg)

        except ArtemisResourceError as e:
            six.reraise(*sys.exc_info())

        except Exception as e:
            self.warn('Exception raised: {}'.format(e))

        return Result.Error("Couldn't get address for guest {}".format(self.artemis_id))

    def _wait_ready(self, timeout, tick):
        # type: (int, int)-> None
        '''
        Wait till the guest is ready to be provisined, which it's IP/hostname is available
        '''

        try:
            self.wait('ip_ready', self._check_ip_ready, timeout=timeout, tick=tick)

        except GlueError as exc:
            raise GlueError("Guest couldn't be provisioned: {}".format(exc))

    def _wait_alive(self, connect_timeout, connect_tick, echo_timeout, echo_tick, boot_timeout, boot_tick):
        # type: (int, int, int, int, int, int) -> None
        '''
        Wait till the guest is alive. That covers several checks.
        '''

        try:
            self.wait_alive(connect_timeout=connect_timeout, connect_tick=connect_tick,
                            echo_timeout=echo_timeout, echo_tick=echo_tick,
                            boot_timeout=boot_timeout, boot_tick=boot_tick)

        except GlueError as exc:
            raise GlueError('Guest failed to become alive: {}'.format(exc))

    @property
    def supports_snapshots(self):
        # type: () -> bool
        assert self.environment
        # Cast needs to mypy stop complaints
        return cast(bool, self.environment.snapshots)

    def setup(self, variables=None, **kwargs):
        # type: (Optional[Dict[str, Any]], **Any) -> Any
        """
        Custom setup for Artemis guests. Add a hostname in case there is none.

        :param dict variables: dictionary with GUEST_HOSTNAME and/or GUEST_DOMAINNAME keys
        """
        variables = variables or {}

        # Our playbooks require hostname and domainname.
        # If not set, create them - some tests may depend on resolvable hostname.
        if 'GUEST_HOSTNAME' not in variables:
            assert self.hostname
            variables['GUEST_HOSTNAME'] = re.sub(r'10\.(\d+)\.(\d+)\.(\d+)', r'host-\1-\2-\3', self.hostname)

        if 'GUEST_DOMAINNAME' not in variables:
            variables['GUEST_DOMAINNAME'] = 'host.example.com'

        if 'IMAGE_NAME' not in variables:
            assert self.environment
            variables['IMAGE_NAME'] = self.environment.compose

        return super(ArtemisGuest, self).setup(variables=variables, **kwargs)

    def create_snapshot(self, start_again=True):
        # type: (bool) -> ArtemisSnapshot
        """
        Creates a snapshot from the current running image of the guest.

        All created snapshots are deleted automatically during destruction.

        :rtype: ArtemisSnapshot
        :returns: newly created snapshot.
        """
        response = cast(ArtemisProvisioner, self._module).api.create_snapshot(self.artemis_id, start_again)

        snapshot = ArtemisSnapshot(cast(ArtemisProvisioner, self._module), response.get('snapshotname'), self)

        snapshot.wait_snapshot_ready(self._module.option('snapshot-ready-timeout'),
                                     self._module.option('snapshot-ready-tick'))

        # The snapshot is ready, but the guest hasn't started yet
        self._wait_ready(self._module.option('ready-timeout'),
                         self._module.option('ready-tick'))

        self._snapshots.append(snapshot)

        self.info("image snapshot '{}' created".format(snapshot.name))

        return snapshot

    def restore_snapshot(self, snapshot):
        # type: (ArtemisSnapshot) -> ArtemisGuest
        """
        Rebuilds server with the given snapshot.

        :param snapshot: :py:class:`ArtemisSnapshot` instance.
        :rtype: ArtemisGuest
        :returns: server instance rebuilt from given snapshot.
        """

        self.info("rebuilding server with snapshot '{}'".format(snapshot.name))

        cast(ArtemisProvisioner, self._module).api.restore_snapshot(self.artemis_id, snapshot.name)
        snapshot.wait_snapshot_ready(self._module.option('snapshot-ready-timeout'),
                                     self._module.option('snapshot-ready-tick'))

        self.info("image snapshot '{}' restored".format(snapshot.name))

        return self

    def _release_snapshots(self):
        # type: () -> None
        for snapshot in self._snapshots:
            snapshot.release()

        if self._snapshots:
            self.info('Successfully released all {} snapshots'.format(len(self._snapshots)))

        self._snapshots = []

    def _release_instance(self):
        # type: () -> None
        cast(ArtemisProvisioner, self._module).api.cancel_guest(self.artemis_id)

    def destroy(self):
        # type: () -> None
        self._release_snapshots()
        self._release_instance()
        cast(ArtemisProvisioner, self._module).remove_from_list(self)


class ArtemisProvisioner(gluetool.Module):
    ''' Provisions guest via Artemis API '''
    name = 'artemis'
    description = 'Provisions guest via Artemis API'
    options = [
        ('API options', {
            'api-url': {
                'help': 'Artemis API url',
                'metavar': 'URL',
                'type': str
            },
            'key': {
                'help': 'Desired guest key name',
                'metavar': 'KEYNAME',
                'type': str
            },
            'arch': {
                'help': 'Desired guest architecture',
                'metavar': 'ARCH',
                'type': str
            },
            'priority-group': {
                'help': 'Desired guest priority group (default: %(default)s)',
                'metavar': 'PRIORITY_GROUP',
                'type': str,
                'default': DEFAULT_PRIORIY_GROUP
            },
            'user-data-vars': {
                'help': 'Save some context vars as user-data field (default: none)',
                'action': 'append',
                'default': []

            }
        }),
        ('Common options', {
            'keep': {
                'help': '''Keep instance(s) running, do not destroy. No reservation records are created and it is
                           expected from the user to cleanup the instance(s).''',
                'action': 'store_true'
            },
            'provision': {
                'help': 'Provision given number of guests',
                'metavar': 'COUNT',
                'type': int
            }
        }),
        ('Guest options', {
            'ssh-options': {
                'help': 'SSH options (default: none).',
                'action': 'append',
                'default': []
            },
            'ssh-key': {
                'help': 'SSH key that is used to connect to the machine',
                'type': str
            }
        }),
        ('Provisioning options', {
            'compose': {
                'help': 'Desired guest compose',
                'metavar': 'COMPOSE',
                'type': str
            },
            'pool': {
                'help': 'Desired pool',
                'metavar': 'POOL',
                'type': str
            },
            'playbook': {
                'help': 'Ansible playbook to run after the guest became ready, before alive checks.',
            },
            'setup-provisioned': {
                'help': "Setup guests after provisioning them. See 'guest-setup' module",
                'action': 'store_true'
            },
            'snapshots': {
                'help': 'Choose a pool with snapshot support',
                'action': 'store_true'
            },
            'post-install-script': {
                'help': 'A post install script to run after vm becomes ready (default: %(default)s)',
                'metavar': 'POST_INSTALL_SCRIPT',
                'type': str,
                'default': ''
            }
        }),
        ('Timeout options', {
            'ready-timeout': {
                'help': 'Timeout for guest to become ready (default: %(default)s)',
                'metavar': 'READY_TIMEOUT',
                'type': int,
                'default': DEFAULT_READY_TIMEOUT
            },
            'ready-tick': {
                'help': 'Check every READY_TICK seconds if a guest has become ready (default: %(default)s)',
                'metavar': 'READY_TICK',
                'type': int,
                'default': DEFAULT_READY_TICK
            },
            'activation-timeout': {
                'help': 'Timeout for guest to become active (default: %(default)s)',
                'metavar': 'ACTIVATION_TIMEOUT',
                'type': int,
                'default': DEFAULT_ACTIVATION_TIMEOUT
            },
            'activation-tick': {
                'help': 'Check every ACTIVATION_TICK seconds if a guest has become active (default: %(default)s)',
                'metavar': 'ACTIVATION_TICK',
                'type': int,
                'default': DEFAULT_ACTIVATION_TICK
            },
            'api-call-timeout': {
                'help': 'Timeout for Artemis API calls (default: %(default)s)',
                'metavar': 'API_CALL_TIMEOUT',
                'type': int,
                'default': DEFAULT_API_CALL_TIMEOUT
            },
            'api-call-tick': {
                'help': 'Check every API_CALL_TICK seconds for Artemis API response (default: %(default)s)',
                'metavar': 'API_CALL_TICK',
                'type': int,
                'default': DEFAULT_API_CALL_TICK
            },
            'echo-timeout': {
                'help': 'Timeout for guest echo (default: %(default)s)',
                'metavar': 'ECHO_TIMEOUT',
                'type': int,
                'default': DEFAULT_ECHO_TIMEOUT
            },
            'echo-tick': {
                'help': 'Echo guest every ECHO_TICK seconds (default: %(default)s)',
                'metavar': 'ECHO_TICK',
                'type': int,
                'default': DEFAULT_ECHO_TICK
            },
            'boot-timeout': {
                'help': 'Timeout for guest boot (default: %(default)s)',
                'metavar': 'BOOT_TIMEOUT',
                'type': int,
                'default': DEFAULT_BOOT_TIMEOUT
            },
            'boot-tick': {
                'help': 'Check every BOOT_TICK seconds if a guest has boot (default: %(default)s)',
                'metavar': 'BOOT_TICK',
                'type': int,
                'default': DEFAULT_BOOT_TICK
            },
            'snapshot-ready-timeout': {
                'help': 'Timeout for snapshot to become ready (default: %(default)s)',
                'metavar': 'SNAPSHOT_READY_TIMEOUT',
                'type': int,
                'default': DEFAULT_SNAPSHOT_READY_TIMEOUT
            },
            'snapshot-ready-tick': {
                'help': 'Check every SNAPSHOT_READY_TICK seconds if a snapshot has become ready (default: %(default)s)',
                'metavar': 'SNAPSHOT_READY_TICK',
                'type': int,
                'default': DEFAULT_SNAPSHOT_READY_TICK
            }
        })
    ]

    required_options = ('api-url', 'key', 'priority-group', 'ssh-key')

    shared_functions = ['provision', 'provisioner_capabilities']

    def sanity(self):
        # type: () -> None

        if not self.option('provision'):
            return

        if not self.option('arch'):
            raise GlueError('Missing required option: --arch')

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        super(ArtemisProvisioner, self).__init__(*args, **kwargs)

        self.guests = []  # type: List[ArtemisGuest]
        self.api = None  # type: ArtemisAPI  # type: ignore

    def provisioner_capabilities(self):
        # type: () -> ProvisionerCapabilities
        '''
        Return description of Artemis provisioner capabilities.

        Follows :doc:`Provisioner Capabilities Protocol </protocols/provisioner-capabilities>`.
        '''

        return ProvisionerCapabilities(
            available_arches=['x86_64', 'ppc64le', 's390x', 'aarch64']
        )

    def provision_guest(self,
                        environment,  # type: TestingEnvironment
                        pool=None,  # type: Optional[str]
                        key=None,  # type: Optional[str]
                        priority=None,  # type: Optional[str]
                        ssh_key=None,  # type: Optional[str]
                        options=None,  # type: Optional[List[str]]
                        post_install_script=None,  # type: Optional[str]
                       ):  # noqa
        # type: (...) -> ArtemisGuest
        '''
        Provision Artemis guest by submitting a request to Artemis API.

        :param tuple environment: description of the environment caller wants to provision.
            Follows :doc:`Testing Environment Protocol </protocols/testing-environment>`.

        :param str pool: name of the pool

        :param str key: name of key stored in Artemis configuration.

        :param str priority: Priority group of the guest request.
            See Artemis API docs for more.

        :param str ssh_key: the path to public key, that should be used to securely connect to a provisioned machine.
            See Artemis API docs for more.

        :param list option: SSH options that would be used when securely connecting to a provisioned guest via SSH.

        :rtype: ArtemisGuest
        :returns: ArtemisGuest instance or ``None`` if it wasn't possible to grab the guest.
        '''

        context = self.shared('eval_context')
        user_data = {var: context.get(var) for var in normalize_multistring_option(self.option('user-data-vars'))}

        response = self.api.create_guest(environment,
                                         pool=pool,
                                         keyname=key,
                                         priority=priority,
                                         user_data=user_data,
                                         post_install_script=post_install_script)

        guestname = response.get('guestname')
        guest = None

        try:
            guest = ArtemisGuest(self, guestname, response['address'], environment,
                                 port=response['ssh']['port'], username=response['ssh']['username'],
                                 key=ssh_key, options=options)

            guest.info('Guest is being provisioned')
            log_dict(guest.debug, 'Created guest request', response)

            guest._wait_ready(timeout=self.option('ready-timeout'), tick=self.option('ready-tick'))
            response = self.api.inspect_guest(guest.artemis_id)
            guest.hostname = response['address']
            guest.info("Guest is ready: {}".format(guest))

            if self.option('playbook'):
                self.require_shared('run_playbook')

                env_variables = os.environ.copy()
                env_variables.update({'ANSIBLE_SSH_RETRIES': '60'})

                self.shared(
                    'run_playbook',
                    gluetool.utils.normalize_path(self.option('playbook')),
                    guest,
                    env=env_variables,
                    variables={
                        'IMAGE_NAME': environment.compose
                    }
                )

            if self.option('playbook'):
                self.require_shared('run_playbook')

                env_variables = os.environ.copy()
                env_variables.update({'ANSIBLE_SSH_RETRIES': '60'})

                self.shared(
                    'run_playbook',
                    gluetool.utils.normalize_path(self.option('playbook')),
                    guest,
                    env=env_variables,
                    variables={
                        'IMAGE_NAME': environment.compose
                    }
                )

            guest._wait_alive(self.option('activation-timeout'), self.option('activation-tick'),
                              self.option('echo-timeout'), self.option('echo-tick'),
                              self.option('boot-timeout'), self.option('boot-tick'))
            guest.info('Guest has become alive')

        except Exception as exc:
            self.warn("Exception while provisioning guest: {}".format(exc))
            if not self.option('keep'):
                if guest:
                    self.api.cancel_guest(guest.artemis_id)
                elif guestname:
                    self.api.cancel_guest(guestname)
            raise exc

        return guest

    def provision(self, environment, **kwargs):
        # type: (TestingEnvironment, Any) -> List[ArtemisGuest]
        '''
        Provision Artemis guest(s).

        :param tuple environment: description of the environment caller wants to provision.
            Follows :doc:`Testing Environment Protocol </protocols/testing-environment>`.

        :rtype: list
        :returns: List of ArtemisGuest instances or ``None`` if it wasn't possible to grab the guests.
        '''

        pool = self.option('pool')
        key = self.option('key')
        ssh_key = self.option('ssh-key')
        priority = self.option('priority-group')
        options = normalize_multistring_option(self.option('ssh-options'))
        post_install_script = self.option('post-install-script')

        if self.option('snapshots'):
            environment.snapshots = True

        guest = self.provision_guest(environment,
                                     pool=pool,
                                     key=key,
                                     priority=priority,
                                     ssh_key=ssh_key,
                                     options=options,
                                     post_install_script=post_install_script)

        guest.info('Guest provisioned')
        self.guests.append(guest)

        return [guest]

    def execute(self):
        # type: () -> None

        self.api = ArtemisAPI(self,
                              self.option('api-url'),
                              self.option('api-call-timeout'),
                              self.option('api-call-tick'))

        # TODO: print Artemis API version when version endpoint is implemented
        self.info('Using Artemis API {}'.format(self.api.url))

        if not self.option('provision'):
            return

        provision_count = self.option('provision')
        arch = self.option('arch')
        compose = self.option('compose')

        environment = TestingEnvironment(arch=arch,
                                         compose=compose)

        for num in range(provision_count):
            self.info("Trying to provision guest #{}".format(num+1))
            guest = self.provision(environment,
                                   provision_count=provision_count)[0]
            guest.info("Provisioned guest #{} {}".format(num+1, guest))

        if self.option('setup-provisioned'):
            for guest in self.guests:
                guest.setup()

    def remove_from_list(self, guest):
        # type: (ArtemisGuest) -> None
        if guest not in self.guests:
            self.error('{} is not found in guests list')
            return

        self.guests.remove(guest)

    def destroy(self, failure=None):
        # type: (Optional[Any]) -> None
        if self.option('keep'):
            return

        for guest in self.guests[:]:
            guest.info('Canceling guest')
            guest.destroy()
            guest.info('Successfully removed guest')
