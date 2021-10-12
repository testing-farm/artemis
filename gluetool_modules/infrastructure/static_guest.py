# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import re
import socket
from concurrent.futures import ThreadPoolExecutor, wait, Future

import gluetool
from gluetool import GlueError
from gluetool_modules.libs.guest import NetworkedGuest

from gluetool_modules.libs.testing_environment import TestingEnvironment

# Type annotations
from typing import Any, List, Optional, Literal, NamedTuple, Set, cast  # noqa

# SSH connection defaults
DEFAULT_SSH_USER = 'root'
DEFAULT_SSH_OPTIONS = ['UserKnownHostsFile=/dev/null', 'StrictHostKeyChecking=no']

# wait_alive defaults
DEFAULT_BOOT_TIMEOUT = 10
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_ECHO_TIMEOUT = 10

#: Generic provisioner capabilities.
#: Follows :doc:`Provisioner Capabilities Protocol </protocols/provisioner-capabilities>`.
ProvisionerCapabilities = collections.namedtuple('ProvisionerCapabilities', ['available_arches'])


class StaticGuest(NetworkedGuest):
    """
    StaticGuest is like py:class:`gluetool_modules.libs.guests.NetworkedGuest`, just it does allow degraded services.
    """

    def _is_allowed_degraded(self, service):
        # type: (Any) -> Literal[True]
        return True

    def __init__(self, module, fqdn, **kwargs):
        # type: (CIStaticGuest, str, **Any) -> None
        super(StaticGuest, self).__init__(module, fqdn, **kwargs)

        try:
            # we expect the machines to be already booted really, timeouts are low
            self.wait_alive(
                boot_timeout=module.option('boot-timeout'), boot_tick=2,
                connect_timeout=module.option('connect-timeout'), connect_tick=2,
                echo_timeout=module.option('echo-timeout'), echo_tick=2)

        except (socket.gaierror, GlueError) as error:
            raise GlueError("Error connecting to guest '{}': {}".format(self, error))

        # populate guest architecture from the OS`
        arch = self.execute('arch').stdout
        if not arch:
            raise GlueError('Error retrieving guest architecture')
        self.environment = TestingEnvironment(arch=arch.rstrip(), compose=None)


class CIStaticGuest(gluetool.Module):
    """
    Provides connection to static guests specified on the command line. The provisioner capabilities are auto-detected
    from the connected machines.
    """
    name = 'static-guest'

    options = [
        ('General Options', {
            'guest': {
                'help': "Guest connection details, in form '[user@]hostname[:port]. Default user is 'root' and port 22",
                'action': 'append'
            },
            'guest-setup': {
                'help': 'Run guest setup after adding the guest. Useful for testing guest-setup related modules.',
                'action': 'store_true'
            },
            'ssh-key': {
                'help': 'SSH key to use to connect to the guests.'
            }
        }),
        ('Timeouts', {
            'boot-timeout': {
                'help': 'Wait SECONDS for a guest to finish its booting process (default: %(default)s)',
                'type': int,
                'default': DEFAULT_BOOT_TIMEOUT,
                'metavar': 'SECONDS'
            },
            'connect-timeout': {
                'help': 'Wait SECOND for a guest to become reachable over network (default: %(default)s)',
                'type': int,
                'default': DEFAULT_CONNECT_TIMEOUT,
                'metavar': 'SECONDS'
            },
            'echo-timeout': {
                'help': 'Wait SECOND for a guest shell to become available (default: %(default)s)',
                'type': int,
                'default': DEFAULT_ECHO_TIMEOUT,
                'metavar': 'SECONDS'
            },
        })
    ]

    shared_functions = ['provision', 'provisioner_capabilities']
    required_options = ('guest', 'ssh-key')

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(CIStaticGuest, self).__init__(*args, **kwargs)

        # All guests connected
        self._guests = []  # type: List[StaticGuest]

    def guest_connect(self, guest):
        # type: (str) -> StaticGuest
        """
        Connect to a guest and return a StaticGuest instance.

        :returns: A connected guest
        """

        match = re.match(r'^(?:([^@]+)@)?([^:@ ]+)(?::([0-9]+))?$', guest)
        if not match:
            raise GlueError("'{}' is not a valid hostname".format(guest))

        port = None  # type: Optional[str]
        (user, hostname, port) = match.groups()

        user = user or DEFAULT_SSH_USER
        port = port or None  # default is 22 from NetworkedGuest

        self.info("adding guest '{}' and checking for its connection".format(guest))
        static_guest = StaticGuest(
            self, hostname,
            name=hostname, username=user, port=port, key=self.option('ssh-key'),
            options=DEFAULT_SSH_OPTIONS)

        return static_guest

    def provisioner_capabilities(self):
        # type: () -> ProvisionerCapabilities
        """
        Return description of Static Guest provisioner capabilities.

        Follows :doc:`Provisioner Capabilities Protocol </protocols/provisioner-capabilities>`.
        """

        return ProvisionerCapabilities(
            available_arches=[
                # note that arch returns with newline, we need to strip it
                guest.environment.arch for guest in self._guests if guest.environment is not None
            ]
        )

    def provision(self, environment, count=1, **kwargs):
        # type: (TestingEnvironment, int, **Any) -> List[StaticGuest]
        """
        Returns a list of N static guests, where N is specified by the parameter ``count``.

        :param tuple environment: Description of the environment caller wants to provision.
        :param int count: Number of guests the client module is asking for.
        :rtype: list(StaticGuest)
        :returns: A list of connected guests.
        """

        # Return requested number of guests. If the do not exist, blow up
        # NOTE: distro is currently ignored
        returned_guests = [
            guest for guest in self._guests if guest.environment and guest.environment.arch == environment.arch
        ][0:count]

        if len(returned_guests) != count:
            raise GlueError("Did not find {} guest(s) with architecture '{}'.".format(count, environment.arch))

        return returned_guests

    def execute(self):
        # type: () -> None
        with ThreadPoolExecutor(thread_name_prefix="connect-thread") as executor:
            futures = {executor.submit(self.guest_connect, guest) for guest in self.option('guest')}

            Wait = NamedTuple('Wait', (('done', Set[Future[Any]]), ('not_done', Set[Future[Any]])))
            wait_result = cast(Wait, wait(futures))

            for future in wait_result.done:
                guest = future.result()
                self.info("added guest '{}' with architecture '{}'".format(guest, guest.environment.arch))

                if self.option('guest-setup'):
                    guest.setup()

                self._guests.append(guest)
