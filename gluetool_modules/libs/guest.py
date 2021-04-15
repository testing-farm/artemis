# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
'Guest' is a (possibly remote) system citool modules can run tests
on. It provides some basic functionality to its users, e.g. you can
copy files to it, and execute commands on it, and the rest is up to
the modules.
"""

import logging
import os
import socket
import tempfile

from functools import partial
from gluetool.log import LoggerMixin
from gluetool.result import Result
from gluetool.utils import Command

import gluetool

# Type annotations
# pylint: disable=unused-import,wrong-import-order
from typing import cast, Any, Callable, Dict, List, Optional, Tuple, Union  # noqa


class GuestConnectionError(gluetool.GlueError):
    """
    Failed to connect to guest.
    """

    def __init__(self, guest):
        # type: (NetworkedGuest) -> None

        super(GuestConnectionError, self).__init__('Failed to connect to guest {}'.format(guest))


class GuestLoggingAdapter(gluetool.log.ContextAdapter):
    """
    Custom logger adapter, adding guest's name as a context.
    """

    def __init__(self, logger, guest_name):
        # type: (gluetool.log.ContextAdapter, str) -> None

        super(GuestLoggingAdapter, self).__init__(logger, {'ctx_guest_name': (20, guest_name)})


class Guest(LoggerMixin, object):
    """
    Base class of "remote system that can run our tests" instances.

    :param gluetool.Module module: Module that created or owns the guest.
    :param str name: Name of the guest, to tell apart multiple guests in logs.
    :param environment: Testing environment provided by the guest.
    """

    def init_logging(self, logger, name=None):
        # type: (gluetool.log.ContextAdapter, Optional[str]) -> None
        """
        Initialize guest's logging facilities. This is usualy done by ``__init__`` method, but in some cases
        one might need to emit guest-related messages **before** the guest is fully initialized, e.g. when
        acquiring resources necessary for such initialization.

        :param ContextAdapter logger: parent logger.
        :param str name: name to use for logging context. If not set, ``self.name`` is used. If this property
            is not set either, dummy value is used.
        """

        # Cannot use simple `self.name` - such property may not have been set yet. ``getattr`` adds the extra
        # "does it even exist?" check we need.
        name = name or getattr(self, 'name', '<unknown guest>')

        self.attach_logger(GuestLoggingAdapter(logger, name))

    def __init__(self, module, name, environment=None):
        # type: (gluetool.glue.Module, str, Optional[Any]) -> None

        self._module = module
        self.name = name

        # Call supertype's __init__ to make sure all its necessary stuff happened...
        super(Guest, self).__init__(module.logger)

        # ... but follow with a call to our own method which re-sets logging with proper context.
        # This method is also available to users, it is part of the public API, it is therefore fine
        # to use it to perform this task instead of copying some of its code here, even it'd would be
        # a bit simplified.
        self.init_logging(module.logger)

        self.environment = environment

    def destroy(self):
        # type: () -> None
        """
        Destroy guest. Free its resources, and no one should be able to use it
        after this method finishes.
        """

        raise NotImplementedError()

    def setup(self, variables=None, **kwargs):
        # type: (Optional[Dict[str, Any]], **Any) -> None
        """
        Setup guest before testing. This is up to child classes to implement - it
        may be a mix of direct commands, temporary files, Ansible playbooks (via
        ``guest-setup`` module).
        """

        raise NotImplementedError()

    @property
    def supports_snapshots(self):
        # type: () -> bool
        """
        Returns `True` if it's possible to create and re-use snapshots of the guest.
        """

        return False

    def create_snapshot(self, start_again=True):
        # type: (bool) -> Any
        """
        Create a snapshot of the guest.

        :param bool start_again: If ``True``, after creating a snapshot guest should be started again.
        :returns: Generic identificator that user is expected to pass to `restore_snapshot`
          when he intents to get the snapshot restored.
        """

        raise NotImplementedError()

    def restore_snapshot(self, snapshot):
        # type: (Any) -> Guest
        """
        Restore given snapshot.

        :returns: a guest. It may be a completely different instance of `Guest`, but
          in any case represents the guest with requested snapshot restored.
        """

        raise NotImplementedError()

    def execute(self, cmd, **kwargs):
        # type: (str, **Any) -> gluetool.utils.ProcessOutput
        """
        Execute a command on the guest. Should behave like `utils.run_command`.
        """

        raise NotImplementedError()

    def copy_to(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, **Any) -> gluetool.utils.ProcessOutput
        """
        Copy a file (or a tree) from local filesystem to the guest.
        """

        raise NotImplementedError()

    def copy_from(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, **Any) -> gluetool.utils.ProcessOutput
        """
        Copy a file (or a tree) from the guest to local filesystem.
        """

        raise NotImplementedError()

    def wait(self, label, check, timeout=None, tick=30):
        # type: (str, gluetool.utils.WaitCheckType[Any], Optional[int], int) -> Any
        """
        Wait for the guest to become responsive (e.g. after reboot).

        :param str label: printable label used for logging.
        :param callable check: called to test the condition. If its return value evaluates as ``True``,
            the condition is assumed to pass the test and waiting ends.
        :param int timeout: fail after this many seconds. ``None`` means test forever.
        :param int tick: test condition every ``tick`` seconds.
        :raises GlueError: when ``timeout`` elapses while condition did not pass the check.
        """

        return gluetool.utils.wait(label, check, timeout=timeout, tick=tick, logger=self.logger)

    def create_file(self, dst, content):
        # type: (str, str) -> None
        """
        Given the name and content, create a file on the guest.
        """

        with tempfile.NamedTemporaryFile() as f:
            f.write(content)
            f.flush()

            self.copy_to(f.name, dst)

    def create_repo(self, name, label, baseurl, **kwargs):
        # type: (str, str, str, **str) -> None
        """
        Given name and its properties, create a repository config file
        on the guest.
        """

        repo = """[{}]
name={}
baseurl={}
{}
""".format(name, label, baseurl, '\n'.join(['{}={}'.format(k, v) for k, v in kwargs.iteritems()]))

        self.create_file(os.path.join(os.sep, 'etc', 'yum.repos.d', '{}.repo'.format(name)), repo)


def sshize_options(options):
    # type: (List[str]) -> List[str]

    return sum([['-o', option] for option in options], [])


class NetworkedGuest(Guest):
    # pylint reports some abstract methods are not implemented by this method.
    # That is expected, methods create_snapshot, restore_snapshot, destroy
    # are left for NetworkedGuest children.
    # pylint: disable=abstract-method

    """
    Guest, accessible over network, using ssh for control.

    :param gluetool.Module module: parent module
    :param str hostname: box hostname - this is used for connecting to the host.
    :param str name: box name - this one appears in log messages, identifies the guest.
      If not set, `hostname` is used.
    :param int port: SSH port (default: 22).
    :param str username: SSH username (default: root).
    :param str key: path to a key file.
    :param list(str) options: list of 'key=value' strings, passed as '-o' options to ssh.
    """

    DEFAULT_SSH_PORT = 22

    # pylint: disable=too-many-arguments
    def __init__(self,
                 module,  # type: gluetool.Module
                 hostname,  # type: str
                 name=None,  # type: Optional[str]
                 port=None,  # type: Optional[int]
                 username=None,  # type: Optional[str]
                 key=None,  # type: Optional[str]
                 options=None,  # type: Optional[List[str]]
                 **kwargs  # type: Any
                ):  # noqa
        # type: (...) -> None

        name = name or hostname
        super(NetworkedGuest, self).__init__(module, name, **kwargs)

        self.hostname = hostname
        self.port = int(port) if port is not None else self.DEFAULT_SSH_PORT
        self.username = username
        self.key = key
        self.options = options or []

        self._ssh = ['ssh']
        self._scp = ['scp']

        if port:
            self._ssh += ['-p', str(port)]
            self._scp += ['-P', str(port)]

        if username:
            self._ssh += ['-l', username]

        if key:
            self._ssh += ['-i', key]
            self._scp += ['-i', key]

        options = sshize_options(self.options)

        self._ssh += options
        self._scp += options

        self._supports_systemctl = None  # type: Optional[bool]
        self._supports_initctl = None  # type: Optional[bool]

    def __repr__(self):
        # type: () -> str

        username = getattr(self, 'username', '<unknown username>')

        return '{}{}:{}'.format(
            (username + '@') if username is not None else '',
            getattr(self, 'hostname', '<unknown hostname>'),
            getattr(self, 'port', '<unknown port>')
        )

    def _is_allowed_degraded(self, service):
        # type: (str) -> bool
        # pylint: disable=unused-argument,no-self-use
        """
        Decide whether a service is allowed to be degraded after booting the guest, or not. By default,
        all services are considered important and therefore for any service, the decission is "not allowed".

        :param str service: Service which is reported as degraded.
        :rtype: bool
        :returns: ``True`` if the service was deemed safe to be left in a degraded state.
        """

        return False

    def setup(self, variables=None, **kwargs):
        # type: (Optional[Dict[str, Any]], **Any) -> Any

        # pylint: disable=arguments-differ
        if not self._module.has_shared('setup_guest'):
            raise gluetool.GlueError("Module 'guest-setup' is required to actually set the guests up.")

        return self._module.shared('setup_guest', self, variables=variables, **kwargs)

    def _execute(self, cmd, **kwargs):
        # type: (List[str], **Any) -> gluetool.utils.ProcessOutput

        try:
            return Command(cmd, logger=self.logger).run(**kwargs)

        except gluetool.GlueCommandError as exc:
            assert exc.output.stderr is not None

            if "No route to host" in exc.output.stderr:
                raise GuestConnectionError(self)

            raise exc

    def execute(self, cmd, ssh_options=None, connection_timeout=None, **kwargs):
        # type: (str, Optional[List[str]], Optional[int], **Any) -> gluetool.utils.ProcessOutput

        # pylint: disable=arguments-differ

        ssh_options = ssh_options or []

        if connection_timeout is not None:
            # The goal is to spend - inactive! - no more than connection_timeout seconds.
            # TO achieve that, we instruct ssh to kill connection if there's nothing
            # going on. However if there *are* data going through the connection, killing
            # the session would require a bigger hammer - that's why it's "connection_timeout"
            # and not a more general "timeout".
            #
            # http://man.openbsd.org/ssh_config#ConnectTimeout
            # http://man.openbsd.org/ssh_config#ServerAliveInterval
            # http://man.openbsd.org/ssh_config#ServerAliveCountMax

            ssh_options += [
                'ConnectTimeout={:d}'.format(connection_timeout),
                'ServerAliveInterval={:d}'.format(connection_timeout),
                'ServerAliveCountMax=1'
            ]

        return self._execute(self._ssh + sshize_options(ssh_options) + [self.hostname] + [cmd], **kwargs)

    def _discover_rc_support(self):
        # type: () -> None

        self._supports_systemctl = False
        self._supports_initctl = False

        try:
            output = self.execute('type systemctl')
        except gluetool.GlueCommandError as exc:
            output = exc.output

        if output.exit_code == 0:
            self._supports_systemctl = True
            return

        try:
            output = self.execute('type initctl')
        except gluetool.GlueCommandError as exc:
            output = exc.output

        if output.exit_code == 0:
            self._supports_initctl = True
            return

    def _check_connectivity(self):
        # type: () -> Result[bool, str]
        """
        Check whether guest is reachable over network by inspecting its ssh port.
        """

        addrinfo = socket.getaddrinfo(self.hostname, self.port, 0, socket.SOCK_STREAM)
        (family, socktype, proto, _, sockaddr) = addrinfo[0]

        sock = socket.socket(family, socktype, proto)
        sock.settimeout(1)

        # pylint: disable=bare-except
        try:
            sock.connect(sockaddr)
            return Result.Ok(True)

        except (socket.error, IOError):
            pass

        finally:
            sock.close()

        return Result.Error('connection failed')

    def _check_echo(self, **kwargs):
        # type: (**Any) -> Result[bool, str]
        """
        Check whether remote shell is available by running a simple ``echo`` command.

        All keyword arguments are passed directly to :py:ref:`execute` method.
        """

        msg = 'guest {} is alive'.format(self.hostname)

        try:
            output = self.execute("echo '{}'".format(msg), **kwargs)

            assert output.stdout is not None

            if output.stdout.strip() == msg:
                return Result.Ok(True)

        except gluetool.GlueCommandError:
            self.debug('echo attempt failed, ignoring error')

        return Result.Error('echo failed')

    def _get_rc_status(self, cmd, **kwargs):
        # type: (str, **Any) -> str

        try:
            output = self.execute(cmd, **kwargs)

        except gluetool.GlueCommandError as exc:
            output = exc.output

        assert output.stdout is not None

        return output.stdout.strip()

    def _check_boot_systemctl(self, **kwargs):
        # type: (**Any) -> Result[bool, str]
        """
        Check whether boot process finished using ``systemctl``.
        """

        status = self._get_rc_status('systemctl is-system-running', **kwargs)

        if status == 'running':
            self.debug('systemctl reports ready')
            return Result.Ok(True)

        if status == 'degraded':
            output = self.execute('systemctl --plain --no-pager --failed', **kwargs)

            assert output.stdout is not None
            report = output.stdout.strip().split('\n')

            degraded_services = [line.strip() for line in report if line.startswith(' ')]
            if not degraded_services:
                self.debug('no degraded services reported')
                return Result.Ok(True)

            not_allowed = [service for service in degraded_services if not self._is_allowed_degraded(service)]

            if not not_allowed:
                self.debug('only ignored services are degraded, report ready')
                return Result.Ok(True)

            gluetool.log.log_dict(self.warn, 'degraded services reported', not_allowed)

            self._module.shared(
                'add_note',
                gluetool.help.trim_docstring(
                    """
                    Some services did not start successfully, and that may influence testing result.
                    If you believe it could represent a problem for your tests, ping us!

                    Degraded services: {}
                    """.format(', '.join([service.split()[0] for service in not_allowed]))
                ),
                level=logging.WARN
            )

            return Result.Ok(True)

        self.debug("systemctl not reporting ready: '{}'".format(status))

        return Result.Error('systemctl reporting not ready')

    def _check_boot_initctl(self, **kwargs):
        # type: (**Any) -> Result[bool, str]
        """
        Check whether boot process finished using ``initctl``.
        """

        status = self._get_rc_status('initctl status rc', **kwargs)

        if status == 'rc stop/waiting':
            self.debug('initctl reports ready')
            return Result.Ok(True)

        return Result.Error('initctl reports not ready')

    def wait_alive(self,
                   connect_timeout=None,  # type: Optional[int]
                   connect_tick=10,  # type: int
                   echo_timeout=None,  # type: Optional[int]
                   echo_tick=30,  # type: int
                   boot_timeout=None,  # type: Optional[int]
                   boot_tick=10  # type: int
                  ):  # noqa
        # type: (...) -> None

        self.debug('waiting for guest to become alive')

        # Step #1: check connectivity first - let's see whether ssh port is connectable
        self.wait('connectivity', self._check_connectivity,
                  timeout=connect_timeout, tick=connect_tick)

        # Step #2: connect to ssh and see whether shell works by printing something
        self.wait('shell available', partial(self._check_echo, connection_timeout=echo_tick),
                  timeout=echo_timeout, tick=echo_tick)

        # Step #3: check system services, there are ways to tell system boot process finished
        if self._supports_systemctl is None or self._supports_initctl is None:
            self._discover_rc_support()

        if self._supports_systemctl is True:
            check_boot = self._check_boot_systemctl

        elif self._supports_initctl is True:
            check_boot = self._check_boot_initctl

        else:
            self.warn("Don't know how to check boot process status - assume it finished and hope for the best")
            return

        check_boot = partial(check_boot, connection_timeout=boot_tick)

        self.wait('boot finished', check_boot, timeout=boot_timeout, tick=boot_tick)

    def copy_to(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, **Any) -> gluetool.utils.ProcessOutput

        self.debug("copy to the guest: '{}' => '{}'".format(src, dst))

        cmd = self._scp[:]

        if recursive:
            cmd += ['-r']

        cmd += [src, '{}@{}:{}'.format(self.username, self.hostname, dst)]

        return self._execute(cmd, **kwargs)

    def copy_from(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, **Any) -> gluetool.utils.ProcessOutput

        self.debug("copy from the guest: '{}' => '{}'".format(src, dst))

        cmd = self._scp[:]

        if recursive:
            cmd += ['-r']

        cmd += ['{}@{}:{}'.format(self.username, self.hostname, src), dst]

        return self._execute(cmd, **kwargs)
