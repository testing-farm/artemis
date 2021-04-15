# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import socket
import pytest

from mock import MagicMock, call

import gluetool
import gluetool_modules.libs.guest as guest_module

from gluetool_modules.tests import *


DEGRADED_REPORT = """
  UNIT                         LOAD   ACTIVE SUB    DESCRIPTION
  dummy.service                loaded failed failed some dummy service
  another-dummy.service        loaded failed failed some other dummy service

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

3 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
"""


@pytest.fixture(name='guest')
def fixture_guest():
    ci = NonLoadingGlue()
    mod = gluetool.Module(ci, 'dummy-module')
    guest = guest_module.NetworkedGuest(mod, '10.20.30.40', 'dummy-guest', port=13, username='ssh-user',
                                        key='/tmp/ssh.key', options=['Foo=17'])

    return guest


@pytest.fixture(name='sock')
def fixture_sock(monkeypatch):
    sock = MagicMock()
    sock.settimeout = MagicMock()

    monkeypatch.setattr(socket, 'socket', MagicMock(return_value=sock))

    return sock


@pytest.fixture(name='copy_guest')
def fixture_copy_guest(guest, monkeypatch):
    output = Bunch(exit_code=17)
    monkeypatch.setattr(guest, '_execute', MagicMock(return_value=output))

    return guest, output


def test_sanity(guest):
    assert guest.name == 'dummy-guest'
    assert guest.hostname == '10.20.30.40'
    assert guest.port == 13
    assert guest.username == 'ssh-user'
    assert guest.key == '/tmp/ssh.key'
    assert guest.options == ['Foo=17']
    # pylint: disable=protected-access
    assert guest._ssh == ['ssh', '-p', '13', '-l', 'ssh-user', '-i', '/tmp/ssh.key', '-o', 'Foo=17']
    assert guest._scp == ['scp', '-P', '13', '-i', '/tmp/ssh.key', '-o', 'Foo=17']


def test_sshize_options():
    assert guest_module.sshize_options(['Foo=11', 'Bar=baz']) == ['-o', 'Foo=11', '-o', 'Bar=baz']


def test_repr(guest):
    assert repr(guest) == 'ssh-user@10.20.30.40:13'


def test_private_execute(guest, monkeypatch):
    output = MagicMock()
    monkeypatch.setattr(gluetool.utils.Command, 'run', MagicMock(return_value=output))

    # pylint: disable=protected-access
    assert guest._execute('/usr/bin/foo', bar='baz') == output

    # pylint: disable=no-member
    gluetool.utils.Command.run.assert_called_once_with(bar='baz')


def test_execute(guest, monkeypatch):
    output = MagicMock()
    monkeypatch.setattr(guest, '_execute', MagicMock(return_value=output))

    assert guest.execute('/usr/bin/foo', bar='baz') == output

    # pylint: disable=protected-access
    guest._execute.assert_called_once_with(['ssh', '-p', '13', '-l', 'ssh-user', '-i', '/tmp/ssh.key', '-o', 'Foo=17',
                                            '10.20.30.40', '/usr/bin/foo'], bar='baz')


def test_execute_ssh_options(guest, monkeypatch):
    output = MagicMock()
    monkeypatch.setattr(guest, '_execute', MagicMock(return_value=output))

    assert guest.execute('/usr/bin/foo', ssh_options=['Bar=23'], bar='baz') == output

    # pylint: disable=protected-access
    guest._execute.assert_called_once_with(['ssh', '-p', '13', '-l', 'ssh-user', '-i', '/tmp/ssh.key', '-o', 'Foo=17',
                                            '-o', 'Bar=23', '10.20.30.40', '/usr/bin/foo'], bar='baz')


@pytest.mark.parametrize('exit_codes, expected', [
    ([0, 0], (True, False)),
    ([1, 0], (False, True)),
    ([1, 1], (False, False))
])
def test_discover_rc(guest, monkeypatch, exit_codes, expected):
    def mock_execute(*args, **kwargs):
        # pylint: disable=unused-argument
        return Bunch(exit_code=exit_codes.pop(0))

    monkeypatch.setattr(guest, 'execute', mock_execute)

    # pylint: disable=protected-access
    assert guest._supports_systemctl is None
    assert guest._supports_initctl is None

    guest._discover_rc_support()

    assert guest._supports_systemctl is expected[0]
    assert guest._supports_initctl is expected[1]


@pytest.mark.parametrize('raise_error, expected', [
    ([False, False], (True, False)),
    ([True, False], (False, True)),
    ([True, True], (False, False))
])
def test_discover_rc_error(guest, monkeypatch, raise_error, expected):
    # pylint: disable=function-redefined
    def mock_execute(*args, **kwargs):
        # pylint: disable=unused-argument
        if raise_error.pop(0) is True:
            raise gluetool.GlueCommandError(None, Bunch(exit_code=1))

        return Bunch(exit_code=0)

    monkeypatch.setattr(guest, 'execute', mock_execute)

    # pylint: disable=protected-access
    assert guest._supports_systemctl is None
    assert guest._supports_initctl is None

    guest._discover_rc_support()

    assert guest._supports_systemctl is expected[0]
    assert guest._supports_initctl is expected[1]


def test_connectivity_check(guest, sock):
    sock.connect = MagicMock()

    # pylint: disable=protected-access
    ret = guest._check_connectivity()
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_ok
    assert sock.connect.called is True


def test_connectivity_check_error(guest, sock):
    sock.connect = MagicMock(side_effect=IOError)

    # pylint: disable=protected-access
    ret = guest._check_connectivity()
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_error


@pytest.mark.parametrize('message, raises_error, ssh_options, expected', [
    ('  guest 10.20.30.40 is alive  ', False, None, True),
    ('  guest 10.20.30.40 is alive  ', False, ['Baz=17'], True),
    (' go away...  ', False, None, False),
    (' meh ', True, None, False)
])
# pylint: disable=too-many-arguments
def test_echo_check(guest, monkeypatch, message, raises_error, ssh_options, expected):
    if raises_error:
        # CICommandError needs arguments, and lambda does not allow throwing exceptions...
        def throw(*args, **kwargs):
            # pylint: disable=unused-argument

            raise gluetool.GlueCommandError(None, Bunch(exit_code=1))

        mock_execute = MagicMock(side_effect=throw)

    else:
        mock_execute = MagicMock(return_value=Bunch(stdout=message))

    monkeypatch.setattr(guest, 'execute', mock_execute)

    # pylint: disable=protected-access
    ret = guest._check_echo(ssh_options=ssh_options)
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_ok is expected
    mock_execute.assert_called_once_with("echo 'guest {} is alive'".format(guest.hostname), ssh_options=ssh_options)


def _test_copy_to(guest, output, recursive=False):
    assert guest.copy_to('/foo', '/bar', recursive=recursive, dummy=19) == output

    expected_cmd = ['scp', '-P', '13', '-i', '/tmp/ssh.key', '-o', 'Foo=17', '/foo', 'ssh-user@10.20.30.40:/bar']

    if recursive is True:
        expected_cmd.insert(7, '-r')

    # pylint: disable=protected-access
    guest._execute.assert_called_once_with(expected_cmd, dummy=19)


def test_copy_to(copy_guest):
    _test_copy_to(*copy_guest)


def test_copy_to_recursive(copy_guest):
    _test_copy_to(*copy_guest, recursive=True)


def _test_copy_from(guest, output, recursive=False):
    assert guest.copy_from('/foo', '/bar', recursive=recursive, dummy=19) == output

    expected_cmd = ['scp', '-P', '13', '-i', '/tmp/ssh.key', '-o', 'Foo=17', 'ssh-user@10.20.30.40:/foo', '/bar']

    if recursive is True:
        expected_cmd.insert(7, '-r')

    # pylint: disable=protected-access
    guest._execute.assert_called_once_with(expected_cmd, dummy=19)


def test_copy_from(copy_guest):
    _test_copy_from(*copy_guest)


def test_copy_from_recursive(copy_guest):
    _test_copy_from(*copy_guest, recursive=True)


def test_get_rc_status(guest, monkeypatch):
    output = Bunch(stdout='  rc status  ')

    monkeypatch.setattr(guest, 'execute', MagicMock(return_value=output))

    # pylint: disable=protected-access
    assert guest._get_rc_status('dummy rc query command') == 'rc status'


def test_get_rc_status_error(guest, monkeypatch):
    def throw(*args, **kwargs):
        # pylint: disable=unused-argument

        raise gluetool.GlueCommandError(None, Bunch(exit_code=1, stdout='  rc status  '))

    monkeypatch.setattr(guest, 'execute', MagicMock(side_effect=throw))

    # pylint: disable=protected-access
    assert guest._get_rc_status('dummy rc query command') == 'rc status'


def test_check_boot_initctl(guest, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='rc stop/waiting'))

    # pylint: disable=protected-access
    ret = guest._check_boot_initctl(ssh_options=['Bar=19'])
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_ok
    guest._get_rc_status.assert_called_once_with('initctl status rc', ssh_options=['Bar=19'])


def test_check_boot_initctl_not_ready(guest, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='rc still running'))

    # pylint: disable=protected-access
    ret = guest._check_boot_initctl()
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_error


def test_check_boot_systemctl(guest, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='running'))

    # pylint: disable=protected-access
    ret = guest._check_boot_systemctl(ssh_options=['Bar=19'])
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_ok
    guest._get_rc_status.assert_called_once_with('systemctl is-system-running', ssh_options=['Bar=19'])


def test_check_boot_systemctl_not_ready(guest, log, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='not running'))

    # pylint: disable=protected-access
    ret = guest._check_boot_systemctl()
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_error
    assert log.records[-1].message == "systemctl not reporting ready: 'not running'"


def test_check_boot_systemctl_degraded(guest, log, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='degraded'))
    monkeypatch.setattr(guest, 'execute', MagicMock(return_value=Bunch(stdout=DEGRADED_REPORT)))

    def _is_allowed_degraded(service):
        return service.startswith('dummy.service') or service.startswith('another-dummy.service')

    monkeypatch.setattr(guest, '_is_allowed_degraded', _is_allowed_degraded)

    # pylint: disable=protected-access
    ret = guest._check_boot_systemctl()
    assert isinstance(ret, gluetool.result.Result)
    assert ret.is_ok
    assert log.records[-1].message == 'only ignored services are degraded, report ready'


def test_check_boot_systemctl_not_ignored(guest, monkeypatch):
    monkeypatch.setattr(guest, '_get_rc_status', MagicMock(return_value='degraded'))
    monkeypatch.setattr(guest, 'execute', MagicMock(return_value=Bunch(stdout=DEGRADED_REPORT)))

    mock_add_note = MagicMock()

    patch_shared(monkeypatch, guest._module, {}, callables={
        'add_note': mock_add_note
    })

    guest._check_boot_systemctl()

    mock_add_note.assert_called_once_with(
        gluetool.help.trim_docstring(
            """
            Some services did not start successfully, and that may influence testing result.
            If you believe it could represent a problem for your tests, ping us!

            Degraded services: dummy.service, another-dummy.service
            """
        ),
        level=logging.WARN
    )


def test_wait_alive_unknown_rc_support(guest, log, monkeypatch):
    monkeypatch.setattr(guest, 'wait', MagicMock())

    # pylint: disable=protected-access
    guest._supports_systemctl = False
    guest._supports_initctl = False

    guest.wait_alive()

    # pylint: disable=line-too-long
    assert log.records[-1].message == "Don't know how to check boot process status - assume it finished and hope for the best"


def test_wait_alive_get_rc_support(guest, monkeypatch):
    monkeypatch.setattr(guest, 'wait', MagicMock())

    def _discover_rc_support(*args, **kwargs):
        # pylint: disable=unused-argument,protected-access

        guest._supports_systemctl = False
        guest._supports_initctl = False

    # pylint: disable=protected-access
    monkeypatch.setattr(guest, '_discover_rc_support', MagicMock(side_effect=_discover_rc_support))

    guest.wait_alive()

    guest._discover_rc_support.assert_called_once()


@pytest.mark.parametrize('rc_support, boot_check', [
    ((True, False), '_check_boot_systemctl'),
    ((False, True), '_check_boot_initctl')
])
def test_wait_alive_waits(guest, monkeypatch, rc_support, boot_check):
    monkeypatch.setattr(guest, 'wait', MagicMock())

    # pylint: disable=protected-access
    guest._supports_systemctl, guest._supports_initctl = rc_support

    guest.wait_alive(connect_timeout=19, connect_tick=13,
                     echo_timeout=23, echo_tick=57,
                     boot_timeout=27, boot_tick=17)

    call_args = guest.wait.call_args_list

    assert call_args[0] == call('connectivity', guest._check_connectivity, tick=13, timeout=19)

    # calls #2 and #3 use partial objects because of ssh options, therefore simple list comparison would not work
    args, kwargs = call_args[1]
    assert args[0] == 'shell available'
    assert args[1].func == guest._check_echo
    assert args[1].args == tuple()
    assert args[1].keywords == {'connection_timeout': 57}
    assert kwargs == {
        'tick': 57,
        'timeout': 23
    }

    args, kwargs = call_args[2]
    assert args[0] == 'boot finished'
    assert args[1].func == getattr(guest, boot_check)
    assert args[1].args == tuple()
    assert args[1].keywords == {'connection_timeout': 17}
    assert kwargs == {
        'tick': 17,
        'timeout': 27
    }


def test_setup_missing_support(guest, monkeypatch):
    # pylint: disable=protected-access
    monkeypatch.setattr(guest._module, 'has_shared', MagicMock(return_value=False))

    with pytest.raises(gluetool.GlueError, match=r"Module 'guest-setup' is required to actually set the guests up."):
        guest.setup()


def test_setup(guest, monkeypatch):
    # pylint: disable=protected-access
    monkeypatch.setattr(guest._module, 'has_shared', MagicMock(return_value=True))

    output = MagicMock()
    monkeypatch.setattr(guest._module, 'shared', MagicMock(return_value=output))

    assert guest.setup(foo=17) == output
    guest._module.shared.assert_called_once_with('setup_guest', guest, variables=None, foo=17)
