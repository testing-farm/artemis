import os
import tempfile

import pytest
from mock import MagicMock

import gluetool
from gluetool.tests import NonLoadingGlue, Bunch

import gluetool_modules.libs.guest as guest_module


@pytest.fixture(name='guest')
def fixture_guest():
    ci = NonLoadingGlue()
    mod = gluetool.Module(ci, 'dummy-module')
    guest = guest_module.Guest(mod, 'dummy-guest')

    return guest


def test_sanity(guest):
    assert guest.name == 'dummy-guest'


def test_logger_context(guest):
    assert guest.logger._contexts == {'guest_name': (20, 'dummy-guest')}


def test_destroy(guest):
    with pytest.raises(NotImplementedError):
        guest.destroy()


def test_setup(guest):
    with pytest.raises(NotImplementedError):
        guest.setup()


def test_create_snapshot(guest):
    with pytest.raises(NotImplementedError):
        guest.create_snapshot()


def test_restore_snapshot(guest):
    with pytest.raises(NotImplementedError):
        guest.restore_snapshot(None)


def test_supports_snapshots(guest):
    assert guest.supports_snapshots is False


def test_execute(guest):
    with pytest.raises(NotImplementedError):
        guest.execute(None)


def test_copy_to(guest):
    with pytest.raises(NotImplementedError):
        guest.copy_to(None, None)


def test_copy_from(guest):
    with pytest.raises(NotImplementedError):
        guest.copy_from(None, None)


def test_wait(guest, monkeypatch):
    mock_check = MagicMock()
    monkeypatch.setattr(gluetool.utils, 'wait', MagicMock())

    guest.wait('dummy wait', mock_check, timeout=13, tick=17)

    # pylint: disable=no-member
    gluetool.utils.wait.assert_called_once_with('dummy wait', mock_check, timeout=13, tick=17, logger=guest.logger)


def test_create_file(guest, monkeypatch):
    mock_file = Bunch(name='dummy.txt', write=MagicMock(), flush=MagicMock())

    # must implement context protocol, I cannot get it to work with Bunch :/
    class MockNamedTemporaryFile(Bunch):
        # pylint: disable=too-few-public-methods
        def __enter__(self):
            return mock_file

        def __exit__(self, *args, **kwargs):
            pass

    mock_tempfile = MockNamedTemporaryFile
    mock_copy_to = MagicMock()

    monkeypatch.setattr(tempfile, 'NamedTemporaryFile', mock_tempfile)
    monkeypatch.setattr(guest, 'copy_to', mock_copy_to)

    guest.create_file('/dst/filepath', 'some dummy content')

    # pylint: disable=no-member
    mock_file.write.assert_called_once_with('some dummy content')
    assert mock_file.flush.called
    guest.copy_to.assert_called_once_with('dummy.txt', '/dst/filepath')


def test_create_repo(guest, monkeypatch):
    monkeypatch.setattr(guest, 'create_file', MagicMock())

    expected_repo = """[dummy-repo]
name=Dummy repo
baseurl=https://foo/bar
gpgcheck=0
"""

    guest.create_repo('dummy-repo', 'Dummy repo', 'https://foo/bar', gpgcheck=0)

    guest.create_file.assert_called_once_with(os.path.join(os.sep, 'etc', 'yum.repos.d', 'dummy-repo.repo'),
                                              expected_repo)
