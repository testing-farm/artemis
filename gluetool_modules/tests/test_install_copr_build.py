import pytest
import gluetool
import os
import shutil
from mock import MagicMock
from mock import call
import gluetool_modules.libs.sut_installation
from gluetool_modules.helpers.install_copr_build import InstallCoprBuild
from gluetool_modules.libs.sut_installation import SUTInstallationFailedError
from gluetool_modules.libs.guest_setup import GuestSetupStage
from . import create_module, patch_shared, check_loadable

LOG_DIR_NAME = 'artifact-installation'


def mock_guest(execute_mock):
    guest_mock = MagicMock()
    guest_mock.name = 'guest0'
    guest_mock.execute = execute_mock

    return guest_mock


def assert_log_files(guest, log_dirpath, file_names=None):
    if not file_names:
        file_names = [
            '0-Download-copr-repository.txt',
            '1-Reinstall-packages.txt',
            '2-Downgrade-packages.txt',
            '3-Update-packages.txt',
            '4-Install-packages.txt',
            '5-Verify-packages-installed.txt'
        ]

    installation_log_dir = os.path.join(
        log_dirpath,
        '{}-{}'.format(LOG_DIR_NAME, guest.name)
    )

    os.path.isdir(installation_log_dir)

    for file_name in file_names:
        filepath = os.path.join(installation_log_dir, file_name)
        if not os.path.isfile(filepath):
            assert False, 'File {} should exist'.format(filepath)


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(InstallCoprBuild)[1]

    module._config['log-dir-name'] = LOG_DIR_NAME

    return module


@pytest.fixture(name='module_shared_patched')
def fixture_module_shared_patched(module, monkeypatch):
    primary_task_mock = MagicMock()
    primary_task_mock.repo_url = 'dummy_repo_url'
    primary_task_mock.rpm_urls = ['dummy_rpm_url1', 'dummy_rpm_url2']
    primary_task_mock.rpm_names = ['dummy_rpm_names1', 'dummy_rpm_names2']

    patch_shared(monkeypatch, module, {
        'primary_task': primary_task_mock,
        'setup_guest': None
    })

    return module, primary_task_mock


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/install_copr_build.py', 'InstallCoprBuild')


def test_setup_guest(module_shared_patched, tmpdir):
    module, primary_task_mock = module_shared_patched

    execute_mock = MagicMock(return_value=MagicMock(stdout='', stderr=''))
    guest = mock_guest(execute_mock)

    module.setup_guest(guest, stage=GuestSetupStage.ARTIFACT_INSTALLATION, log_dirpath=str(tmpdir))

    calls = [
        call('curl -v dummy_repo_url --output /etc/yum.repos.d/copr_build.repo'),
        call('yum -y reinstall dummy_rpm_url1'),
        call('yum -y reinstall dummy_rpm_url2'),
        call('yum -y downgrade dummy_rpm_url1 dummy_rpm_url2'),
        call('yum -y update dummy_rpm_url1 dummy_rpm_url2'),
        call('yum -y install dummy_rpm_url1 dummy_rpm_url2')
    ]

    execute_mock.assert_has_calls(calls, any_order=True)
    assert_log_files(guest, str(tmpdir))


def test_no_yum(module_shared_patched, tmpdir):
    module, primary_task_mock = module_shared_patched

    def execute_mock_side_effect(cmd):
        if cmd == 'command -v yum':
            raise gluetool.glue.GlueCommandError('dummy_error', MagicMock(exit_code=1, stdout='', stderr=''))
        return MagicMock(stdout='', stderr='')

    execute_mock = MagicMock()
    execute_mock.side_effect = execute_mock_side_effect

    guest = mock_guest(execute_mock)
    module.setup_guest(guest, stage=GuestSetupStage.ARTIFACT_INSTALLATION, log_dirpath=str(tmpdir))

    calls = [
        call('curl -v dummy_repo_url --output /etc/yum.repos.d/copr_build.repo'),
        call('dnf -y reinstall dummy_rpm_url1'),
        call('dnf -y reinstall dummy_rpm_url2'),
        call('dnf -y downgrade dummy_rpm_url1 dummy_rpm_url2'),
        call('dnf -y update dummy_rpm_url1 dummy_rpm_url2'),
        call('dnf -y install dummy_rpm_url1 dummy_rpm_url2')
    ]

    execute_mock.assert_has_calls(calls, any_order=True)
    assert_log_files(guest, str(tmpdir))


def test_nvr_check_fails(module_shared_patched, tmpdir):
    module, primary_task_mock = module_shared_patched

    def execute_mock(cmd):
        if cmd.startswith('rpm -q') or cmd.startswith('yum -y downgrade'):
            raise gluetool.glue.GlueCommandError('dummy_error', MagicMock(exit_code=1, stdout='', stderr=''))
        return MagicMock(stdout='', stderr='')

    guest = mock_guest(execute_mock)

    ret = module.setup_guest(guest, stage=GuestSetupStage.ARTIFACT_INSTALLATION, log_dirpath=str(tmpdir))

    assert ret.is_error

    outputs, exc = ret.value

    assert len(outputs) == 1
    assert outputs[0].stage == GuestSetupStage.ARTIFACT_INSTALLATION
    assert outputs[0].label == 'Copr build installation'
    assert outputs[0].log_path == '{}/artifact-installation-guest0'.format(str(tmpdir))
    assert isinstance(outputs[0].additional_data, gluetool_modules.libs.sut_installation.SUTInstallation)

    assert isinstance(exc, SUTInstallationFailedError)
    assert exc.message == 'Test environment installation failed: reason unknown, please escalate'

    assert_log_files(guest, str(tmpdir))


def test_repo_download_fails(module_shared_patched, tmpdir):
    module, primary_task_mock = module_shared_patched

    def execute_mock(cmd):
        if cmd.startswith('curl'):
            raise gluetool.glue.GlueCommandError('dummy_error', MagicMock(exit_code=1, stdout='', stderr=''))
        return MagicMock(stdout='', stderr='')

    guest = mock_guest(execute_mock)

    ret = module.setup_guest(guest, stage=GuestSetupStage.ARTIFACT_INSTALLATION, log_dirpath=str(tmpdir))

    assert ret.is_error

    outputs, exc = ret.value

    assert len(outputs) == 1
    assert outputs[0].stage == GuestSetupStage.ARTIFACT_INSTALLATION
    assert outputs[0].label == 'Copr build installation'
    assert outputs[0].log_path == '{}/artifact-installation-guest0'.format(str(tmpdir))
    assert isinstance(outputs[0].additional_data, gluetool_modules.libs.sut_installation.SUTInstallation)

    assert isinstance(exc, SUTInstallationFailedError)
    assert exc.message == 'Test environment installation failed: reason unknown, please escalate'

    assert_log_files(guest, str(tmpdir), file_names=['0-Download-copr-repository.txt'])
