import pytest

from mock import MagicMock, call

import gluetool
import gluetool_modules.helpers.upload_results
from gluetool_modules.helpers import upload_results

from . import check_loadable, create_module, patch_shared


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(upload_results.UploadResults)[1]
    module._config['artifact-src-filenames'] = 'ansible.out'
    module._config['artifact-dest-file-postfix'] = '.log'
    module._config['artifact-target-dir-name'] = 'pull_request3_fs45da5'
    module._config['artifact-target-subdirs'] = 'artifacts'
    module._config['key-path'] = '/home/user/.ssh/id_rsa'
    module._config['upload-to-public'] = True
    module._config['user'] = 'user'
    module._config['domain'] = 'myGlueResults.com'
    module._config['download-domain'] = 'myGlueResults-download.com'
    module._config['target-url'] = 'artifacts/results'
    module._config['target-dir'] = 'data/artifacts/results'
    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/upload_results.py', 'UploadResults')


def test_upload_result(module, monkeypatch):
    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.helpers.upload_results, 'Command', mock_command)

    destination_path = 'dest/foo/bar'
    user_and_domain = 'user@domain'
    files = [{'src-file-path': 'src/foo/bar/ansible.log', 'dest-filename': 'foo.log'}]
    module._upload_results(destination_path, user_and_domain, files)

    mock_command.assert_called_with([
        'scp',
        '-i',
        '/home/user/.ssh/id_rsa',
        'src/foo/bar/ansible.log',
        'user@domain:dest/foo/bar/foo.log'
    ])


def test_upload_multiple_results(module, monkeypatch):
    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.helpers.upload_results, 'Command', mock_command)

    destination_path = 'dest/foo/bar'
    user_and_domain = 'user@domain'
    files = [
        {'src-file-path': 'src/foo/bar/ansible.log', 'dest-filename': 'foo.log'},
        {'src-file-path': 'src/foo2/bar2/ansible2.log', 'dest-filename': 'foo2.log'}
    ]
    module._upload_results(destination_path, user_and_domain, files)

    mock_command.assert_has_calls([
        call([
            'scp',
            '-i',
            '/home/user/.ssh/id_rsa',
            'src/foo/bar/ansible.log',
            'user@domain:dest/foo/bar/foo.log']),
        call([
            'scp',
            '-i',
            '/home/user/.ssh/id_rsa',
            'src/foo2/bar2/ansible2.log',
            'user@domain:dest/foo/bar/foo2.log'])
    ])


def test_destroy(module, monkeypatch):
    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.helpers.upload_results, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.repo = 'foo-repo'
    mock_primary_task.pull_number = 42
    mock_primary_task.commit_sha = 'a1b0c3d4'

    mock_test_entry_1 = MagicMock()
    mock_test_entry_1.work_dirpath = 'work/dir/path'
    mock_test_entry_1.playbook_filepath = 'repo/tests/test_foo.yml'
    mock_test_entry_1.result = 'PASSED'

    mock_test_entry_2 = MagicMock()
    mock_test_entry_2.work_dirpath = 'work/dir2/path2'
    mock_test_entry_2.playbook_filepath = 'repo/tests/test_bar.yml'
    mock_test_entry_2.result = 'PASSED'

    mock_test_schedule = [mock_test_entry_1, mock_test_entry_2]

    patch_shared(monkeypatch, module, {
        'primary_task': mock_primary_task,
        'test_schedule': mock_test_schedule
    })

    module.destroy()

    mock_command.assert_has_calls([
        call([
            'ssh',
            '-i',
            '/home/user/.ssh/id_rsa',
            'user@myGlueResults.com',
            'mkdir -p data/artifacts/results/pull_request3_fs45da5/artifacts'
        ]),
        call([
            'scp',
            '-i',
            '/home/user/.ssh/id_rsa',
            'work/dir/path/ansible.out',
            'user@myGlueResults.com:data/artifacts/results/pull_request3_fs45da5/artifacts/test_foo-PASSED.log']),
        call([
            'scp',
            '-i',
            '/home/user/.ssh/id_rsa',
            'work/dir2/path2/ansible.out',
            'user@myGlueResults.com:data/artifacts/results/pull_request3_fs45da5/artifacts/test_bar-PASSED.log'])
    ])

    assert module.full_target_url == 'https://myGlueResults-download.com/artifacts/results/pull_request3_fs45da5/artifacts'


def test_destroy_empty_schedule(module, monkeypatch):
    mock_runinfo = MagicMock()
    mock_runinfo.stdout = ''
    mock_runinfo.stderr = ''
    mock_command_run = MagicMock(return_value=mock_runinfo)

    mock_command = MagicMock(return_value=MagicMock(run=mock_command_run))

    monkeypatch.setattr(gluetool_modules.helpers.upload_results, 'Command', mock_command)

    mock_primary_task = MagicMock()
    mock_primary_task.repo = 'foo-repo'
    mock_primary_task.pull_number = 42
    mock_primary_task.commit_sha = 'a1b0c3d4'

    mock_test_schedule = []

    patch_shared(monkeypatch, module, {
        'primary_task': mock_primary_task,
        'test_schedule': mock_test_schedule
    })

    with pytest.raises(gluetool.GlueError, match=r"^test_schedule is empty.$"):
        module.destroy()

    mock_command.assert_not_called()
