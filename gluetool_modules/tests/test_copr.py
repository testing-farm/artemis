# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

import gluetool
import gluetool_modules.infrastructure.copr
from gluetool_modules.infrastructure.copr import Copr, TaskArches
from . import create_module, check_loadable

BUILD_INFO = {
    '_links': {
        'build_tasks': {
            'href': '/api_2/build_tasks?build_id=802020'
        },
        'project': {
            'href': '/api_2/projects/19741'
        },
        'self': {
            'href': '/api_2/builds/802020'
        }
    },
    'build': {
        'built_packages': [
            {
                'name': 'pycho',
                'version': '0.84'
            }
        ],
        'enable_net': 'false',
        'id': 802020,
        'package_name': 'pycho',
        'package_version': '0.84-1.fc27',
        'repos': [],
        'source_metadata': {
            'pkg': 'pycho-0.84-1.fc27.src.rpm',
            'tmp': 'tmpw7y826ay',
            'url': 'https://copr.fedorainfracloud.org/tmp/tmpw7y826ay/pycho-0.84-1.fc27.src.rpm'
        },
        'source_type': 'upload',
        'state': 'succeeded',
        'submitted_on': 1537775125,
        'submitter': 'mkluson'
    }
}

BUILD_INFO_NOT_FOUND = {
    'data': {
        'build_id': 999999
    },
    'message': 'Build with id `999999` not found'
}

PROJECT_INFO = {
    '_links': {
        'build_tasks': {
            'href': '/api_2/build_tasks?project_id=19741'
        },
        'builds': {
            'href': '/api_2/builds?project_id=19741'
        },
        'chroots': {
            'href': '/api_2/projects/19741/chroots'
        },
        'self': {
            'href': '/api_2/projects/19741'
        }
    },
    'project': {
        'build_enable_net': 'false',
        'contact': '',
        'description': 'Package for testing purposes',
        'disable_createrepo': 'false',
        'id': 19741,
        'instructions': '',
        'is_a_group_project': 'false',
        'name': 'pycho',
        'owner': 'mkluson',
        'repos': []
    }
}

BUILD_TASK_INFO = {
    '_links': {
        'build': {
            'href': '/api_2/builds/802020'
        },
        'project': {
            'href': '/api_2/projects/19741'
        },
        'self': {
            'href': '/api_2/build_tasks/802020/fedora-28-x86_64'
        }
    },
    'build_task': {
        'build_id': 802020,
        'chroot_name': 'fedora-28-x86_64',
        'ended_on': 1537775303,
        'git_hash': '01cbdd2f3d4156b9c05a216111b41075b5fd398d',
        'result_dir_url':
            'https://copr-be.cloud.fedoraproject.org/results/mkluson/pycho/fedora-28-x86_64/00802020-pycho/',
        'started_on': 1537775126,
        'state': 'succeeded'
    }
}

BUILD_TASK_INFO_NOT_FOUND = {
    'message': 'Build task {} for build {} not found'
}

BUILDER_LIVE_LOG = '''
...
Checking for unpackaged file(s): /usr/lib/rpm/check-files /builddir/build/BUILDROOT/pycho-0.84-1.fc28.x86_64
Wrote: /builddir/build/RPMS/pycho-0.84-1.fc28.x86_64.rpm
Executing(%clean): /bin/sh -e /var/tmp/rpm-tmp.esjg1H
+ umask 022
+ cd /builddir/build/BUILD
+ /usr/bin/rm -rf /builddir/build/BUILDROOT/pycho-0.84-1.fc28.x86_64
+ exit 0
Finish: rpmbuild pycho-0.84-1.fc28.src.rpm
INFO: chroot_scan: 3 files copied to /var/lib/copr-rpmbuild/results/chroot_scan
INFO: /var/lib/mock/802020-fedora-28-x86_64-1537775442.571937/root/var/log/dnf.log
/var/lib/mock/802020-fedora-28-x86_64-1537775442.571937/root/var/log/dnf.librepo.log
/var/lib/mock/802020-fedora-28-x86_64-1537775442.571937/root/var/log/dnf.rpm.log
Finish: build phase for pycho-0.84-1.fc28.src.rpm
INFO: Done(/var/lib/copr-rpmbuild/results/pycho-0.84-1.fc28.src.rpm) Config(child) 0 minutes 47 seconds
INFO: Results and/or logs in: /var/lib/copr-rpmbuild/results
INFO: Cleaning up build root ('cleanup_on_success=True')
Start: clean chroot
INFO: unmounting tmpfs.
Finish: clean chroot
Finish: run
'''


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(Copr)[1]

    module._config['copr-web-url-template'] = 'dummy-web-url-{{ TASK.id }}'

    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/infrastructure/copr.py', 'Copr')


def test_execute(module, monkeypatch):
    module._config['task-id'] = '802020:fedora-28-x86_64'

    class dummy_request(object):

        def __init__(self, source):
            self.source = source
            self.content = str(self.source)
            self.status_code = 200

        def json(self):
            return self.source

    def mocked_get(url):
        if 'api_2/build_tasks' in url:
            source = BUILD_TASK_INFO
        elif 'api_2/builds' in url:
            source = BUILD_INFO
        elif 'api_2/projects' in url:
            source = PROJECT_INFO
        elif 'builder-live.log' in url:
            source = BUILDER_LIVE_LOG

        return dummy_request(source)

    monkeypatch.setattr(gluetool_modules.infrastructure.copr.requests, 'get', mocked_get)

    assert module.eval_context == {}

    module.execute()

    eval_context = module.eval_context
    primary_task = module.primary_task()

    assert eval_context['ARTIFACT_TYPE'] == 'copr-build'
    assert eval_context['BUILD_TARGET'] == primary_task.target
    assert eval_context['NVR'] == primary_task.nvr
    assert eval_context['PRIMARY_TASK'] == primary_task
    assert eval_context['TASKS'] == module.tasks()

    assert primary_task.id == '802020:fedora-28-x86_64'
    assert primary_task.dispatch_id == '802020:fedora-28-x86_64'
    assert primary_task.status == 'succeeded'
    assert primary_task.component == 'pycho'
    assert primary_task.target == 'fedora-28-x86_64'
    assert primary_task.nvr == 'pycho-0.84-1.fc27'
    assert primary_task.owner == 'mkluson'
    assert primary_task.project == 'pycho'
    assert primary_task.issuer == 'mkluson'
    assert primary_task.component_id == 'mkluson/pycho/pycho'

    assert primary_task.rpm_names == ['pycho-0.84-1.fc28.x86_64']
    assert primary_task.rpm_urls == [
        'https://copr-be.cloud.fedoraproject.org/results/mkluson/pycho/fedora-28-x86_64/00802020-pycho/pycho-0.84-1.fc28.x86_64.rpm']

    assert primary_task.task_arches == TaskArches(['x86_64'])
    assert primary_task.full_name == "package 'pycho' build '802020' target 'fedora-28-x86_64'"

    assert primary_task.url == 'dummy-web-url-802020:fedora-28-x86_64'


def test_not_found(module, monkeypatch):
    module._config['task-id'] = '999999:fedora-28-x86_64'

    class dummy_request(object):

        def __init__(self, source):
            self.source = source
            self.text = str(self.source)
            self.status_code = 200

        def json(self):
            return self.source

    def mocked_get(url):
        if 'api_2/build_tasks' in url:
            source = BUILD_TASK_INFO_NOT_FOUND
        elif 'api_2/builds' in url:
            source = BUILD_INFO_NOT_FOUND

        return dummy_request(source)

    monkeypatch.setattr(gluetool_modules.infrastructure.copr.requests, 'get', mocked_get)

    module.execute()

    primary_task = module.primary_task()

    assert primary_task.status == 'UNKNOWN-COPR-STATUS'
    assert primary_task.component == 'UNKNOWN-COPR-COMPONENT'
    assert primary_task.target == 'fedora-28-x86_64'
    assert primary_task.nvr == 'UNKNOWN-COPR-COMPONENT-UNKNOWN-COPR-VERSION'
    assert primary_task.owner == 'UNKNOWN-COPR-OWNER'
    assert primary_task.project == 'UNKNOWN-COPR-PROJECT'
    assert primary_task.issuer == 'UNKNOWN-COPR-ISSUER'
    assert primary_task.component_id == 'UNKNOWN-COPR-OWNER/UNKNOWN-COPR-PROJECT/UNKNOWN-COPR-COMPONENT'

    assert primary_task.rpm_names == []
    assert primary_task.rpm_urls == []

    assert primary_task.task_arches == TaskArches(['x86_64'])

    assert primary_task.url == 'dummy-web-url-999999:fedora-28-x86_64'


def test_unreachable_copr(module, monkeypatch):
    module._config['task-id'] = '999999:fedora-28-x86_64'

    def mocked_get(url):
        raise Exception

    monkeypatch.setattr(gluetool_modules.infrastructure.copr.requests, 'get', mocked_get)

    with pytest.raises(gluetool.GlueError, match=r"^Unable to get:"):
        module.execute()


def test_tasks(module, monkeypatch):
    class dummy_request(object):

        def __init__(self, source):
            self.source = source
            self.text = str(self.source)
            self.status_code = 200

        def json(self):
            return self.source

    def mocked_get(url):
        if 'api_2/build_tasks' in url:
            source = BUILD_TASK_INFO
        elif 'api_2/builds' in url:
            source = BUILD_INFO
        elif 'api_2/projects' in url:
            source = PROJECT_INFO
        elif 'builder-live.log' in url:
            source = BUILDER_LIVE_LOG

        return dummy_request(source)

    monkeypatch.setattr(gluetool_modules.infrastructure.copr.requests, 'get', mocked_get)

    task_ids = ['802020:fedora-28-x86_64', '802020:fedora-29-x86_64']
    tasks = module.tasks(task_ids=task_ids)

    assert len(tasks) == len(task_ids)
