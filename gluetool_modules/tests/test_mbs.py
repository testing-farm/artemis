# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest
from mock import MagicMock

import gluetool
import gluetool_modules.infrastructure.mbs
from gluetool_modules.infrastructure.mbs import MBS, TaskArches, nsvc_from_nvr
from . import create_module, patch_shared, check_loadable, testing_asset
from gluetool.utils import load_yaml

BUILD_TARGET = 'el8'

MBS_ABOUT = {
    'api_version': '1.0',
    'auth_method': 'dummy',
    'version': '0.1'
}


@pytest.fixture(name='root_action')
def fixture_root_action():
    root = gluetool.action.Action('dummy root action')

    gluetool.action.Action.set_thread_root(root)

    return root


@pytest.fixture(name='module')
def fixture_module(root_action):
    return create_module(MBS)[1]


@pytest.fixture(name='tags')
def fixture_tags(monkeypatch, module):
    class KojiSession(object):
        def listTags(self, tag):
            return [
                {'name': 'tag1'},
                {'name': 'tag2'}
            ]

    patch_shared(monkeypatch, module, {
        'koji_session': KojiSession()
    })


@pytest.fixture(name='mbs_module_info')
def fixture_mbs_module_info():
    return load_yaml(testing_asset('mbs', 'module_info_non_scratch.yml'))


@pytest.fixture(name='get')
def fixture_get(mbs_module_info, monkeypatch):
    def dummy_request(location):

        response = MagicMock()
        response.json.return_value = mbs_module_info

        # about API response
        if location == 'None/module-build-service/1/about':
            response.json.return_value = MBS_ABOUT

        # NSVC search
        elif location.startswith('None/module-build-service/1/module-builds/?context=b09eea91'):
            response.json.return_value = {'items': [mbs_module_info]}

        # NSVC search - not found
        elif location.startswith('None/module-build-service/1/module-builds/?context=invalid'):
            response.json.return_value = {'items': []}

        # NSVC search - no modulemd
        elif location.startswith('None/module-build-service/1/module-builds/?context=no-modulemd'):
            del mbs_module_info['modulemd']
            response.json.return_value = {'items': [mbs_module_info]}

        # NSVC search - no scm url
        elif location.startswith('None/module-build-service/1/module-builds/?context=no-scm-url'):
            mbs_module_info['scmurl'] = 'nourl'
            response.json.return_value = {'items': [mbs_module_info]}

        # NSVC search - scm url is None
        elif location.startswith('None/module-build-service/1/module-builds/?context=empty-scm-url'):
            mbs_module_info['scmurl'] = None
            response.json.return_value = {'items': [mbs_module_info]}

        return response

    monkeypatch.setattr(gluetool_modules.infrastructure.mbs.requests, 'get', dummy_request)


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/infrastructure/mbs.py', 'MBS')


def test_invalid_nvr(module, get, tags):
    module._config['nvr'] = ['virt-rhel-8-20190107132853:9edba152']
    with pytest.raises(gluetool.GlueError, match="'virt-rhel-8-20190107132853:9edba152' is not a valid module nvr"):
        module.execute()


def test_invalid_nsvc(module, get, tags):
    module._config['nsvc'] = ['virt-rhel-8-20190107132853:9edba152']
    with pytest.raises(gluetool.GlueError, match="'virt-rhel-8-20190107132853:9edba152' is not a valid module nsvc"):
        module.execute()


def test_invalid_url(module, monkeypatch):
    monkeypatch.setattr(gluetool_modules.infrastructure.mbs.requests, 'get', MagicMock(side_effect=Exception('fake')))

    with pytest.raises(gluetool.GlueError, match='Unable to get: None/module-build-service/1/about'):
        module.execute()


def test_nsvc_not_found(module, get, tags):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:invalid']

    with pytest.raises(gluetool.GlueError, match="Could not find module with nsvc 'rust-toolset:rhel8:820181105234334:invalid'"):  # Ignore PEP8Bear
        module.execute()


def test_execute(module, tags, get):
    module._config['build-id'] = ['2178', '2178']
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']
    module._config['nvr'] = ['rust-toolset-rhel8-820181105234334.b09eea91']

    assert module.eval_context == {}

    module.execute()

    eval_context = module.eval_context
    primary_task = module.primary_task()

    assert eval_context['ARTIFACT_TYPE'] == 'redhat-module'
    assert eval_context['BUILD_TARGET'] == BUILD_TARGET
    assert eval_context['PRIMARY_TASK'] == primary_task
    assert eval_context['TAGS'] == primary_task.tags
    assert eval_context['TASKS'] == module.tasks()

    assert primary_task.id == 2178
    assert primary_task.dispatch_id == 2178
    assert primary_task.name == 'rust-toolset'
    assert primary_task.component == 'rust-toolset'
    assert primary_task.stream == 'rhel8'
    assert primary_task.version == '820181105234334'
    assert primary_task.context == 'b09eea91'
    assert primary_task.issuer == 'jistone'
    assert primary_task.nsvc == 'rust-toolset:rhel8:820181105234334:b09eea91'
    assert primary_task.nvr == 'rust-toolset-rhel8-820181105234334.b09eea91'
    assert primary_task.devel_nvr == 'rust-toolset-devel-rhel8-820181105234334.b09eea91'
    assert primary_task.component_id == 'rust-toolset:rhel8'
    assert primary_task.has_artifacts is True
    assert primary_task.platform_stream == 'el8'
    assert primary_task.distgit_ref == '7981ffe74ef8badda5dfcc5407fb2d9a84af0d62'

    assert primary_task.tags == ['tag1', 'tag2']
    assert primary_task.task_arches == TaskArches(['aarch64', 'i686', 'ppc64le', 's390x', 'x86_64'])

    # hmm, seems it is better to sort this, happend the items were in different order when run via gitlab CI
    assert sorted(primary_task.dependencies) == ['llvm-toolset:rhel8', 'platform:el8']


def test_scratch_build(module, get, tags, mbs_module_info):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']

    mbs_module_info['scratch'] = True

    module.execute()

    assert module.primary_task().nvr == 'rust-toolset-rhel8-820181105234334.b09eea91+2178'


def test_shared(module, get, tags):
    module.tasks(build_ids=['2178'])

    assert module.primary_task().name == 'rust-toolset'


def test_mbs_task_invalid_init(module):
    with pytest.raises(gluetool.GlueError, match='module must be initialized only from one of build_id, nsvc or nvr'):
        gluetool_modules.infrastructure.mbs.MBSTask(module, build_id=2178, nvr='nvr')


@pytest.mark.parametrize("nvr,nsvc", [
    ('perl-bootstrap-5.24-2711.cdc', ('perl-bootstrap', '5.24', '2711', 'cdc')),
    ('perl-bootstrap-5_24-2711.cdc', ('perl-bootstrap', '5-24', '2711', 'cdc'))
])
def test_nsvc_from_nvr(nvr, nsvc):
    assert nsvc_from_nvr(nvr) == nsvc


def test_no_dependencies(module, monkeypatch, get, tags, mbs_module_info):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']

    # remove dependencies from modulemd
    mbs_module_info['modulemd'] = "---\ndocument: modulemd\nversion: 2\ndata:\n  name: rust-toolset\n  stream: rhel8\n  version: 820181105234334\n  context: b09eea91\n  summary: Rust\n  description: >-\n    Rust Toolset\n  license:\n    module:\n    - MIT\n  xmd:\n    mbs:\n      scmurl: git://pkgs.devel.redhat.com/modules/rust-toolset?#7981ffe74ef8badda5dfcc5407fb2d9a84af0d62\n      buildrequires:\n        platform:\n          stream: el8\n          filtered_rpms: []\n          version: 2\n          koji_tag: module-rhel-8.0.0-build\n          context: 00000000\n          ref: virtual\n        llvm-toolset:\n          stream: rhel8\n          filtered_rpms: []\n          version: 820181030213659\n          koji_tag: module-llvm-toolset-rhel8-820181030213659-9edba152\n          context: 9edba152\n          ref: 32f47423126c0c2cc8b3cb0d3711da2b6999c9aa\n        rust-toolset:\n          stream: rhel8\n          filtered_rpms: []\n          version: 820181105191008\n          koji_tag: module-rust-toolset-rhel8-820181105191008-b09eea91\n          context: b09eea91\n          ref: 14bbba9cd56090bb4cb350cebaeebd6804abdd6d\n      mse: TRUE\n      rpms:\n        cargo-vendor:\n          ref: bac28fbd3452f187aa2c154e604898c0cef32437\n        rust:\n          ref: 13df2ea8a6f55619da6c030e4452f0170fcd3530\n        rust-toolset:\n          ref: fc700a92b0484d05ccb70e7f0de0bc4891c48efd\n      commit: 7981ffe74ef8badda5dfcc5407fb2d9a84af0d62\n  dependencies:\n  - buildrequires:\n      llvm-toolset: [rhel8]\n      platform: [el8]\n      rust-toolset: [rhel8]\n  profiles:\n    default:\n      rpms:\n      - rust-toolset\n  api:\n    rpms:\n    - cargo\n    - cargo-doc\n    - cargo-vendor\n    - rls-preview\n    - rust\n    - rust-analysis\n    - rust-doc\n    - rust-gdb\n    - rust-lldb\n    - rust-src\n    - rust-std-static\n    - rustfmt-preview\n  components:\n    rpms:\n      cargo-vendor:\n        rationale: Tool for bundling Rust dependencies\n        repository: git://pkgs.devel.redhat.com/rpms/cargo-vendor\n        cache: http://pkgs.devel.redhat.com/repo/pkgs/cargo-vendor\n        ref: stream-rhel-8\n        buildorder: 1\n        arches: [aarch64, i686, ppc64le, s390x, x86_64]\n      rust:\n        rationale: Rust compiler and tools\n        repository: git://pkgs.devel.redhat.com/rpms/rust\n        cache: http://pkgs.devel.redhat.com/repo/pkgs/rust\n        ref: stream-rhel-8\n        arches: [aarch64, i686, ppc64le, s390x, x86_64]\n      rust-toolset:\n        rationale: Meta package for rust-toolset.\n        repository: git://pkgs.devel.redhat.com/rpms/rust-toolset\n        cache: http://pkgs.devel.redhat.com/repo/pkgs/rust-toolset\n        ref: stream-rhel-8\n        arches: [aarch64, i686, ppc64le, s390x, x86_64]\n...\n"  # Ignore PEP8Bear

    module.execute()

    with pytest.raises(gluetool.GlueError, match="Could not detect module dependecies: 'requires'"):
        assert module.primary_task().dependencies is None


def test_empty_module(module, monkeypatch, get, tags, mbs_module_info):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']
    module._config['default-task-arches'] = ['arch1, arch2', 'arch3']

    # remove dependencies from modulemd
    mbs_module_info['modulemd'] = "---\ndocument: modulemd\nversion: 2\ndata:\n  name: rust-toolset\n  stream: rhel8\n  version: 820181105234334\n  context: b09eea91\n  summary: Rust\n  description: >-\n    Rust Toolset\n  license:\n    module:\n    - MIT\n  xmd:\n    mbs:\n      scmurl: git://pkgs.devel.redhat.com/modules/rust-toolset?#7981ffe74ef8badda5dfcc5407fb2d9a84af0d62\n      buildrequires:\n        platform:\n          stream: el8\n          filtered_rpms: []\n          version: 2\n          koji_tag: module-rhel-8.0.0-build\n          context: 00000000\n          ref: virtual\n        llvm-toolset:\n          stream: rhel8\n          filtered_rpms: []\n          version: 820181030213659\n          koji_tag: module-llvm-toolset-rhel8-820181030213659-9edba152\n          context: 9edba152\n          ref: 32f47423126c0c2cc8b3cb0d3711da2b6999c9aa\n        rust-toolset:\n          stream: rhel8\n          filtered_rpms: []\n          version: 820181105191008\n          koji_tag: module-rust-toolset-rhel8-820181105191008-b09eea91\n          context: b09eea91\n          ref: 14bbba9cd56090bb4cb350cebaeebd6804abdd6d\n      mse: TRUE\n      rpms:\n        cargo-vendor:\n          ref: bac28fbd3452f187aa2c154e604898c0cef32437\n        rust:\n          ref: 13df2ea8a6f55619da6c030e4452f0170fcd3530\n        rust-toolset:\n          ref: fc700a92b0484d05ccb70e7f0de0bc4891c48efd\n      commit: 7981ffe74ef8badda5dfcc5407fb2d9a84af0d62\n  dependencies:\n  - buildrequires:\n      llvm-toolset: [rhel8]\n      platform: [el8]\n      rust-toolset: [rhel8]\n  profiles:\n    default:\n      rpms:\n      - rust-toolset\n  api:\n    rpms:\n    - cargo\n    - cargo-doc\n    - cargo-vendor\n    - rls-preview\n    - rust\n    - rust-analysis\n    - rust-doc\n    - rust-gdb\n    - rust-lldb\n    - rust-src\n    - rust-std-static\n    - rustfmt-preview"  # Ignore PEP8Bear

    module.execute()

    assert module.primary_task().task_arches.arches == ['arch1', 'arch2', 'arch3']


@pytest.mark.parametrize("context", ['no-scm-url', 'empty-scm-url'])
def test_no_scm_url(module, get, tags, context):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:{}'.format(context)]

    module.execute()

    assert module.primary_task().distgit_ref is None


def test_no_platform_stream(module, get, tags, mbs_module_info):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']

    # make moduleinfo empty
    mbs_module_info['modulemd'] = ''

    with pytest.raises(gluetool.GlueError, match="Could not detect platform stream in modulemd document"):
        module.execute()


# NOTE: MUST BE RUN AS LAST, AS IT REMOVES A KEY FROM MBS_INFO
def test_nsvc_no_modulemd(module, get, tags):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:no-modulemd']

    with pytest.raises(gluetool.GlueError, match="Artifact build info does not include modulemd document"):
        module.execute()


def test_no_tags_in_scratch_module(module, get, tags, mbs_module_info):
    module._config['nsvc'] = ['rust-toolset:rhel8:820181105234334:b09eea91']

    mbs_module_info['scratch'] = True

    module.execute()

    assert module.primary_task().tags == []
