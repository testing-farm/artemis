import logging
import re
import six

import bugzilla
import pytest

from mock import MagicMock

import gluetool
from gluetool.utils import load_yaml
from gluetool.log import format_dict
import gluetool_modules.infrastructure.bugzilla
from . import create_module, check_loadable, testing_asset


@pytest.fixture(name='bugzilla')
def fixture_bugzilla(dataset, monkeypatch):
    test_data = load_yaml(testing_asset('bugzilla', '{}.yaml'.format(dataset)))

    api_key = 'some-api-key'
    base_url = 'some-base-url'

    class BugzillaMock(MagicMock):
        bz_ver_major = '5'
        bz_ver_minor = '0'

        def __init__(self, url, **kwargs):
            assert url == '{}/xmlrpc.cgi'.format(base_url)
            assert kwargs['api_key'] == api_key

        def getbugs(self, ids, **kwargs):
            return [
                MagicMock(**test_data['getbugs'][int(bug_id)])
                for bug_id in ids
            ]

        def build_update(*args, **kwargs):
            return 'update'

        def update_bugs(*args, **kwargs):
            return True

    monkeypatch.setattr(bugzilla, 'Bugzilla', BugzillaMock)

    module = create_module(gluetool_modules.infrastructure.bugzilla.Bugzilla)[1]

    module._config['api-key'] = api_key
    module._config['base-url'] = base_url
    module._config['external-tracker-id-tcms'] = 69

    module._config['bug-id'] = ','.join(str(id) for id in test_data['getbugs'].keys())
    module._config['attributes'] = ['summary', 'priority', 'severity']

    module._config['retry-tick'] = 1
    module._config['retry-timeout'] = 1

    # expected data
    module._expected_bz_attrs = test_data['bugzilla_attributes']
    module._expected_tcms_tests = test_data['tcms_tests']

    return module


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.infrastructure.bugzilla.Bugzilla)[1]

    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/infrastructure/bugzilla.py', 'Bugzilla')


@pytest.mark.parametrize('dataset', ['valid'])
def test_list_tcms_tests(bugzilla, log):

    bugzilla._config['list-tcms-tests'] = True

    bugzilla.execute()

    for _, tests in six.iteritems(bugzilla._expected_tcms_tests):
        for test in tests:
            assert re.search(
                '"TC#{} - {}"'.format(test['id'], test['description']),
                log.records[-1].message
            )


@pytest.mark.parametrize('dataset', ['no-tests'])
def test_list_tcms_tests_no_tests(bugzilla, log):

    bugzilla._config['list-tcms-tests'] = True

    bugzilla.execute()

    if not bugzilla._expected_tcms_tests:
        assert log.match(message='No TCMS tests found for given bugzillas.', levelno=logging.DEBUG)


@pytest.mark.parametrize('dataset', ['valid'])
def test_list_attributes(bugzilla, log):

    bugzilla._config['list-attributes'] = True

    bugzilla.execute()

    print(format_dict(bugzilla._expected_bz_attrs))

    assert log.match(
        message='Bugzilla attributes:\n{}'.format(format_dict(bugzilla._expected_bz_attrs)),
        levelno=logging.INFO
    )


@pytest.mark.parametrize('dataset', ['valid'])
def test_post_comment(bugzilla, log):

    bugzilla._config['post-comment'] = 'this-is-a-comment'

    bugzilla.execute()

    assert log.match(
        message="""Given bugs updated with following comment:
---v---v---v---v---v---
this-is-a-comment
---^---^---^---^---^---""",
        levelno=logging.INFO
    )


def test_sanity(module):
    # mutual exclusive option failure
    module._config['list-attributes'] = True
    module._config['list-tcms-tests'] = True
    with pytest.raises(
        gluetool.GlueError,
        match="Options list-attributes, list-tcms-tests, post-comment are mutually exclusive"
    ):
        module.sanity()

    # required 'bug-id' failure
    module._config['list-tcms-tests'] = False
    with pytest.raises(gluetool.GlueError, match="Option 'bug-id' is required"):
        module.sanity()

    # all params fine, note we need to reinitialize bug_ids as it is done in sanity function
    del module.bug_ids
    module._config['bug-id'] = '123456'
    module.sanity()
