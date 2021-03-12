import logging
import pytest
import requests
import simplejson

from mock import MagicMock

import gluetool
from gluetool_modules.infrastructure import pes
from . import check_loadable, create_module, patch_shared, testing_asset


@pytest.fixture(name='module')
def fixture_module():

    module = create_module(pes.PES)[1]

    module._config['api-url'] = 'https://pes-api-url'
    module._config['retry-tick'] = 1
    module._config['retry-timeout'] = 1
    module._config['map-primary-task'] = True

    return module


def prepare_test(module, monkeypatch, name, side_effect=None, side_effect_json=None):

    test = gluetool.utils.load_yaml(testing_asset('pes', 'test-{}.yaml'.format(name)))

    mocked_response = MagicMock(content='')

    if side_effect_json:
        mocked_response.json = MagicMock(side_effect=side_effect_json)
    else:
        mocked_response.json = MagicMock(return_value=gluetool.utils.load_json(testing_asset('pes', test['response'])))

    mocked_response.status_code = test['status_code']

    if side_effect:
        monkeypatch.setattr(requests, 'post', MagicMock(side_effect=side_effect))
    else:
        monkeypatch.setattr(requests, 'post', MagicMock(return_value=mocked_response))

    return (test, module)


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/infrastructure/pes.py', 'PES')


@pytest.mark.parametrize('test', [
    'no-events',
    'multiple-events'
])
def test_ancestors(module, monkeypatch, test, log):

    (test, module) = prepare_test(module, monkeypatch, test)

    primary_task = MagicMock()
    primary_task.component = test['package']

    patch_shared(monkeypatch, module, {
        'primary_task': primary_task
    })

    module.execute()

    assert log.match(
        message="Ancestors of '{}': {}".format(test['package'], ', '.join(test['ancestors'])),
        levelno=logging.INFO
    )


def test_invalid_response(module, monkeypatch):

    (_, module) = prepare_test(module, monkeypatch, 'invalid-response')

    with pytest.raises(gluetool.GlueError, match=r'post.*returned 500'):
        module.ancestors('dummy')


def test_invalid_json(module, monkeypatch):

    exception = simplejson.errors.JSONDecodeError('', '', 0)

    (_, module) = prepare_test(module, monkeypatch, 'invalid-json', side_effect_json=exception)

    with pytest.raises(gluetool.GlueError, match=r'Pes returned unexpected non-json output, needs investigation'):
        module.ancestors('dummy')


def test_connection_error(module, monkeypatch):

    exception = requests.exceptions.ConnectionError('connection-error')
    (_, module) = prepare_test(module, monkeypatch, 'invalid-response', side_effect=exception)

    with pytest.raises(gluetool.GlueError, match=r"Condition 'getting post response from https://pes-api-url/srpm-events/' failed to pass within given time"):
        module.pes_api().get_ancestors('dummy')


def test_no_build_available(module, monkeypatch):

    patch_shared(monkeypatch, module, {
        'primary_task': None
    })

    with pytest.raises(gluetool.GlueError, match='No build available, cannot continue'):
        module.execute()
