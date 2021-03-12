import logging
import pytest

from mock import MagicMock

import gluetool_modules.helpers.coldstore
from . import create_module, patch_shared, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.helpers.coldstore.ColdStore)[1]


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/coldstore.py', 'ColdStore')


def test_coldstore_url(module, monkeypatch):
    module._config['coldstore-url-template'] = '{{ URL }}'

    patch_shared(monkeypatch, module, {
        'eval_context': {
            'URL': 'some-url'
        }
    })

    assert module.coldstore_url == 'some-url'


def test_execute_no_coldstore_url(module, monkeypatch, log):
    monkeypatch.setattr(gluetool_modules.helpers.coldstore.ColdStore, 'coldstore_url', None)

    module.execute()

    assert log.match(message='Cold store URL seems to be empty', levelno=logging.WARN)
    assert not log.match(message='For the pipeline artifacts, see None')


def test_execute_with_coldstore_url(module, monkeypatch, log):
    monkeypatch.setattr(gluetool_modules.helpers.coldstore.ColdStore, 'coldstore_url', 'some-url')

    module.execute()

    assert not log.match(message='Cold store URL seems to be empty', levelno=logging.WARN)
    assert log.match(message='For the pipeline artifacts, see some-url')


def test_eval_context(module, monkeypatch):
    monkeypatch.setattr(gluetool_modules.helpers.coldstore.ColdStore, 'coldstore_url', 'some-url')

    assert module.eval_context == {
        'COLDSTORE_URL': 'some-url'
    }


def test_eval_context_recursion(module, monkeypatch):
    monkeypatch.setattr(gluetool_modules.libs, 'is_recursion', MagicMock(return_value=True))

    assert module.eval_context == {}
