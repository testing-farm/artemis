# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest
import os
from mock import MagicMock
from gluetool_modules.helpers.testing_thread import TestingThread
from . import create_module, check_loadable, patch_shared


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(TestingThread)[1]
    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/testing_thread.py', 'TestingThread')


def test_sanity_no_option(module):
    module.sanity()

    assert module.thread_id() is None


def test_sanity_option(module):
    thread_id = '123'
    module._config['id'] = thread_id
    module.sanity()

    assert module.thread_id() == thread_id


def test_execute_id(module):
    thread_id = '123'
    module._thread_id = thread_id
    module.execute()

    assert module.thread_id() == thread_id


def test_execute_no_id(module, monkeypatch):
    patch_shared(monkeypatch, module, {
        'eval_context': {
            'SOME_VARIABLE': 'dummy_value'
        }
    })

    module._config['id-template'] = '{{ SOME_VARIABLE }}'
    module.execute()

    assert module.thread_id() == '4d412756673b7d9879736e277b44f31dd1d72b58'


def test_execute_length_no_id(module, monkeypatch):
    patch_shared(monkeypatch, module, {
        'eval_context': {
            'SOME_VARIABLE': 'dummy_value'
        }
    })

    module._config['id-template'] = '{{ SOME_VARIABLE }}'
    module._config['id-length'] = 4
    module.execute()

    assert module.thread_id() == '4d41'


def test_eval_context(module):
    thread_id = '123'
    module._thread_id = thread_id

    assert module.eval_context['THREAD_ID'] == thread_id


def test_destroy_no_option(module):
    module.destroy()

    assert module.thread_id() is None


def test_destroy_id_file(module):
    thread_id = '123'
    file_name = 'some_name'
    module._thread_id = thread_id
    module._config['id-file'] = file_name
    module.destroy()

    assert os.path.isfile(file_name)

    with open(file_name) as id_file:
        assert id_file.read().replace('"', '') == thread_id

    os.unlink(file_name)


def test_destroy_results(module, monkeypatch):
    thread_id = '123'
    other_id = '456'
    module._thread_id = thread_id
    result1 = MagicMock()
    result2 = MagicMock()
    result1.ids = {
        'other-id': other_id
    }
    result2.ids = {
        'testing-thread-id': thread_id,
        'other-id': other_id
    }

    patch_shared(monkeypatch, module, {
        'results': [result1, result2]
    })

    module.destroy()

    assert result1.ids == {
        'testing-thread-id': thread_id,
        'other-id': other_id
    }
    assert result2.ids == {
        'testing-thread-id': thread_id,
        'other-id': other_id
    }
