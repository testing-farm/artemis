# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

from gluetool_modules.helpers.envinject import EnvInject
from . import create_module, check_loadable


KEY_VALUES = [['key1', 'value1'], ['key2', ''], ['key3', 'value 3']]
SERIALIZED = """key1=\"value1\"
key2=\"\"
key3=\"value 3\"
"""


@pytest.fixture(name='module')
def fixture_module():
    return create_module(EnvInject)


@pytest.fixture(name='configured_module')
def fixture_configured_module(module, tmpdir):
    ci, module = module
    filename = 'vars.props'
    outfile = tmpdir.join(filename)
    module._config['file'] = str(outfile)
    return ci, module


def test_loadable(module):
    glue, _ = module

    check_loadable(glue, 'gluetool_modules/helpers/envinject.py', 'EnvInject')


def test_shared(module):
    ci, _ = module
    assert ci.has_shared('env') is True


def test_add_variable(module):
    ci, _ = module
    env = ci.shared('env')
    key = KEY_VALUES[0][0]
    value = KEY_VALUES[0][1]
    assert key not in env
    env[key] = value
    env = ci.shared('env')
    assert key in env
    assert env[key] == value


@pytest.mark.parametrize("filepath", [None, ""])
def test_write_variable_no_file(module, log, filepath):
    _, module = module
    module._config['file'] = filepath
    module.destroy()
    assert log.match(message='Do not save exported variables for EnvInject plugin: no file provided')
    assert not log.match(message='Saving exported variables for EnvInject plugin')


def test_write_variable(configured_module):
    ci, module = configured_module
    env = ci.shared('env')
    for key, value in KEY_VALUES:
        env[key] = value
    module.destroy()
    with open(module._config['file'], 'r') as f:
        assert f.read() == SERIALIZED
