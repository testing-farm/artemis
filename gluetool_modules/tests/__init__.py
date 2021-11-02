# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os.path

import bs4

import gluetool
# pylint: disable=wildcard-import
from gluetool.tests import *  # noqa

import pytest
from mock import MagicMock


__all__ = ['Bunch', 'NonLoadingGlue', 'create_module', 'create_yaml', 'assert_shared', 'patch_shared']  # noqa


def check_loadable(glue, path, klass):
    python_mod = glue._import_pm(path, 'pytest_foo')

    assert hasattr(python_mod, klass)


def xml(text):
    return bs4.BeautifulSoup(text, 'xml').contents[0]


def testing_asset(*pieces):
    return os.path.join('gluetool_modules', 'tests', 'assets', *pieces)


def assert_shared(name, func, *args, **kwargs):
    """
    Syntax sugar for ``pytest.raises`` when testing whether called code checks for shared function.

    :param str name: name of shared function the test expect to be missing.
    :param callable func: Callable piece that should raise an exception.
    :param args: Arguments for ``func``.
    :param kwargs: Keyword arguments for ``func``.
    """

    # pylint: disable=line-too-long
    pattern = r"^Shared function '{}' is required. See `gluetool -L` to find out which module provides it.$".format(name)  # Ignore PEP8Bear

    with pytest.raises(gluetool.GlueError, match=pattern):
        func(*args, **kwargs)


def patch_shared(monkeypatch, module, return_values, callables=None):
    """
    Monkeypatch registry of shared functions. This helper is intended for simple and common use cases
    where test needs to inject its own list of functions that return values. If you need anything
    more complicated, you're on your own.

    Function accepts both values to return - for these, dummy shared function is created for a given name,
    or actual functions to execute.

    :param monkeypatch: Monkeypatch fixture, usually passed to the original test function.
    :param module: Module instance that serves as an access point to CI internals.
    :param dict(str, obj) return_values: Maping between shared function names and return values.
    :param dict(str, callable) callables: Mapping between shared function names and actual functions.
    """

    callables = callables or {}

    for name, value in return_values.iteritems():
        monkeypatch.setitem(module.glue.pipelines[-1].shared_functions, name, (None, MagicMock(return_value=value)))

    for name, value in callables.iteritems():
        monkeypatch.setitem(module.glue.pipelines[-1].shared_functions, name, (None, value))
