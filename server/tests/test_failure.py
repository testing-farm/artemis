# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional

import pytest

from tft.artemis import Failure


@pytest.fixture(name='failure')
def fixture_failure() -> Failure:
    failure: Optional[Failure] = None

    # Create a nice traceback for our failure...
    def _a() -> None:
        raise ValueError

    def _b() -> None:
        _a()

    def _c() -> None:
        _b()

    try:
        _c()

    except Exception as exc:
        failure = Failure.from_exc('dummy failure', exc, a_dummy_detail='bar')

    assert failure is not None  # narrow type
    return failure


DUMMY_FAILURE_PRINTABLE = """failure

a_dummy_detail: bar
message: dummy failure
recoverable: true
fail_guest_request: true
exception:
    instance: ''
    type: <class 'ValueError'>
traceback: |-
    File "__FILE__", line 26, in fixture_failure
        12   def fixture_failure() -> Failure:
     (...)
        22       def _c() -> None:
        23           _b()
        24
        25       try:
    --> 26           _c()
        27
        ..................................................
         _c = <function 'fixture_failure.<locals>._c' test_failure.py:22>
         _b = <function 'fixture_failure.<locals>._b' test_failure.py:19>
        ..................................................

    File "__FILE__", line 23, in _c
        22   def _c() -> None:
    --> 23       _b()
        ..................................................
         _b = <function 'fixture_failure.<locals>._b' test_failure.py:19>
        ..................................................

    File "__FILE__", line 20, in _b
        19   def _b() -> None:
    --> 20       _a()
        ..................................................
         _a = <function 'fixture_failure.<locals>._a' test_failure.py:16>
        ..................................................

    File "__FILE__", line 17, in _a
        16   def _a() -> None:
    --> 17       raise ValueError

    ValueError""".replace('__FILE__', __file__)


def test_printable(failure: Failure) -> None:
    #    # Because traceback formatting containts
    #    def _cmp(left: str, right: str) -> None:
    assert failure._printable() == DUMMY_FAILURE_PRINTABLE
    assert str(failure) == DUMMY_FAILURE_PRINTABLE
    assert repr(failure) == '<Failure: message="dummy failure">'
