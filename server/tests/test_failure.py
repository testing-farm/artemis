# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import pytest

from tft.artemis import Failure


@pytest.fixture(name='failure')
def fixture_failure() -> Failure:
    # Create a nice traceback for our failure...
    def _a() -> None:
        raise ValueError('dummy error happened')

    def _b() -> None:
        _a()

    def _c() -> None:
        _b()

    try:
        _c()

    except Exception as exc:
        failure = Failure.from_exc('dummy failure', exc, a_dummy_detail='bar')

    return failure


DUMMY_FAILURE_PRINTABLE = """failure

a_dummy_detail: bar
message: dummy failure
recoverable: true
fail_guest_request: true
exception:
    instance: dummy error happened
    type: <class 'ValueError'>
traceback: |-
    File "__FILE__", line 22, in fixture_failure
        10   def fixture_failure() -> Failure:
     (...)
        18       def _c() -> None:
        19           _b()
        20
        21       try:
    --> 22           _c()
        23
        ..................................................
         Failure = <class 'tft.artemis.Failure'>
         _c = <function 'fixture_failure.<locals>._c' test_failure.py:18>
         _b = <function 'fixture_failure.<locals>._b' test_failure.py:15>
        ..................................................

    File "__FILE__", line 19, in _c
        18   def _c() -> None:
    --> 19       _b()
        ..................................................
         _b = <function 'fixture_failure.<locals>._b' test_failure.py:15>
        ..................................................

    File "__FILE__", line 16, in _b
        15   def _b() -> None:
    --> 16       _a()
        ..................................................
         _a = <function 'fixture_failure.<locals>._a' test_failure.py:12>
        ..................................................

    File "__FILE__", line 13, in _a
        12   def _a() -> None:
    --> 13       raise ValueError('dummy error happened')

    ValueError: dummy error happened""".replace('__FILE__', __file__)


def test_printable(failure: Failure) -> None:
    #    # Because traceback formatting containts
    #    def _cmp(left: str, right: str) -> None:
    assert failure._printable() == DUMMY_FAILURE_PRINTABLE
    assert str(failure) == DUMMY_FAILURE_PRINTABLE
    assert repr(failure) == '<Failure: message="dummy failure">'
