# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import operator
import re
from typing import Any, Callable, Iterable, List, Optional, Tuple
from unittest.mock import MagicMock

import _pytest.logging
import _pytest.monkeypatch
import jinja2
from typing_extensions import Protocol

# Since this is our entry point when running tests, we must take care of injecting additional filters
# into defaults before we start messing with Jinja. Otherwise, the template below would initialize
# an environment deep in Jinja internals, which would then be reused for all `Template` calls, even those
# made by Artemis code.
#
# Importing Artemis core package gives it chance to do what must be done.
import tft.artemis  # noqa: F401

LOG_ASSERT_MESAGE = jinja2.Template("""
Cannot find log record with these properties:
{% for field, value in fields.items() %}
    {{ field }} == {{ value }}
{%- endfor %}
""")


class MockPatcher(Protocol):
    def __call__(
        self,
        obj: Any,
        member_name: str,
        obj_name: Optional[str] = None
    ) -> MagicMock:
        pass


class PatternMatching:
    def __init__(self, pattern: str, method: str) -> None:
        self.pattern = pattern
        self._compiled_pattern = re.compile(pattern)
        self.method = getattr(self._compiled_pattern, method)

    def __repr__(self) -> str:
        return f'<{self.__class__.__name__}: "{self.pattern}">'


class MATCH(PatternMatching):
    """
    Wrap a string with this class, to use it as a regular expression when matching log records.

    :py:class:`SEARCH` applies to any place within the string, while ``MATCH`` must match from the
    beginning of the string.

    .. code-block:: python

       assert_log(message=MATCH('an exception .+ was raised'))
    """

    def __init__(self, pattern: str) -> None:
        super().__init__(pattern, 'match')


class SEARCH(PatternMatching):
    """
    Wrap a string with this class, to use it as a regular expression when searching for log records.

    ``SEARCH`` applies to any place within the string, while :py:class:`MATCH` must match from the
    beginning of the string.

    .. code-block:: python

       assert_log(message=SEARCH('an exception .+ was raised'))
    """

    def __init__(self, pattern: str) -> None:
        super().__init__(pattern, 'search')


def assert_log(
    caplog: _pytest.logging.LogCaptureFixture,
    evaluator: Callable[[Iterable[Any]], bool] = any,
    **tests: Any
) -> None:
    """
    Assert log contains a record - logged message - with given properties. Those are specified as keyword
    parameters: :py:class:`logging.LogRecords` properties are allowed names, parameter values are the
    expected values.

    .. code-block:: python

       assert_log(message='everything went well', levelno=logging.INFO)
       assert_log(message='things broke down', levelno=logging.ERROR)
       assert_log(message=MATCH('user .+ logged in'), levelno=logging.INFO)

    :param caplog: Pytest's `caplog` fixture.
    :param evaluator: a callable reducing a given list of booleans into a single boolean. It is used
        to evaluate whether the search for matching record was successfull: each record is tested, and
        results of these per-record tests are passed to `evaluator` for the final decision.
    """

    # We are given field_name=expected_value pairs, but we also want to be open to other binary operators,
    # like "field_name matches pattern". To protect the actual matching from aspects of different possible
    # operators, we will convert the "tests" into basic building blocks: a field name, a callable accepting
    # two parameters, and the given (expected) value. With these, we can reduce the matching into functions
    # calls without worrying what functions we work with.

    operators: List[Tuple[str, Callable[[Any, Any], bool], Any]] = []

    for field_name, expected_value in tests.items():
        # Special case: if the expected value is a pattern matching instance, it represents a regular expression.
        # We don't modify the field name and "expected" value, but the function will be a custom lambda calling
        # proper `re` method.
        if isinstance(expected_value, PatternMatching):
            operators.append((
                field_name,
                lambda a, b: a.method(b) is not None,
                expected_value
            ))

            continue

        # Python's `operator` package offers operators - `==` or `!=` - in a form of functions, which is exactly
        # what we need here, so we don't have to build our own `lambda a, b: a == b`. We might use more than just
        # `eq` in the future, so let's start with `operator` right away.

        operators.append((
            field_name,
            operator.eq,
            expected_value
        ))

    # Given a logging record, apply all field/operator/value triplets, and make sure all match the actual
    # record properties.
    def _cmp(record: logging.LogRecord) -> bool:
        return all([
            op(expected_value, getattr(record, field_name))
            for field_name, op, expected_value in operators
        ])

    # Final step: apply our "make sure field/operator/value triplets match given record" to each and every record,
    # and reduce per-record results into a single answer. By default, `any` is used which means that any record
    # matching all field/operator/value triples yield the final "yes, such a record exists".
    assert evaluator([
        _cmp(record)
        for record in caplog.records
    ]), LOG_ASSERT_MESAGE.render(fields=tests)


def assert_failure_log(
    caplog: _pytest.logging.LogCaptureFixture,
    failure_message: str,
    exception_label: Optional[str] = None,
    **tests: Any
) -> None:
    """
    A failure log is just a special log record, with a nicely formatted message describing the aspects
    of the failure. As of now, only the failure message is tested, but in the future we want to verify
    failure details as well, to make sure code under the test actually sets them.

    .. code-block::

       assert_failure_log(caplog, 'failed to release pool resources')
       assert_failure_log(caplog, 'failed to unserialize resource IDs', exception_label='JSONDecodeError:')
    """

    message = rf'(?m){failure_message}\n'

    if exception_label:
        message = f'{message}(?:.*\n)+    {exception_label}'

    assert_log(
        caplog,
        message=SEARCH(message),
        levelno=logging.ERROR
    )
