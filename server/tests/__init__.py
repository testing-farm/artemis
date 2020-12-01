import operator
import re

import jinja2

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


class MATCH:
    """
    Wrap a string with this class, to use it as a regular expression when searching for log records.

    .. code-block:: python

       assert_log(message=MATCH('an exception .+ was raised'))
    """

    def __init__(self, pattern):
        self.pattern = pattern


def assert_log(caplog, evaluator=any, **tests):
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

    operators = []

    for field_name, expected_value in tests.items():
        # Special case: if the expected value is `MATCH` instance, it represents a regular expression.
        # We don't modify the field name and "expected" value, but the function will be a custom
        # lambda calling `re.match`.
        if isinstance(expected_value, MATCH):
            operators.append((
                field_name,
                lambda a, b: re.match(a.pattern, b) is not None,
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
    def _cmp(record):
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
