# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import collections
import logging
import re
import types

import pytest

import gluetool
import gluetool_modules.helpers.rules_engine
from gluetool_modules.helpers.rules_engine import RulesEngine, Rules, MatchableString, RulesSyntaxError, InvalidASTNodeError

from mock import MagicMock
from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    _, module = create_module(RulesEngine)

    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/rules_engine.py', 'RulesEngine')


def test_shared(module):
    assert module.glue.has_shared('evaluate_rules') is True


def test_rules_repr():
    assert repr(Rules('1 == 1')) == '<Rules: 1 == 1>'


def test_matchable_string_inheritance():
    s = MatchableString('foo')

    assert isinstance(s, str)


@pytest.mark.parametrize('regex_method, kwargs, expected_args', [
    ('match',  {},           (re.I,)),
    ('match',  {'I': True},  (re.I,)),
    ('match',  {'I': False}, (0,)),
    ('search', {},           (re.I,)),
    ('search', {'I': True},  (re.I,)),
    ('search', {'I': False}, (0,))
])
def test_matchable_string_regex(monkeypatch, regex_method, kwargs, expected_args):
    s = MatchableString('foo')

    mock_method = MagicMock()
    monkeypatch.setattr('gluetool_modules.helpers.rules_engine.re.{}'.format(regex_method), mock_method)

    getattr(s, regex_method)('bar', **kwargs)

    mock_method.assert_called_once_with('bar', 'foo', *expected_args)


@pytest.mark.parametrize('rule', [
    '1 == 1'
])
def test_compile_sanity(rule):
    code = Rules(rule)._compile()

    assert isinstance(code, types.CodeType)


@pytest.mark.parametrize('rule, error_klass, error_message, error_detail', [
    (
        '1 == ',
        RulesSyntaxError,
        r'Cannot parse rules',
        'Position 1:5: unexpected EOF while parsing (<unknown>, line 1)'
    ),
    (
        '1 * 1',
        InvalidASTNodeError,
        r"It is not allowed to use 'BinOp' in rules",
        "It is not allowed to use 'BinOp' in rules."
    ),
    (
        1,
        gluetool_modules.helpers.rules_engine.RulesTypeError,
        r'Cannot parse rules',
        'expected a readable buffer object'
    )
])
def test_compile_error(rule, error_klass, error_message, error_detail):
    with pytest.raises(error_klass, match=error_message) as excinfo:
        Rules(rule)._compile()

    assert excinfo.value.error == error_detail


@pytest.mark.parametrize('rule, context, outcome', [
    (
        '1 == 1', {}, True
    ),
    (
        '1 == 2', {}, False
    ),
    (
        "FOO.match('bar')", {'FOO': MatchableString('foo')}, None
    ),
    (
        "FOO.match('bar') is None", {'FOO': MatchableString('bar')}, False
    ),
    (
        "FOO.match('bar') is None", {'FOO': MatchableString('foo')}, True
    ),
    (
        "not FOO.match('bar')", {'FOO': MatchableString('bar')}, False
    )
])
def test_eval(rule, context, outcome):
    assert Rules(rule).eval({}, context) == outcome


def test_unknown_variable(module):
    with pytest.raises(gluetool.GlueError, match=r"Unknown variable used in rule: name 'foo' is not defined"):
        module.evaluate_rules('foo')


@pytest.mark.parametrize('rule, context, result', [
    ("EXISTS('foo')",     {}, False,),
    ("not EXISTS('foo')", {}, True),
    ("EXISTS('foo')",     {'foo': 17}, True)
])
def test_exists(module, rule, context, result):
    assert module.evaluate_rules(rule, context=context) is result


@pytest.mark.parametrize('rule, context, result', [
    ("ANY([True, False])", {}, True),
    ("not ANY([True, False])", {}, False),
    ("ANY([False, False])", {}, False),
    ("ANY(foo)", {'foo': [True, False]}, True)
])
def test_any(module, rule, context, result):
    assert module.evaluate_rules(rule, context=context) is result


@pytest.mark.parametrize('rule, context, result', [
    ("ALL([True, False])", {}, False),
    ("not ALL([True, False])", {}, True),
    ("ALL([True, True])", {}, True),
    ("ALL(foo)", {'foo': [True, True]}, True),
    ("ALL(foo)", {'foo': [True, False]}, False)
])
def test_all(module, rule, context, result):
    assert module.evaluate_rules(rule, context=context) is result


FILTER_CASES = [
    # simple case, single entry with matching rule
    (
        [{'rule': 'True'}],
        None,
        'True',
        False,
        [{'rule': 'True'}]
    ),

    # two entries, both valid
    (
        [{'rule': 'True'}, {'rule': 'True'}],
        None,
        'True',
        False,
        [{'rule': 'True'}, {'rule': 'True'}]
    ),

    # two entries, both valid, but "stop after first match" set
    (
        [{'rule': 'True'}, {'rule': 'True'}],
        None,
        'True',
        True,
        [{'rule': 'True'}]
    ),

    # one invalid entry
    (
        [{'rule': 'False'}, {'rule': 'True'}],
        None,
        'True',
        True,
        [{'rule': 'True'}]
    ),

    # two entries, one without a rule
    (
        [{}, {'rule': 'True'}],
        None,
        'True',
        False,
        [{}, {'rule': 'True'}]
    ),

    # custom context
    (
        [{'rule': 'FOO == 1'}],
        {'FOO': 1},
        'True',
        False,
        [{'rule': 'FOO == 1'}]
    ),

    # custom context provider
    (
        [{'rule': 'FOO == 1'}],
        lambda: {'FOO': 1},
        'True',
        False,
        [{'rule': 'FOO == 1'}]
    )
]


@pytest.mark.parametrize(
    'entries, context, default_rule, stop_at_first_hit, expected',
    FILTER_CASES
)
def test_filter(module, entries, context, default_rule, stop_at_first_hit, expected):
    # `_filter` returns iterator of tuples with two items, we need a list to compare with `expected`
    actual = [
        entry for entry, _ in module._filter(entries, context=context, default_rule=default_rule, stop_at_first_hit=stop_at_first_hit)
    ]

    assert actual == expected


@pytest.mark.parametrize(
    'entries, context, default_rule, stop_at_first_hit, expected',
    FILTER_CASES
)
def test_evaluate_filter(module, entries, context, default_rule, stop_at_first_hit, expected):
    actual = module.evaluate_filter(
        entries, context=context, default_rule=default_rule, stop_at_first_hit=stop_at_first_hit
    )

    assert actual == expected


@pytest.mark.parametrize(
    'rules, expected_call, expected_message',
    [
        ('', False, None),
        ('1 == 1', True, 'rules evaluate to: True')
    ]
)
def test_execute(log, monkeypatch, module, rules, expected_call, expected_message):
    # Make evaluate_rules always return "True" - it's not important what the value is
    monkeypatch.setattr(module, 'evaluate_rules', MagicMock(return_value='True'))

    module._config['rules'] = rules

    module.execute()

    if expected_call:
        module.evaluate_rules.assert_called_once_with(rules)

        assert log.match(levelno=logging.INFO, message=expected_message)

    else:
        module.evaluate_rules.assert_not_called()

        assert not log.match(levelno=logging.INFO, message=expected_message)


# Testing of instruction processing could be a bit messy when put into a "simple" list, therefore splitting into
# more distinct entries before merging them for parametrization.
EICase = collections.namedtuple(
    'EICase',
    (
        'instructions',
        'commands',
        'context',
        'default_rule',
        'stop_at_first_hit',
        'ignore_unhandled_commands',
        'check',
        'raises'
    )
)


# simple case - no commands, just a rule
IC_SIMPLE = EICase(
    instructions=[{'rule': 'True'}],
    commands={},
    context=None,
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=False,
    check=None,
    raises=False
)


# single instruction, with a single command
def _check_single_instruction(log):
    IC_SINGLE_INSTRUCTION.commands['cmd1'].assert_called_once_with(
        IC_SINGLE_INSTRUCTION.instructions[0],
        'cmd1',
        IC_SINGLE_INSTRUCTION.instructions[0]['cmd1'],
        IC_SINGLE_INSTRUCTION.context
    )


IC_SINGLE_INSTRUCTION = EICase(
    instructions=[{'rule': 'True', 'cmd1': {'dummy-argument': 1}}],
    commands={'cmd1': MagicMock()},
    context={'dummy-context': None},
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=False,
    check=_check_single_instruction,
    raises=False
)


# two instructions, each with a single command
def _check_two_instructions(log):
    IC_TWO_INSTRUCTIONS.commands['cmd1'].assert_called_once_with(
        IC_TWO_INSTRUCTIONS.instructions[0],
        'cmd1',
        IC_TWO_INSTRUCTIONS.instructions[0]['cmd1'],
        IC_TWO_INSTRUCTIONS.context
    )

    IC_TWO_INSTRUCTIONS.commands['cmd2'].assert_called_once_with(
        IC_TWO_INSTRUCTIONS.instructions[1],
        'cmd2',
        IC_TWO_INSTRUCTIONS.instructions[1]['cmd2'],
        IC_TWO_INSTRUCTIONS.context
    )


IC_TWO_INSTRUCTIONS = EICase(
    instructions=[{'rule': 'True', 'cmd1': {'dummy-argument': 1}}, {'rule': 'True', 'cmd2': {'dummy-argument': 1}}],
    commands={'cmd1': MagicMock(), 'cmd2': MagicMock()},
    context={'dummy-context': None},
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=False,
    check=_check_two_instructions,
    raises=False
)


# single instruction with two distinct commands
def _check_multiple_commands(log):
    IC_MULTIPLE_COMMANDS.commands['cmd1'].assert_called_once_with(
        IC_MULTIPLE_COMMANDS.instructions[0],
        'cmd1',
        IC_MULTIPLE_COMMANDS.instructions[0]['cmd1'],
        IC_MULTIPLE_COMMANDS.context
    )

    IC_MULTIPLE_COMMANDS.commands['cmd2'].assert_called_once_with(
        IC_MULTIPLE_COMMANDS.instructions[0],
        'cmd2',
        IC_MULTIPLE_COMMANDS.instructions[0]['cmd2'],
        IC_MULTIPLE_COMMANDS.context
    )


IC_MULTIPLE_COMMANDS = EICase(
    instructions=[
        collections.OrderedDict([
            ('rule', 'True'),
            ('cmd1', {'dummy-argument': 1}),
            ('cmd2', {'dummy-argument': 1})
        ])
    ],
    commands={'cmd1': MagicMock(), 'cmd2': MagicMock()},
    context={'dummy-context': None},
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=False,
    check=_check_multiple_commands,
    raises=False
)


# single instruction with two commands, but the first first one returns `True` and `stop_at_first_hit`
# is set, therefore the second command shouldn't be triggered
def _check_multiple_commands_first_hit(log):
    IC_MULTIPLE_COMMANDS_FIRST_HIT.commands['cmd1'].assert_called_once_with(
        IC_MULTIPLE_COMMANDS_FIRST_HIT.instructions[0],
        'cmd1',
        IC_MULTIPLE_COMMANDS_FIRST_HIT.instructions[0]['cmd1'],
        IC_MULTIPLE_COMMANDS_FIRST_HIT.context
    )

    IC_MULTIPLE_COMMANDS_FIRST_HIT.commands['cmd2'].assert_not_called()


IC_MULTIPLE_COMMANDS_FIRST_HIT = EICase(
    instructions=[
        collections.OrderedDict([
            ('rule', 'True'),
            ('cmd1', {'dummy-argument': 1}),
            ('cmd2', {'dummy-argument': 1})
        ])
    ],
    commands={
        'cmd1': MagicMock(return_value=True),
        'cmd2': MagicMock()
    },
    context={'dummy-context': None},
    default_rule='True',
    stop_at_first_hit=True,
    ignore_unhandled_commands=False,
    check=_check_multiple_commands_first_hit,
    raises=False
)


# command without a callback, but ignoring, only a warnign should appear
def _check_no_callback(log):
    assert log.match(levelno=logging.WARN, message="No callback for command 'cmd1'")


IC_NO_CALLBACK = EICase(
    instructions=[{'rule': 'True', 'cmd1': {'dummy-argument': 1}}],
    commands={},
    context=None,
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=True,
    check=_check_no_callback,
    raises=False
)

# command without a callback, an exception should be raised
IC_NO_CALLBACK_EXC = EICase(
    instructions=[{'rule': 'True', 'cmd1': {'dummy-argument': 1}}],
    commands={},
    context=None,
    default_rule='True',
    stop_at_first_hit=False,
    ignore_unhandled_commands=False,
    check=None,
    raises=True
)


@pytest.mark.parametrize(
    'instructions, commands, context, default_rule, stop_at_first_hit, ignore_unhandled_commands, check, raises',
    [
        IC_SIMPLE,
        IC_SINGLE_INSTRUCTION,
        IC_TWO_INSTRUCTIONS,
        IC_MULTIPLE_COMMANDS,
        IC_MULTIPLE_COMMANDS_FIRST_HIT,
        IC_NO_CALLBACK,
        IC_NO_CALLBACK_EXC
    ]
)
def test_evaluate_instructions(log, module, instructions, commands, context, default_rule, stop_at_first_hit, ignore_unhandled_commands, check, raises):
    if raises:
        with pytest.raises(gluetool.GlueError):
            module.evaluate_instructions(
                instructions,
                commands,
                context=context,
                default_rule=default_rule,
                stop_at_first_hit=stop_at_first_hit,
                ignore_unhandled_commands=ignore_unhandled_commands
            )

    else:
        module.evaluate_instructions(
            instructions,
            commands,
            context=context,
            default_rule=default_rule,
            stop_at_first_hit=stop_at_first_hit,
            ignore_unhandled_commands=ignore_unhandled_commands
        )

    if check:
        check(log)
