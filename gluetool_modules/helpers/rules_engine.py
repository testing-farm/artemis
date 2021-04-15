# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import functools
import imp
import re
import sys
import ast

import jinja2
import gluetool
from gluetool import GlueError, SoftGlueError
from gluetool.log import log_dict
from gluetool.utils import cached_property, load_yaml, normalize_multistring_option
import _ast

# Type annotations
from typing import cast, Any, Callable, Dict, Iterator, List, Match, Optional, Tuple, Union  # noqa

EntryType = Dict[str, Any]  # noqa
ContextType = Dict[str, Any]  # noqa
ContextGetterType = Callable[[], ContextType]  # noqa
CommandCallbackType = Callable[[EntryType, str, Any, ContextType], bool]  # noqa


# The module makes context available to rules via `EVAL_CONTEXT()` call. Level the playground
# by making it available to templates as well.
@jinja2.contextfunction  # type: ignore  # untyped decorator
def _get_context(context):
    # type: (Dict[str, Any]) -> Dict[str, Any]

    return context


jinja2.defaults.DEFAULT_NAMESPACE['EVAL_CONTEXT'] = _get_context


class AttrDict(Dict[str, Any]):
    """
    Access dictonary items as its attributes.
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None

        super(AttrDict, self).__init__(*args, **kwargs)

        self.__dict__ = self


class RulesExecutionError(GlueError):
    def __init__(
        self,
        message,  # type: str
        rules,  # type: str
        rule_locals,  # type: ContextType
        rule_globals,  # type: ContextType
        exc_info=None  # type: Optional[gluetool.log.ExceptionInfoType]
    ):
        # type: (...) -> None

        super(RulesExecutionError, self).__init__(message)

        self.rules = rules
        self.rule_locals = rule_locals
        self.rule_globals = rule_globals
        self.exc_info = exc_info


class RulesError(SoftGlueError):
    """
    Base class of rules-related soft exceptions.

    :param str message: descriptive message, passed to parent Exception classes.
    :param Rules rules: rules in question.
    :param str intro: introductory text, pasted at the beginning of template.
    :param str error: specific error message.
    """

    def __init__(self, message, rules, intro, error):
        # type: (str, str, str, str) -> None

        super(RulesError, self).__init__(message)

        self.rules = rules
        self.intro = intro
        self.error = error


class InvalidASTNodeError(RulesError):
    def __init__(self, rules, node):
        # type: (str, ast.AST) -> None

        super(InvalidASTNodeError, self).__init__(
            "It is not allowed to use '{}' in rules".format(node.__class__.__name__),
            rules,
            'Dangerous and disallowed node used in rules',
            "It is not allowed to use '{}' in rules.".format(node.__class__.__name__))


class RulesSyntaxError(RulesError):
    def __init__(self, rules, exc):
        # type: (str, SyntaxError) -> None

        super(RulesSyntaxError, self).__init__(
            'Cannot parse rules',
            rules,
            "Cannot parse rules '{}'".format(rules),
            'Position {}:{}: {}'.format(exc.lineno, exc.offset, exc))


class RulesTypeError(RulesError):
    def __init__(self, rules, exc):
        # type: (str, Exception) -> None

        super(RulesTypeError, self).__init__(
            'Cannot parse rules',
            rules,
            "Cannot parse rules '{}'".format(rules),
            str(exc))


class RulesASTVisitor(ast.NodeTransformer):
    """
    Custom AST visitor, making sure no disallowed nodes are present in the rules' AST.
    """

    _valid_classes = tuple([
        getattr(_ast, node_class) for node_class in (
            'Expression', 'Expr', 'Compare', 'Name', 'Load', 'BoolOp', 'UnaryOp',
            'Str', 'Num', 'List', 'Tuple', 'Dict',
            'Subscript', 'Index', 'ListComp', 'comprehension',
            'Store',
            'Eq', 'NotEq', 'Lt', 'LtE', 'Gt', 'GtE', 'Is', 'IsNot', 'In', 'NotIn',
            'And', 'Or', 'Not',
            'IfExp',
            'Attribute', 'Call'
        )
    ])

    def __init__(self, rules):
        # type: (Rules) -> None

        super(RulesASTVisitor, self).__init__()

        self._rules = rules

    def generic_visit(self, node):
        # type: (ast.AST) -> Any

        if not isinstance(node, RulesASTVisitor._valid_classes):
            raise InvalidASTNodeError(self._rules._rules, node)

        return super(RulesASTVisitor, self).generic_visit(node)


class MatchableString(str):
    """
    Enhanced string - it has all methods and properties of a string, provides
    :py:ref:`re.match` and :py:ref:`re.search` as instance methods.
    """

    def match(self, pattern, I=True):  # noqa: E741  # ambiguous variable name 'I'
        # type: (str, bool) -> Optional[Match[Any]]

        return re.match(pattern, str(self), re.I if I is True else 0)

    def search(self, pattern, I=True):  # noqa: E741  # ambiguous variable name 'I'
        # type: (str, bool) -> Optional[Match[Any]]

        return re.search(pattern, str(self), re.I if I is True else 0)


class Rules(object):
    """
    Wrap compilation and evaluation of filtering rules.

    :param str rules: Rule is a Python expression that could be evaluated.
    """

    def __init__(self, rules):
        # type: (str) -> None

        self._rules = rules
        self._code = None  # type: Any

    def __repr__(self):
        # type: () -> str

        return '<Rules: {}>'.format(self._rules)

    def _compile(self):
        # type: () -> Any
        """
        Compile rule. Parse rule into an AST, perform its sanity checks,
        and then compile it into executable.
        """

        try:
            tree = ast.parse(self._rules, mode='eval')

        except SyntaxError as exc:
            raise RulesSyntaxError(self._rules, exc)

        except TypeError as e:
            raise RulesTypeError(self._rules, e)

        RulesASTVisitor(self).visit(tree)

        try:
            return compile(tree, '<static-config-file>', 'eval')

        # This bit will probably be left uncovered by unit tests - the best way forward seems to be patching
        # `compile` and injecting an error, but `compile` is an builtin function and pytest might be using
        # it internaly (or may start in the future...). Not a good idea to poke into that.
        except Exception as e:
            raise RulesTypeError(self._rules, e)

    def eval(self, our_globals, our_locals):
        # type: (ContextType, ContextType) -> Any
        """
        Evaluate rule. User must provide both `locals` and `globals` dictionaries
        we use as a context for the rule.
        """

        if self._code is None:
            self._code = self._compile()

        # eval is dangerous. This time I hope it's safe-guarded by AST filtering...
        try:
            return eval(self._code, our_globals, our_locals)

        except NameError as exc:
            raise RulesExecutionError(
                'Unknown variable used in rule: {}'.format(exc.message),
                self._rules,
                our_locals,
                our_globals,
                exc_info=sys.exc_info()
            )

        except Exception as exc:
            raise RulesExecutionError(
                'Cannot execute the rule: `{}` => {}'.format(self._rules, exc.message),
                self._rules,
                our_locals,
                our_globals,
                exc_info=sys.exc_info()
            )


class RulesEngine(gluetool.Module):
    """
    Simple "rule" evaluation engine. Allows users to use subset of Python language
    in their configuration, for example to decide which section of a config file to
    use. Module using such configuration just need to provide necessary context, e.g.
    objects that are available to the rules the module supports.

    To write rules, a restricted set of Python expressions is provided. Following
    Python constructs are allowed:

        * comparisons: ``==``, ``<=``, ``not in``, etc.
        * strings, numbers, lists, tuples;
        * logic operators: ``and``, ``or``, ``not``;
        * ``... if ... else ...`` expressions;
        * calling a function or method;
        * list, tuples, dicts and list comprehensions.

    Strings have two extra methods, providing access to regular expression functionality:

        * ``match(pattern, I=True)``
        * ``search(pattern, I=True)``

    Few helper functions are available as well:

        * ``ALL(iterable)``, returning ``True`` when all items of iterable are true-ish;
        * ``ANY(iterable)``, returning ``True`` when any item of iterable is true-ish;
        * ``EXISTS('foo')``, returning ``True`` when the variable named ``foo`` exists.

    Custom functions are supported via ``--functions`` option. Listed files are loaded and
    any global object with name not starting with `_` becomes part of ``rules-engine`` eval
    context. These functions can be called, and they are given eval context as their first
    argument implicitly.

    Custom variables are supported via ``--variables`` and ``--user-variables`` options.
    Listed YAML files are expected to contain key:value mappings which are then loaded and:

        * ``variables``: key:value pairs will be exported into ``rules-engine`` eval context.
        Values can be complex objects and lists, they are exported as-is, with no additional
        processing.
        * ``user-variables``: key:value pairs will be available via ``user_variables`` shared
        function. On every call, the values - which support templates - are re-rendered.

    .. code-block:: yaml

       # variables
       NAMES:
         - foo
         - bar
         - baz: 79

       # user-variables

       NAME: |
         {% JENKINS_JOB_NAME == 'foo' %}
           some-value
         {% else %}
           some-other-value
         {% endif %}

    Users of this module would simply specify what objects are available to rules in their
    domain, and then provides these objects when asking ``rules-engine`` (via the shared
    function) to evaluate the rules.

    For example, a module M promises its users that current user's username would be
    available to rules M is using for its functionality, as a variable ``USERNAME``.
    Such rules can then look like ``USERNAME.match('f.*')``, or ``USERNAME == 'foo'``.
    If M is used by user named ``foobar``, the first rule would evaluate to ``True``,
    while the second would be false-ish.
    """

    name = 'rules-engine'
    description = 'Evaluate simple Python-like rules.'

    options = {
        'rules': {
            'help': 'Rules to evaluate when module is executed. Used for testing (default: %(default)s).',
            'default': None
        },
        'functions': {
            'help': 'File(s) with additional functions to use in rules and templates (default: none).',
            'action': 'append',
            'default': []
        },
        'variables': {
            'help': 'File(s) with additional context objects (default: none).',
            'action': 'append',
            'default': [],
            'metavar': 'FILE'
        },
        'user-variables': {
            'help': 'File(s) with additional variables that are rendered on demand (default: none).',
            'action': 'append',
            'default': [],
            'metavar': 'FILE'
        }
    }

    shared_functions = ['evaluate_rules', 'evaluate_filter', 'evaluate_instructions', 'user_variables']

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    @gluetool.utils.cached_property
    def _user_variable_files(self):
        # type: () -> List[str]

        return gluetool.utils.normalize_path_option(self.option('user-variables'))

    @gluetool.utils.cached_property
    def _user_variable_templates(self):
        # type: () -> Dict[str, str]

        templates = {}  # type: Dict[str, str]

        for filepath in self._user_variable_files:
            templates.update(gluetool.utils.load_yaml(filepath, logger=self.logger))

        return templates

    @property
    def eval_context(self):
        # type: () -> Any

        return gluetool.utils.dict_update(
            self.functions,
            self.variables
        )

    def _filter(self,
                entries,  # type: List[EntryType]
                context=None,  # type: Optional[Union[ContextType, ContextGetterType]]
                default_rule='True',  # type: str
                stop_at_first_hit=False  # type: bool
               ):  # noqa
        # type: (...) -> Iterator[Tuple[EntryType, ContextType]]
        """
        Yields entries that are allowed by their rules.

        This is an internal implementation of a common functionality: find out what entries are valid
        with respect to their rules. The method is used to simplify other - public - methods.

        :param list(dict) entries: List of entries to filter.
        :param context: Provider of context for rules and templating services. Either a dictionary or a callable
            returning a dictionary. If callable is provided, it will be called before each entry to
            refresh the context.
        :param str default_rule: If there's no rule in the instruction, this will be used. For example, use ``"False"``
            to skip instructions without rules.
        :param bool stop_at_first_hit: If set, first entry whose rule evaluated true-ishly is returned immediately.
        :rtype: Iterator[tuple(dict, dict)]
        :returns: yields tuples of two items: the entry and the context used in its evaluation.
        """

        # If we don't have a context, get one from the core.
        if context is None:
            context = self.shared('eval_context')

        # For the sake of simplicity, the loop over instructions will always call context_getter. It's either
        # callable given by caller, or a simple anonymous function returning a dictionary - either the one
        # given by caller or the default from above.
        if callable(context):
            context_getter = context

        else:
            context_getter = cast(ContextGetterType, lambda: context)

        for entry in entries:
            loop_context = context_getter()

            log_dict(self.debug, 'entry', entry)

            # Not calling `self.evaluate_rules` directly - other modules may have overload this shared function,
            # let's use the correct implementation.
            if not self.shared('evaluate_rules', entry.get('rule', default_rule), context=loop_context):
                self.debug('denied by rules')
                continue

            yield entry, loop_context

            if stop_at_first_hit:
                break

    @cached_property
    def functions(self):
        # type: () -> Dict[str, Callable[..., Any]]

        sources = normalize_multistring_option(self.option('functions'))

        functions = {}  # type: Dict[str, Callable[..., Any]]

        def _wrapper(wrapped, *args, **kwargs):
            # type: (Callable[..., Any], *Any, **Any) -> Any

            return wrapped(
                self.shared('eval_context'),
                *args,
                **kwargs
            )

        for source_filename in sources:
            source_filepath = gluetool.utils.normalize_path(source_filename)

            try:
                code = imp.load_source(source_filename.replace('/', '_'), source_filepath)

            except Exception as exc:
                raise GlueError('Failed to load functions from {}: {}'.format(source_filename, exc))

            for member_name in dir(code):
                if member_name.startswith('_'):
                    continue

                self.debug("registered function '{}' from {}".format(member_name, source_filename))

                fn = getattr(code, member_name)

                if not callable(fn):
                    continue

                # Here we employ one of Python's quirks: default values of keyword arguments are evaluated
                # when the function is defined. That's why one shouldn't use mutables as default values. But,
                # it can help us solve problem with closures and loops.
                #
                # Functions loaded from the file expect eval context as their first argument, and may accept
                # multiple other arguments. Because of reasons, they have no direct access to eval context
                # namespace, it must be given to them. Currently caller passes the eval context to them, but
                # that prolongs the function call, and leads to messy YAML files. It would be much better to
                # pass eval context to the functions automagically. So, loop over each function, wrap it with
                # a thin function that acquires eval context and calls the wrapped function, and let users call
                # our wrappers. Easy, right?
                #
                # for fn in functions:
                #     def wrapper():
                #         fn()
                #
                # Wrong! Wrappers would use our loop variable, `fn`, to call the function, but since closures
                # close over values, nor variables, wrapper would get the value of `fn` *at the runtime* - no
                # matter what wrapper we would call, its `fn` would always point to the last function in the
                # list.
                #
                # So, to overcome that, we pass the function to wrapper as a default value of a keyword argument.
                # That way, for each `fn` we would get its own wrapper which would not be misled by our loop variable,
                # because `fn` would be located in wrapper's scope \o/
                #
                # for fn in functions:
                #     def wrapper(wrapped=fn, *args, **kwargs):
                #         wrapped(*args, **kwargs)
                #
                # Wrong! Because of Python 2 limitations:
                #   - _wrapper(wrapped=fn, *args, **kwargs) won't work in Python 2,
                #   - _wrapper(wrapped=fn, *args) would work, but the first positional argument overrides `wrapped`.
                #
                # So, functools.partial it is...

                functions[member_name] = functools.partial(_wrapper, fn)

        return functions

    def _render_user_variables(self, logger=None, context=None):
        # type: (Optional[gluetool.log.ContextAdapter], Optional[Dict[str, Any]]) -> Dict[str, Any]
        """
        Returns mapping of variables, with values fully rendered.
        """

        logger = logger or self.logger
        context = context or self.shared('eval_context')

        return {
            name: gluetool.utils.render_template(template, logger=self.logger, **context)
            for name, template in self._user_variable_templates.iteritems()
        }

    @cached_property
    def variables(self):
        # type: () -> Any

        configs = normalize_multistring_option(self.option('variables'))

        variables = {}  # type: Any

        def _assert_var_names(d, *path):
            # type: (Dict[str, Any], *str) -> None
            """
            Make sure no key in the dictionary collides with any dictionary method. Should there be any collision,
            value of the key would replace the method, and calling such method would result in error since it's
            not the original method anymore but an arbitrary value that was present in the dictionary.

            .. code-block:: python

               d = {'keys': 'foo'}
               e = AttrDict(**d)
               e.keys()  # e.keys is now "foo", not callable...
            """

            for k in d.iterkeys():
                if k not in dir(d):
                    continue

                raise GlueError("Invalid variable name '{}' in {}:{}".format(k, path[0], '.'.join(path[1:])))

        def _replace_dicts(current, *path):
            # type: (Any, *str) -> Any
            """
            Replaces all dictionaries under (and including) ``current`` with :py:class:`AttrDict`.
            An object is returned, to be used instead of ``current`` - it *may* be the same object,
            but it also may have been replaced with ``AttrDict`` instance (with the same content).

            :param current: object to start with.
            :param list(str) path: list of variable names as we walk the tree.
            """

            # If `current` is a dictionary, replace `current` itself by `AttrDict` instance with the same content,
            # and then walk through all its keys and values, and take care of lists and dictionaries.
            if isinstance(current, dict):
                _assert_var_names(current, *path)

                current = AttrDict(**current)

                for k, v in current.iteritems():
                    if not isinstance(v, (dict, list)):
                        continue

                    current[k] = _replace_dicts(v, *(list(path) + [k]))

            # For list, we don't have to replace the list itself, but we need to check its items.
            elif isinstance(current, list):
                for i, v in enumerate(current):
                    current[i] = _replace_dicts(v, *(list(path) + [str(i)]))

            # Return what we created. We "repaired" objects bellow `current`, and we put them into their
            # correct places in dictionaries and lists, an by returning `current` we make sure that if
            # we "repaired" `current` itself, it'd not be lost - our caller will put it into the correct
            # position in *its own* frame.
            return current

        for config in configs:
            new_variables = load_yaml(config, logger=self.logger)

            if not isinstance(new_variables, dict):
                raise GlueError('Cannot add variables from {}, not a key: value format'.format(config))

            new_variables = _replace_dicts(new_variables, config)

            variables.update(new_variables)

        return variables

    def user_variables(self, logger=None, context=None):
        # type: (Optional[gluetool.log.ContextAdapter], Optional[Dict[str, Any]]) -> Dict[str, Any]

        return self._render_user_variables(logger=logger, context=context)

    def evaluate_rules(self, rules, context=None):
        # type: (str, Optional[ContextType]) -> Any
        """
        Evaluate rules to a single value (usualy bool-ish - ``True``/``False``, (non-)empty string, etc.),
        within a context provided by the caller via ``context`` mapping.
        Keys and values in the mapping are passed to internal ``eval`` implementation, making them
        available to the rules.

        :param str rules: rules to evaluate.
        :param dict context: mapping of names and object caller wants to be available to rules.
        :returns: whatever comes out from rules evaluation.
        """

        def _enhance_strings(variables):
            # type: (ContextType) -> ContextType

            return {
                key: MatchableString(value) if isinstance(value, str) else value for key, value in variables.iteritems()
            }

        # If we don't have a context, get one from the core.
        if context is None:
            context = self.shared('eval_context')

        assert context is not None  # to make mypy happy
        custom_locals = _enhance_strings(context)

        # `EVAL_CONTEXT` cannot be `custom_locals` itself - that would be a circular reference.
        # it must be called first to return the context itself.
        custom_locals.update({
            'EVAL_CONTEXT': lambda: AttrDict(custom_locals),
            'ALL': all,
            'ANY': any,
            'EXISTS': lambda name: name in custom_locals
        })

        self.debug('rules: {}'.format(rules))
        log_dict(self.verbose, 'locals', custom_locals)

        result = Rules(rules).eval({}, custom_locals)

        log_dict(self.debug, 'eval result', result)

        return result

    def evaluate_filter(self, entries, context=None, default_rule='True',
                        stop_at_first_hit=False):
        # type: (List[EntryType], Optional[Union[ContextType, ContextGetterType]], str, bool) -> List[EntryType]
        """
        Find out what entries of the list are allowed by their rules, and return them.

        An entry is a simple dictionary with arbitrary keys. If there is a key named ``rule``, it
        is evaluated and when the result is false-ish, the entry does not make the cut. The list of
        entries that are allowed by their rules is returned.

        .. code-block:: yaml

           - rule: ...
             <key #1>: ...
             <key #2>: ...

        :param list(dict) entries: List of entries to filter.
        :param context: Provider of context for rules and templating services. Either a dictionary or a callable
            returning a dictionary. If callable is provided, it will be called before each entry to
            refresh the context.
        :param str default_rule: If there's no rule in the instruction, this will be used. For example, use ``False``
            to skip instructions without rules.
        :param bool stop_at_first_hit: If set, first entry whose rule evaluated true-ishly is returned immediately.
        :rtype: list(dict)
        :returns: List of entries that passed through the filter.
        """

        instruction_iterator = self._filter(
            entries, context=context, default_rule=default_rule, stop_at_first_hit=stop_at_first_hit
        )

        return [
            entry for entry, _ in instruction_iterator
        ]

    def evaluate_instructions(self,
                              instructions,  # type: List[EntryType]
                              commands,  # type: Dict[str, CommandCallbackType]
                              context=None,  # type: Optional[Union[ContextType, ContextGetterType]]
                              default_rule='True',  # type: str
                              stop_at_first_hit=False,  # type: bool
                              ignore_unhandled_commands=False  # type: bool
                             ):  # noqa
        # type: (...) -> None
        """
        Evaluate "instructions", using given callbacks to perform commands ordered by instructions.

        An instruction is a simple dictionary with arbitrary keys, "commands". If there is a key named ``rule``, it
        is evaluated and when the result is false-ish, the instruction is skipped.

        .. code-block:: yaml

           - rule:
             <command #1>: ...
             <command #2>: ...

        Instructions are inspected in order they are given by the caller, and unless denied by the optional rule,
        the instruction commands are looked up in the ``commands`` mapping, and found callbacks are called,
        with the current instruction, command, its value and a context rules-engine used to evaluate instruction
        rule as arguments.

        .. code-block:: yaml

           - rule: True
             log: some dummy message

        .. code-block:: python

           def foo(self, instruction, command, argument, context):
               self.info(argument)

           self.shared('evaluate_instructions', <instructions loaded from a file>, {'log': foo})

        ``foo`` callback will be called like this:

        .. code-block:: python

           foo(instruction, 'log', 'some dummy message', context_used_by_rules_engine)

        :param list(dict) instructions: List of instructions to follow.
        :param dict(str, callable(dict, str, object, dict)) commands: Mapping between command names and their
            callbacks.
        :param context: Provider of context for rules and templating services. Either a dictionary or a callable
            returning a dictionary. If callable is provided, it will be called before each instruction to
            refresh the context.
        :param str default_rule: If there's no rule in the instruction, this will be used. For example, use ``False``
            to skip instructions without rules.
        :param bool stop_at_first_hit: If set, first command callback returning ``True`` will cause the function
            to skip remaining commands and start with the next instruction.
        :param bool ignore_unhandled_commands: If set, commands without any callbacks will be ignored. otherwise,
            an exception will be raised.
        """

        # Oops, `stop_at_first_hit` means something different to this method than to `_filter` :/
        # `_filter`'s `stop_at_first_hit` cannot be expressed by parameters of this method,
        # therefore defaulting to `False`, letting `_filter` process all instructions.
        instruction_iterator = self._filter(
            instructions, context=context, default_rule=default_rule, stop_at_first_hit=False
        )

        for instruction, instruction_context in instruction_iterator:
            for command, argument in instruction.iteritems():
                if command == 'rule':
                    continue

                callback = commands.get(command, None)

                if not callback:
                    msg = "No callback for command '{}'".format(command)

                    if ignore_unhandled_commands:
                        self.warn(msg)
                        continue

                    raise GlueError(msg)

                result = callback(instruction, command, argument, instruction_context)

                if result is True and stop_at_first_hit:
                    self.debug('command handled and we should stop at first hit')
                    break

    def execute(self):
        # type: () -> None

        if not self.option('rules'):
            return

        self.info('rules evaluate to: {}'.format(self.evaluate_rules(self.option('rules'))))
