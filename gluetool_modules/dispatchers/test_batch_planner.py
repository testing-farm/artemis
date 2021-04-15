# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import re
import shlex

import gluetool
from gluetool import GlueError, SoftGlueError
from gluetool.log import format_dict, log_dict
from gluetool.utils import cached_property, load_yaml, PatternMap

# Type annotations
from typing import List, Tuple  # Ignore PyUnusedCodeBear


class CommandsError(SoftGlueError):
    """
    Base class of commands-related soft exceptions.

    :param str message: descriptive message, passed to parent Exception classes.
    :param obj commands: commands in question. Will be formatted and pasted into
      the template.
    """

    def __init__(self, message, commands):
        super(CommandsError, self).__init__(message)

        self.commands = commands


class NoFilteringRulesError(CommandsError):
    def __init__(self, name, commands):
        super(NoFilteringRulesError, self).__init__(
            "Command set '{}' does not contain any filtering rules".format(name),
            commands)


class UnexpectedConfigDataError(CommandsError):
    def __init__(self, commands):
        super(UnexpectedConfigDataError, self).__init__(
            'Unexpected command or structures found in config file',
            commands)


class TestBatchPlanner(gluetool.Module):
    """
    Provides different methods of finding out *what* jobs (and tests) should be started
    for a artifact. Allows use of multiple methods in sequence - when the first one is
    unable to find the answer, the next method in the list is used, and so on.

    Currently, these methods are provided:

    * ``static-config``: use a YAML file (set by ``--config`` option) to specify what jobs
      are supposed to be run for artifacts. Config sections are processed sequentially and
      only the first rule is triggered, therefore order of sections is important.

    * ``basic-static-config``: use a YAML file (set by ``--config`` option) to specify what jobs
      are supposed to be run. All entries with True-ish rule are triggered.

    * ``sti``: check if test/test.yaml is present in component repository. Jenkins job name
      is found in mapping file (set by ``--sti-job-map`` option).

    There is a possibility to ignore some of the methods according to a rules file passed
    via the ``--ignore-methods-map`` option. This is useful if you do not want to run some
    of the methods for some of the artifacts. The format of the rule file is as follows:

    .. code-block:: yaml

       ---

       - rule: PRIMARY_TASK.ARTIFACT_NAMESPACE == 'redhat-module' and PRIMARY_TASK.component == '389-ds'
         ignore-methods:
           - sti

    Where ``ignore-methods`` attribute contains a list of methods to be ignored.

    It is possible to tweak *priority* of each scheduled test, via ``--job-priority-map``:

    .. code-block:: yaml

       ---

       # Scratch builds shall run with lower priority, to vacate place for real builds (read: gating).
       - rule: PRIMARY_TASK.scratch is True
         set-priority: 4

    Instructions are evaluated for each command, with ``COMMAND`` variable representing the current command
    of the loop.

    The priority itself is of no concern to this module, it is just a number. It is not evaluated,
    that's up to that part of the infrastructure that actually executes the tests, to obey their priorities.
    """

    # Supported flags - keep them alphabetically sorted
    KNOWN_FLAGS = ('apply-all', 'options', 'recipients')

    name = 'test-batch-planner'
    description = 'Configurable test batch planner.'
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = {
        'default-job': {
            'help': 'The default job to use for triggering (default: %(default)s)',
            'default': 'openstack-job'
        },
        'methods': {
            'help': 'Comma-separated list of methods (default: none).',
            'metavar': 'METHOD',
            'action': 'append',
            'choices': ['basic-static-config', 'tmt', 'static-config', 'sti', 'sidetag'],
            'default': []
        },
        'config': {
            'help': 'Static configuration(s) for components (default: none).',
            'action': 'append',
            'default': []
        },
        'sidetag-jobs': {
            'help': """
                    List of jobs supporting sidetags, for which the module adds/modifies
                    ``--build-dependencies-options`` (default: none).
                    """,
            'metavar': 'JOB',
            'default': []
        },
        'sti-job-map': {
            'help': 'Path to a file with ``ARTIFACT_NAMESPACE`` => ``<jenkins_job_name>`` patterns.',
            'metavar': 'FILE'
        },
        'tmt-job-map': {
            'help': 'Path to a file with ``ARTIFACT_NAMESPACE`` => ``<jenkins_job_name>`` patterns.',
            'metavar': 'FILE'
        },
        'job-result-type': {
            'help': 'List of comma-separated pairs <job>:<result type> (default: none).',
            'action': 'append',
            'default': []
        },
        'ignore-methods-map': {
            'help': 'Additional rules for ignoring specific methods.',
            'metavar': 'FILE'
        },
        'job-priority-map': {
            'help': 'Rules for setting priorities of tests.',
            'metavar': 'FILE'
        }
    }

    required_options = ('methods',)

    shared_functions = ('plan_test_batch',)

    @cached_property
    def job_result_types(self):
        # we accept multiple --job-result-type options, and when set in config
        # file, one can have multiple pairs...

        mapping = {}

        value = self.option('job-result-type')

        if isinstance(value, str):
            value = [value]

        for entry in value:
            for pair in entry.strip().split(','):
                job, result_type = pair.strip().split(':')

                job = job.strip()
                result_type = result_type.strip()

                mapping[job] = result_type
                self.debug("job '{}' provides results of type '{}'".format(job, result_type))

        return mapping

    @cached_property
    def configs(self):
        # type: () -> List[str]

        return gluetool.utils.normalize_multistring_option(self.option('config'))

    @cached_property
    def _ignore_methods_map(self):
        if not self.option('ignore-methods-map'):
            return []

        return load_yaml(self.option('ignore-methods-map'), logger=self.logger)

    @cached_property
    def _job_priority_map(self):
        if not self.option('job-priority-map'):
            return []

        return load_yaml(self.option('job-priority-map'), logger=self.logger)

    def _reduce_section(self, commands, is_component=True, default_commands=None, all_commands=None):
        """
        Reduce commands to a minimal set - apply filtering rules, apply global sections,
        and return set of command sets.
        """

        self.debug('reduce section:\n{}'.format(format_dict(commands)))

        all_commands = all_commands or []
        default_commands = default_commands or []

        reduced = {}

        def _default_flags():
            return {
                'apply-all': None,
                'recipients': None,
                'options': None
            }

        section_flags = _default_flags()

        def _add_command_set(name, set_commands):
            self.debug("    adding command set '{}', with commands:\n{}".format(name, format_dict(set_commands)))

            if not set_commands:
                if is_component is True:
                    # there is nothing in this command set, not even flag telling us
                    # to avoid "all" commands, therefore add just them
                    self.debug('      empty command set, using only "all" commands')
                    reduced[name] = all_commands[:]

                else:
                    # command sets in global sections are simply empty
                    self.debug('      empty command set')
                    reduced[name] = []

                return

            # cannot use section_flags.copy() because section_flags might be an ordered dict,
            # and copy into unordered leads to an exception - we don't care about ordering,
            # we can ignore it.
            set_flags = {key: value for key, value in section_flags.iteritems()}

            if is_component is True:
                if isinstance(set_commands[0], dict):
                    log_dict(self.debug, 'set flags', set_commands[0])

                    set_flags.update(set_commands[0])
                    del set_commands[0]

                for flag in set_flags.iterkeys():
                    if flag in TestBatchPlanner.KNOWN_FLAGS:
                        continue

                    self.warn("Flag '{}' is not supported (typo maybe?)".format(flag), sentry=True)

                self.debug('final set flags:\n{}'.format(format_dict(set_flags)))

                if set_flags.get('options', None):
                    options = set_flags['options']

                    self.debug('set-wide options set to:\n{}'.format(format_dict(options)))

                    for i, command in enumerate(set_commands):
                        self.debug('adding set-wide options to command: {}'.format(command))

                        command = '{} {}'.format(command, options)

                        self.debug('with set options applied: {}'.format(command))

                        set_commands[i] = command

                if set_flags.get('apply-all', True) is not False:
                    self.debug("      allows 'all' section to be appended")
                    set_commands = set_commands[:] + all_commands

            if set_flags.get('recipients', None) is not None:
                self.debug('set-wide recipients set to: {}'.format(set_flags['recipients']))

                # if `recipients` are specified as a string, split it into recipients,
                # don't bother with strip, it's done later.
                if isinstance(set_flags['recipients'], str):
                    raw_recipients = set_flags['recipients'].split(',')

                # if `recipients` is a list, we're pretty much done
                elif isinstance(set_flags['recipients'], list):
                    raw_recipients = set_flags['recipients']

                else:
                    raise GlueError('Recipients specified in a wrong format: {}'.format(set_flags['recipients']))

                # Strip each recipient and join them into a single string we can pass down to other modules
                # via some command-line option, i.e. commas and no spaces. Ugly.
                recipients = ','.join([s.strip() for s in raw_recipients])

                for i, command in enumerate(set_commands):
                    command = command.strip()

                    self.debug("command: '{}'".format(command))

                    for job, result_type in self.job_result_types.iteritems():
                        if not command.startswith(job):
                            continue

                        command = '{} --notify-recipients-options="--{}-add-notify {}"'.format(command, result_type,
                                                                                               recipients)
                        self.debug("with set recipients applied: '{}'".format(command))

                        set_commands[i] = command
                        break

                    else:
                        self.warn("Cannot add recipients to '{}' pipeline".format(command), sentry=True)

            reduced[name] = set_commands[:]

        if commands is None:
            # No tests in this section
            self.debug('  section contains no commands')

            if is_component is True:
                return {
                    'default': default_commands[:]
                }

            return {
                'default': []
            }

        if isinstance(commands, list):
            # foo:
            #   - flag1: foo
            #     flag2: bar
            #   - command1
            #   - command2
            #
            # Simply add commands as a "default" set.

            _add_command_set('default', commands)
            return reduced

        if isinstance(commands, dict):
            # Now it gets complicated:
            #
            # foo:
            #   extra-testing:
            #     - rules
            #     - command1
            #     - command2
            #   extra-special-testing:
            #     - rules
            #     - flag1: foo
            #       flag2: bar
            #     - command3
            #     - command4
            #   default:
            #     - command5

            if 'flags' in commands:
                section_flags = commands['flags']
                del commands['flags']

            else:
                section_flags = _default_flags()

            log_dict(self.debug, 'section flags', section_flags)

            for set_name, set_commands in commands.iteritems():
                self.debug('  checking command set {}'.format(set_name))

                if set_name == 'default':
                    # no rules
                    _add_command_set('default', set_commands)
                    continue

                if set_commands is None or len(set_commands) < 2:
                    raise NoFilteringRulesError(set_name, set_commands)

                if not self.shared('evaluate_rules', set_commands[0], context=self.shared('eval_context')):
                    self.debug('    denied by rules')
                    continue

                del set_commands[0]

                self.debug('    allowed by rules')
                _add_command_set(set_name, set_commands)

            if 'default' in reduced and len(reduced) > 1:
                self.debug('  there are other sections, not just "default" - remove it')
                del reduced['default']

            return reduced

        raise UnexpectedConfigDataError(commands)

    def _construct_command_sets(self, config, component):
        """
        Preprocess configuration for given component, and create a pile of
        "command sets". Each set has a name and list of commands, and can carry
        filtering rules.

        Returns a dictionary, where keys are set names and values are list of commands.

        .. code-block:: python

           {
               'default': [cmd1, cmd2],
               'foo': [cmd3, cmd4]
           }

        Commands listed in "all" section of the config file are added to every command
        set.

        Commands listed in "default" section of the config file are used when there is
        not specific configuration for the component.

        ;param dict config: config file.
        :param str component: component name.
        """

        self.debug("construct command sets for component '{}'".format(component))

        def _reduce_global_section(name):
            self.debug('reducing "{}" section'.format(name))

            commands = self._reduce_section(config.get(name, []), is_component=False)

            if commands is None:
                self.debug('  empty section, empty list')

                return []

            if len(commands) > 1:
                raise GlueError('Top-level section {} must reduce to a single command set'.format(name))

            self.debug('reduced to:\n{}'.format(format_dict(commands)))
            return commands.values()[0]

        global_all_commands = _reduce_global_section('all')
        self.debug('global "all" commands:\n{}'.format(format_dict(global_all_commands)))

        global_default_commands = _reduce_global_section('default')
        self.debug('global "default" commands:\n{}'.format(format_dict(global_default_commands)))

        packages_config = config.get('packages', None)
        if packages_config is None:
            # either there's no key "packages", or it's empty
            packages_config = {}

        component_commands = None

        for pattern, commands in packages_config.iteritems():
            self.debug("component: '{}', pattern: '{}'".format(component, pattern))

            try:
                match = re.match('^(?:{})$'.format(pattern), component)

                if match is None:
                    continue

                if match.group() != component:
                    self.debug("match '{}' is not equal to component '{}'".format(match.group(), component))
                    continue

            except re.error as exc:
                raise GlueError("Cannot compile regexp pattern '{}': {}".format(pattern, str(exc)))

            if component_commands:
                raise GlueError("Multiple patterns matching component name '{}'".format(component))

            self.debug('  match!')
            component_commands = commands

        return self._reduce_section(component_commands,
                                    all_commands=global_all_commands,
                                    default_commands=global_default_commands)

    def _plan_by_sidetag(self):
        self.require_shared('trigger_message')

        message = self.shared('trigger_message')

        try:
            builds = message['artifact']['builds']

        except TypeError:
            self.warn('Trigger message is empty, skipping sidetag', sentry=True)
            return []

        except KeyError as error:
            self.warn("Could not find builds in trigger message, skipping sidetag: '{}'".format(error), sentry=True)
            return []

        final_commands = []

        for build in builds:
            # initialize primary_task
            tasks = self.shared('tasks', nvrs=[build['nvr']])

            if not tasks:
                raise GlueError("Could not find build '{}'".format(build['nvr']))

            # companions are all other builds
            companion_nvrs = [companion['nvr'] for companion in builds if companion['nvr'] != build['nvr']]

            # call _plan_by_static_config to plan normal execition
            final_commands.extend(self._plan_by_static_config(companion_nvrs=companion_nvrs))

        return final_commands

    def _plan_by_static_config(self, companion_nvrs=None):
        self.require_shared('evaluate_rules', 'eval_context')

        if not self.configs:
            self.warn('Empty dispatcher configuration')

        task = self.shared('primary_task')

        final_commands = []

        context = self.shared('eval_context')

        def _modify_build_dependecies(args):
            # modify existing --build-dependecies-options
            if not any(['--build-dependencies-options' in arg for arg in args]):

                self.debug('added new build dependencies')

                nvrs = ','.join(companion_nvrs)

                args.append(
                    '--build-dependencies-options=--method=companions-from-koji --companions-nvr={}'.format(nvrs)
                )

            else:
                # modify build dependencies with --companions-nvr option
                args = [_alter_companions_nvr(arg) for arg in args]

            return args

        def _alter_companions_nvr(arg):
            # not an option we are interested in, just return it
            if '--build-dependencies-options' not in arg:
                return arg

            # create companion-nvrs option
            nvrs = '--companions-nvr={}'.format(','.join(companion_nvrs))

            # add to existing option
            if '--companions-nvr' in arg:
                self.debug('modified existing --companions-nvr')
                return re.sub('--companions-nvr[= ]*', '{},'.format(nvrs), arg)

            # add new option
            self.debug('added new --companions-nvr')

            return '{} {}'.format(arg, nvrs)

        for config_filepath in self.configs:
            config = load_yaml(config_filepath, logger=self.logger)

            self.debug('find out which config section we should use')

            matching_section = None

            for section in config:
                if 'rule' not in section:
                    self.warn("Section does not contain 'rule' key, ignored", sentry=True)
                    continue

                if not self.shared('evaluate_rules', section['rule'],
                                   context=self.shared('eval_context')):
                    self.debug('denied by rules')
                    continue

                matching_section = section
                break

            else:
                self.warn('Cannot select any section, no rules matched current environment')
                continue

            # Find command sets for the component
            commands = self._construct_command_sets(matching_section, task.component_id)
            log_dict(self.debug, 'commands', commands)

            for set_name, set_commands in commands.iteritems():
                commands_desc = '\n'.join(['  {}'.format(command) for command in set_commands])
                self.info("Set '{}':\n{}".format(set_name, commands_desc))

                for command in set_commands:
                    module = shlex.split(command)[0]
                    args = shlex.split(command)[1:]

                    self.debug("module='{}', args='{}'".format(module, args))

                    # Render command arguments
                    args = [
                        gluetool.utils.render_template(arg, logger=self.logger, **context)
                        for arg in args
                    ]

                    self.debug("module='{}', rendered args='{}'".format(module, args))

                    # Modify companions if needed
                    if companion_nvrs and module in self._sidetag_jobs:
                        args = _modify_build_dependecies(args)

                    # Add required artifact ID
                    args.insert(0, '--artifact-id={}'.format(task.dispatch_id))

                    final_commands.append((module, args))

        return final_commands

    def _plan_by_basic_static_config(self):
        self.require_shared('evaluate_filter')

        task = self.shared('primary_task')
        context = self.shared('eval_context')

        if not self.configs:
            self.warn('Empty dispatcher configuration')

        final_commands = []

        for config_filepath in self.configs:
            config = load_yaml(config_filepath, logger=self.logger)

            for item in self.shared('evaluate_filter', config):

                module = item['module']
                args = item['args'] if item['args'] else []

                # Render command arguments
                args = [
                    gluetool.utils.render_template(arg, logger=self.logger, **context)
                    for arg in args
                ]

                # Add required artifact ID if it is not already defined
                if not any([arg for arg in args if '--artifact-id' in arg]):
                    args.insert(0, '--artifact-id={}'.format(task.dispatch_id))

                self.info("module='{}', args='{}'".format(module, args))
                final_commands.append((module, args))

        return final_commands

    @cached_property
    def sti_job_map(self):
        return PatternMap(self.option('sti-job-map'), logger=self.logger)

    @cached_property
    def tmt_job_map(self):
        return PatternMap(self.option('tmt-job-map'), logger=self.logger)

    def _plan_by_sti(self):
        self.require_shared('dist_git_repository')

        task = self.shared('primary_task')
        job_name = self.sti_job_map.match(task.ARTIFACT_NAMESPACE)

        # Construct URL to the dist-git repository of the component
        repository = self.shared('dist_git_repository')

        if repository.has_sti_tests:
            # Note that we currently support only Openstack
            return [(
                self.option('default-job'),
                [
                    '--artifact-id={}'.format(task.dispatch_id),
                    '--job-name', job_name
                ]
            )]

        return []

    def _plan_by_tmt(self):
        # type: () -> List[Tuple[str, List[str]]]

        self.require_shared('dist_git_repository')

        distgit_repo = self.shared('dist_git_repository')

        if not distgit_repo.has_ci_config:
            return []

        task = self.shared('primary_task')
        job_name = self.tmt_job_map.match(task.ARTIFACT_NAMESPACE)

        return [(
            self.option('default-job'),
            [
                '--artifact-id={}'.format(task.dispatch_id),
                '--job-name', job_name
            ]
        )]

    def _get_ignored_methods(self):
        ignored_methods = []

        def _add_ignore_methods(instruction, command, argument, context):
            if not isinstance(argument, list):
                raise GlueError('ignore-methods MUST be a list.')

            ignored_methods.extend(argument)

        self.shared('evaluate_instructions', self._ignore_methods_map, {
            'ignore-methods': _add_ignore_methods
        })

        # note: duplicates are OK
        return ignored_methods

    def plan_test_batch(self):
        """
        Returns list of modules and their options. These modules implement testing process
        of given artifact.

        Return this kind of structure:

        .. code-block:: python

           [
               ( module1, [--option1, --option2, ...] ),
               ( module2, [--option3, --option4, ...] ),
               ...
           ]

        :rtype: list(tuple)
        """

        self.require_shared('primary_task')

        test_batch = []

        ignored_methods = self._get_ignored_methods()

        for method in self._methods:
            if method in ignored_methods:
                self.warn("Ignoring method '{}' due to ignore rules".format(method))
                continue

            self.debug("Plan test batch using '{}' method".format(method))

            method_test_batch = self._planners[method]()

            if not method_test_batch:
                self.info("Method '{}' provided no tests, moving on".format(method))
                continue

            test_batch += method_test_batch

        # Apply priorities where necessary
        for i, batch_command in enumerate(test_batch):
            def _set_priority(instruction, command, argument, context):
                try:
                    priority = int(argument)

                except ValueError as exc:
                    raise GlueError('Command priority must be an integer: {}'.format(exc))

                batch_command[1].append('--priority={}'.format(priority))

                self.debug('command #{}: priority set to {}'.format(i, priority))

            context = gluetool.utils.dict_update(
                self.shared('eval_context'),
                {
                    'COMMAND': batch_command
                }
            )

            self.shared('evaluate_instructions', self._job_priority_map, {
                'set-priority': _set_priority
            }, context=context)

        return test_batch

    def sanity(self):
        self._planners = {
            'basic-static-config': self._plan_by_basic_static_config,
            'tmt': self._plan_by_tmt,
            'sidetag': self._plan_by_sidetag,
            'static-config': self._plan_by_static_config,
            'sti': self._plan_by_sti
        }

        self._methods = gluetool.utils.normalize_multistring_option(self.option('methods'))
        self._sidetag_jobs = gluetool.utils.normalize_multistring_option(self.option('sidetag-jobs'))

        if 'static-config' in self._methods and 'basic-static-config' in self._methods:
            raise gluetool.utils.IncompatibleOptionsError(
                self,
                "methods 'basic-static-config' and 'static-config' cannot be used together"
            )

        if 'sidetag' in self._methods and not self._sidetag_jobs:
            raise gluetool.utils.IncompatibleOptionsError("--sidetag-jobs option is required with method 'sidetag'")

        for method in self._methods:
            if method not in self._planners:
                raise GlueError("Unknown method '{}'".format(method))

            if method == 'static-config' and not self.option('config'):
                raise gluetool.utils.IncompatibleOptionsError(
                    "--config option is required with method 'static-config'"
                )

            if method == 'basic-static-config' and not self.option('config'):
                raise gluetool.utils.IncompatibleOptionsError(
                    "--config option is required with method 'basic-static-config'"
                )

            if method == 'sti' and not self.option('sti-job-map'):
                raise gluetool.utils.IncompatibleOptionsError(
                    "--sti-job-map option is required with method 'sti'"
                )

            if method == 'tmt' and not self.option('tmt-job-map'):
                raise gluetool.utils.IncompatibleOptionsError(
                    "--tmt-job-map option is required with method 'tmt'"
                )
