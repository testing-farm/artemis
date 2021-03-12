import re

import gluetool
from gluetool.log import log_dict
from gluetool.utils import cached_property


class TaskDispatcher(gluetool.Module):
    """
    A generic task dispatcher. It asks other modules - via ``plan_test_batch``
    shared function - for modules and their arguments, and than runs them.
    """

    name = 'task-dispatcher'
    description = 'Configurable task dispatcher'
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = {
        'pipeline-test-categories': {
            'help': """
                    Mapping between jobs and their default test category, as reported later by
                    ``pipeline-state-reporter`` module (default: %(default)s).
                    """,
            'type': str,
            'default': None
        },
        'pipeline-test-types': {
            'help': """
                    Mapping between jobs and their default test type, as reported later by
                    ``pipeline-state-reporter`` module (default: %(default)s).
                    """,
            'type': str,
            'default': None
        },
        'pipeline-test-bus-topic': {
            'help': 'Topic to use for messages sent for dispatched jobs (default: %(default)s).',
            'type': str,
            'default': None
        }
    }

    def __init__(self, *args, **kwargs):
        super(TaskDispatcher, self).__init__(*args, **kwargs)

        self.build = {}

        self._thread_id = None
        self._subthread_counter = 0
        self._child_thread_id = None

    @cached_property
    def pipeline_test_categories(self):
        if not self.option('pipeline-test-categories'):
            return None

        return gluetool.utils.SimplePatternMap(self.option('pipeline-test-categories'), logger=self.logger)

    @cached_property
    def pipeline_test_types(self):
        if not self.option('pipeline-test-types'):
            return None

        return gluetool.utils.SimplePatternMap(self.option('pipeline-test-types'), logger=self.logger)

    def execute(self):
        """
        Dispatch tests for a component. Ask for what modules should be called, and their options,
        and run them.
        """

        self.require_shared('plan_test_batch')

        batch = self.shared('plan_test_batch')
        log_dict(self.debug, 'prepared test batch', batch)

        if self.has_shared('thread_id'):
            self._thread_id = self.shared('thread_id')

        def _find_test_property(module, args, test_property, mapping):
            joined_args = ' '.join(args)

            log_dict(self.debug, "find test property '{}' for job".format(test_property), args)

            match = re.search(
                r'--test-{}(?:\s+|=)([\w-]+)'.format(test_property),
                joined_args
            )

            if match:
                self.debug("  test property is '{}'".format(match.group(1)))

                return match.group(1).strip()

            if mapping is None:
                self.debug('  test property not found, and there is no mapping')

                return 'unknown'

            full_command = [module] + args

            try:
                # try to match our command with an entry from the mapping, to get what
                # configurator thinks would be an appropriate default value for such command
                ret = mapping.match(' '.join(full_command))

                self.debug("  test property found in mapping: '{}'".format(ret))

                return ret

            except gluetool.GlueError:
                self.warn(
                    'Cannot find a test property {} for job:\n{}'.format(
                        test_property,
                        gluetool.log.format_dict(full_command)
                    ),
                    sentry=True
                )

                return 'unknown'

        for module, args in batch:
            if self._thread_id is not None:
                self._subthread_counter += 1

                self._child_thread_id = '{}-{}'.format(self._thread_id, self._subthread_counter)
                args = ['--testing-thread-id', self._child_thread_id] + args

                log_dict(self.debug, 'augmented args with thread-id', args)

            if self.has_shared('report_pipeline_state'):
                # finding the correct test category and type might be tricky
                test_category, test_type = 'unknown', 'unknown'

                test_category = _find_test_property(module, args, 'category', self.pipeline_test_categories)
                test_type = _find_test_property(module, args, 'type', self.pipeline_test_types)

                self.shared('report_pipeline_state', 'queued', thread_id=self._child_thread_id,
                            topic=self.option('pipeline-test-bus-topic'),
                            test_category=test_category, test_type=test_type)

            log_dict(self.debug, 'command to dispatch', [module, args])
            self.info('    {} {}'.format(module, ' '.join(args)))

            self.run_module(module, args)
