# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import shlex

import gluetool
from gluetool.utils import cached_property, normalize_multistring_option

# Type annotations
# pylint: disable=unused-import,wrong-import-order
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, TYPE_CHECKING  # noqa

# Mixins need a bit special handling to make typing understand what the heck is this
# https://github.com/python/mypy/issues/5837#issuecomment-433284818
if TYPE_CHECKING:
    _Base = gluetool.Module
else:
    _Base = object


class DispatchJenkinsJobMixin(_Base):
    """
    Base class providing common functionality to modules whose only goal is to accept
    options (from command-line or environment), and dispatch specific Jenkins job for
    a given task.

    This class brings only pieces relevant to its purpose, it's up to its children to
    be based not just on this mixin class but on the :py:class:`gluetool.glue.Module` as well.

    .. note::

       Value of the ``id`` parameter is read from the shared function ``primary_task``.

    .. note::

       This module dispatches a Jenkins job, therefore it requires other module to provide connection
       to a Jenkins instance via the shared function ``jenkins``.
    """

    # pylint: disable=unused-variable
    job_name = None  # type: str
    """Name of the Jenkins job this module dispatches."""
    supported_dryrun_level = gluetool.glue.DryRunLevels.ISOLATED

    options = {
        'artifact-id': {
            'help': 'Artifact ID'
        },
        'testing-thread-id': {
            'help': 'Testing thread ID'
        },
        'job-name': {
            'help': 'Jenkins job name. Use this option to override the default name.'
        },
        'pipeline-prepend': {
            'help': '``citool`` options that will be added at the beginning of the pipeline.'
        },
        'pipeline-append': {
            'help': '``citool`` options that will be added at the end of the pipeline.'
        },
        'notify-recipients-options': {
            'help': 'Additional options for ``notify-recipients`` module. (default: none)',
            'action': 'append',
            'default': []
        },
        'recipients': {
            'help': 'List of notification recipients (default: none).',
            'metavar': 'NAME[,NAME...]',
            'action': 'append',
            'default': []
        },
        'notify-email-options': {
            'help': 'Additional options for ``notify-email`` module.'
        },
        'timeout-duration': {
            'help': 'Kill the pipeline when this many seconds elapsed.'
        },
        'priority': {
            'help': 'Priority of dispatched build (default: %(default)s).',
            'type': int,
            'default': None
        },

        # Options for pipeline-state-reporter module
        'pipeline-state-reporter-options': {
            'help': 'Additional options for ``pipeline-state-reporter`` module.'
        },
        'test-category': {
            'help': """
                    Category of tests performed in this pipeline, e.g. ``static-analysis`` or ``functional``.
                    """
        },
        'test-type': {
            'help': """
                    Type of tests provided in this pipeline, e.g. ``tier1``, ``rpmdiff-analysis`` or ``covscan``.
                    """
        }
    }

    required_options = ('artifact-id',)

    @cached_property
    def build_params(self):
        # type: () -> Dict[str, Any]
        """
        Converts command-line options - and possibly other sources as well - to a build parameters, a dictionary
        that's passed to Jenkins, listing keys and values which form parameters of the triggered Jenkins build.

        :rtype: dict
        """

        # Gather all options for `notify-recipients` module
        notify_recipients_options_list = []  # type: List[str]
        notify_recipients_options = None  # type: Optional[str]

        if self.option('notify-recipients-options'):
            notify_recipients_options_list += self.option('notify-recipients-options')

        recipients = normalize_multistring_option(self.option('recipients'))
        if recipients:
            notify_recipients_options_list += [
                '--recipients={}'.format(recipient) for recipient in recipients
            ]

        if notify_recipients_options_list:
            notify_recipients_options = ' '.join(notify_recipients_options_list)

        else:
            notify_recipients_options = None

        # Gather all options for `pipeline-state-reporter` module
        pipeline_state_reporter_options_list = []  # type: List[str]
        pipeline_state_reporter_options = None  # type: Optional[str]

        if self.option('pipeline-state-reporter-options'):
            pipeline_state_reporter_options_list += shlex.split(self.option('pipeline-state-reporter-options'))

        if self.option('test-category'):
            pipeline_state_reporter_options_list += ['--test-category={}'.format(self.option('test-category'))]

        if self.option('test-type'):
            pipeline_state_reporter_options_list += ['--test-type={}'.format(self.option('test-type'))]

        if pipeline_state_reporter_options_list:
            pipeline_state_reporter_options = ' '.join(pipeline_state_reporter_options_list)

        else:
            pipeline_state_reporter_options = None

        return {
            'testing_thread_id': self.option('testing-thread-id'),
            'artifact_id': self.option('artifact-id'),
            'pipeline_prepend': self.option('pipeline-prepend'),
            'pipeline_append': self.option('pipeline-append'),
            'pipeline_state_reporter_options': pipeline_state_reporter_options,
            'notify_recipients_options': notify_recipients_options,
            'notify_email_options': self.option('notify-email-options'),
            'timeout_duration': self.option('timeout-duration'),
            'priority': self.option('priority')
        }

    def execute(self):
        # type: () -> None

        job_name = self.option('job-name') if self.option('job-name') else self.job_name

        self.require_shared('jenkins')

        self.shared('jenkins').invoke_job(job_name, self.build_params)
