# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Sends pipeline messages as specified in draft.

https://docs.google.com/document/d/16L5odC-B4L6iwb9dp8Ry0Xk5Sc49h9KvTHrG86fdfQM/edit?ts=5a2af73c
"""

import argparse
import base64
import datetime
import zlib

import bs4
import gluetool
from gluetool.log import log_dict
from gluetool.utils import render_template, normalize_bool_option
import gluetool_modules.libs

from typing import Any, List, Optional, Dict, Tuple, Union, cast  # noqa


STATE_QUEUED = 'queued'
STATE_RUNNING = 'running'
STATE_COMPLETE = 'complete'
STATE_ERROR = 'error'


class PipelineStateReporter(gluetool.Module):
    """
    Sends messages reporting the pipeline state.

    The module sends two messages:

        * the first when the module is executed, reporting the pipeline just started. Depending
          on the module position in the pipeline, there were definitely actions taken before sending
          this message.
          This message can be disabled by ``--dont-report-running`` option.

        * the second message is sent when the pipeline is being destroyed. it can contain information
          about the error causing pipeline to crash, or export testing results.


    **Artifact details**

    Provided via ``--artifact-map`` option. Supports rules and their evaluation.

    .. code-block:: yaml

       ---

       # no "rule" key defaults to ``True``, meaning "always apply"
       - artifact-details:
           type: "{{ ARTIFACT_TYPE }}"

       - rule: ARTIFACT_TYPE == 'foo'
         artifact-details:
           id: "{{ PRIMARY_TASK.id }}"
           component: "{{ PRIMARY_TASK.component }}"
           issuer: "{{ PRIMARY_TASK.issuer }}"

       # Some details may be required to have different type, then use ``eval-as-rule: true`` flag
       # whose default is ``false``. Artifact details are then evaluated the same way rules are,
       # yielding possibly other data types than just string.
       - eval-as-rule: true
         artifact-details:
           branch: PRIMARY_TASK.branch or None  # string or None
           scratch: PRIMARY_TASK.scratch  # boolean

    **Final pipeline state**

    Provided via ``--final-state-map`` option, a mapping is used to determine the final state of the pipeline. By
    default, when exception was raised and failure is being handled, the final result is supposed to be ``error``,
    but on some occasions user might want to "whitelist" some of the errors.

    Rules are optional, with ``True`` being the default (i.e. no rule means the instruction applies always). The
    first instruction allowed by its rules wins, no other instructions are inspected.

    If there is no instruction map or no rule matched, the final state is determined easily - if there was an
    exception, it's ``error``, ``complete`` otherwise.

    Besides the common evaluation context, a ``FAILURE`` variable is available, representing
    the failure - if any - being the cause of the pipeline doom. If there was no failure, the
    variable is set to ``None``.

    .. code-block:: yaml

       ---

       # If there is a failure, and it's an exception we want to pretend like nothing happened, set the state.
       - rule: FAILURE and FAILURE.exc_info and FAILURE.exc_info[0].__name__ in ('ThisIsFineError',)
         state: complete

       # If there is a soft failure, pretend like nothing happened.
       - rule: FAILURE and FAILURE.soft
         state: complete

       # Final "catch the rest" instruction to set "complete" is not necessary
       # - state: complete

    **Reason of failure**

    If pipeline failed, the ``reason`` value in the message is filled with an error message or a custom message
    provided by error-reason mapping. The ``note`` value in the message is filled with the same data, if it wasn't
    filled by ``--note`` option. This allows to show the error message to users in the CI dashboard.

    """

    name = 'pipeline-state-reporter'
    description = 'Sends messages reporting the pipeline state.'
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = [
        ('CI team options', {
            'contact-name': {
                'help': "Human-readable name of the CI system, e.g. 'BaseOS CI'.",
            },
            'contact-team': {
                'help': "Human-readable name of the team running the testing, e.g. 'BaseOS QE'."
            },
            'contact-url': {
                'help': 'URL of the CI system.'
            },
            'contact-email': {
                'help': 'Team or CI system contact e-mail.'
            },
            'contact-irc': {
                'help': 'Team or CI system IRC channel.'
            },
            'contact-docs': {
                'help': 'URL of documentation of the CI system.'
            }
        }),
        ('PR options', {
            'pr-label': {
                'help': """
                        Label identifying PR status. If specified, status will be reported using 'set_pr_status'
                        shared function.
                        """
            }
        }),
        ('Test options', {
            'test-category': {
                'help': """
                        Category of tests performed in this pipeline. One of 'static-analysis', 'functional',
                        'integration' or 'validation'.
                        """,
                'choices': ['static-analysis', 'functional', 'integration', 'validation']
            },
            'test-docs': {
                'help': """
                        URL to the test documentation. By default the this field is set via mapping file
                        specified by `--test-docs-map`` option. By specifying this option you override
                        the mapping file value.
                        """,
            },
            'test-namespace': {
                'help':
                    """
                    Prefix to be used when constructing result testcase name in ResultsDB. The name is rendered
                    with these context variables available:

                        PRIMARY_TASK - object with ``primary_task`` shared function if available, None otherwise
                    """
            },
            'test-type': {
                'help': "Type of tests provided in this pipeline, e.g. 'tier1', 'rpmdiff-analysis' or 'covscan'."
            }
        }),
        ('Mapping options', {
            'artifact-map': {
                'help': 'File with description of items provided as artifact info.'
            },
            'test-docs-map': {
                'help':
                    """
                    Rules file to decide the link to the documentation of the test, i.e. content of
                    `test.docs <https://pagure.io/fedora-ci/messages/blob/master/f/schemas/test-common.yaml>`_
                    field.
                    """
            },
            'run-map': {
                'help': 'File with description of items provided as run info.'
            },
            'final-overall-result-map': {
                'help': 'Instructions to decide the final overall result of the pipeline.'
            },
            'final-state-map': {
                'help': 'Instructions to decide the final state of the pipeline.'
            },
            'error-reason-map': {
                'help': 'Instructions to decide the error reason. By default the error message from the pipline.'
            }
        }),
        ('Tweaks', {
            'label': {
                'help': 'Custom pipeline label, distinguishing the pipelines of the same type (default: %(default)s).',
                'default': None
            },
            'note': {
                'help': 'Custom, arbitrary note or comment (default: %(default)s).',
                'default': None
            },
            'version': {
                'help': 'Current version of emitted messages (default: %(default)s).',
                'default': None
            },
            'pipeline-name': {
                'help': 'A human readable name of the pipeline.'
            }
        }),
        ('General options', {
            'dont-report-running': {
                'help': "Do not send out a 'running' message automatically (default: %(default)s).",
                'action': 'store_true',
                'default': 'no'
            },
            'bus-topic': {
                'help': 'Topic of the messages sent to the message bus.'
            }
        })
    ]

    required_options = (
        'contact-name', 'contact-team', 'contact-url', 'contact-email', 'contact-irc', 'contact-docs',
        'bus-topic',
        'test-namespace')

    shared_functions = ['report_pipeline_state']

    @property
    def eval_context(self):
        # type: () -> Dict[str, Optional[str]]
        __content__ = {  # noqa
            'PIPELINE_TEST_TYPE': """
                                  Type of tests provided in this pipeline, e.g. ``tier1``, ``rpmdiff-analysis``,
                                  ``covscan``, or any other string. The value of this variable is taken from the
                                  ``test-type`` option.
                                  """,
            'PIPELINE_TEST_CATEGORY': """
                                      Category of tests performed in this pipeline. See ``test-category`` option.
                                      """,
            'PIPELINE_TEST_DOCS': """
                                  Link to the documentation of the test. See ``test-docs`` and ``test-docs-map``
                                  options.
                                  """,
            'PIPELINE_TEST_NAMESPACE': """
                                       Test namespace (i.e. prefix) used when constructing ResultsDB testcase name.
                                       See ``test-namespace`` option.
                                       """,
            'PIPELINE_LABEL': """
                              Pipeline label - arbitrary string specified by the user to better distinguish this
                              pipeline from other pipelines taking care of the artifact. See ``--label`` option.
                              """
        }

        context = {
            # common for all artifact providers
            'PIPELINE_TEST_TYPE': self.option('test-type'),
            'PIPELINE_TEST_CATEGORY': self.option('test-category'),
            'PIPELINE_TEST_DOCS': None,
            'PIPELINE_TEST_NAMESPACE': None,
            'PIPELINE_LABEL': self.option('label')
        }

        if not gluetool_modules.libs.is_recursion(__file__, 'eval_context'):
            context.update({
                'PIPELINE_TEST_DOCS': self._get_test_docs(),
                'PIPELINE_TEST_NAMESPACE': self._get_test_namespace()
            })

        return context

    @gluetool.utils.cached_property
    def artifact_map(self):
        # type: () -> Any
        if not self.option('artifact-map'):
            return []

        return gluetool.utils.load_yaml(self.option('artifact-map'), logger=self.logger)

    @gluetool.utils.cached_property
    def error_reason_map(self):
        # type: () -> Any
        if not self.option('error-reason-map'):
            return []

        return gluetool.utils.load_yaml(self.option('error-reason-map'), logger=self.logger)

    @gluetool.utils.cached_property
    def test_docs_map(self):
        # type: () -> Any
        if not self.option('test-docs-map'):
            return []

        return gluetool.utils.load_yaml(self.option('test-docs-map'), logger=self.logger)

    @gluetool.utils.cached_property
    def run_map(self):
        # type: () -> Any
        if not self.option('run-map'):
            return []

        return gluetool.utils.load_yaml(self.option('run-map'), logger=self.logger)

    @gluetool.utils.cached_property
    def final_overall_result_map(self):
        # type: () -> Any
        if not self.option('final-overall-result-map'):
            return []

        return gluetool.utils.load_yaml(self.option('final-overall-result-map'), logger=self.logger)

    @gluetool.utils.cached_property
    def final_state_map(self):
        # type: () -> Any
        if not self.option('final-state-map'):
            return []

        return gluetool.utils.load_yaml(self.option('final-state-map'), logger=self.logger)

    def _subject_info(self, subject_name, instructions):
        # type: (str, str) -> Dict[str, Any]
        self.require_shared('evaluate_instructions', 'evaluate_rules')

        subject_info = {}

        # Callback for 'details' command, applies changes to `subject_info`
        def _details_callback(instruction, command, argument, context):
            # type: (Dict[str, Any], str, Dict[str, Any], Dict[Any, Any]) -> None
            if instruction.get('eval-as-rule', False):
                subject_info.update({
                    detail: self.shared('evaluate_rules', value, context=context)
                    for detail, value in argument.iteritems()
                })

            else:
                subject_info.update({
                    detail: render_template(value, **context) for detail, value in argument.iteritems()
                })

            log_dict(self.debug, '{} info'.format(subject_name), subject_info)

        # Callback for 'eval-as-rule' command - it does nothing, it is handled by 'details' callback,
        # but we must provide it anyway to make ``rules-engine`` happy (unhandled command).
        def _eval_as_rule_callback(instruction, command, argument, context):
            # type: (Dict[str, Any], str, str, str) -> None
            pass

        self.shared('evaluate_instructions', instructions, {
            'details': _details_callback,
            'eval-as-rule': _eval_as_rule_callback
        })

        return subject_info

    def _artifact_info(self):
        # type: () -> Dict[str, Union[str, int]]
        artifact = self._subject_info('artifact', self.artifact_map,)
        if 'id' in artifact:
            try:
                artifact['id'] = int(artifact['id'])
            except ValueError:
                self.warn('Could not convert artifact id to integer, leaving as string')

        return artifact

    def _contact_info(self):
        # type: () -> Dict[str, str]
        return {
            'name': self.option('contact-name'),
            'team': self.option('contact-team'),
            'url': self.option('contact-url'),
            'email': self.option('contact-email'),
            'irc': self.option('contact-irc'),
            'docs': self.option('contact-docs')
        }

    def _run_info(self):
        # type: () -> Dict[str, Any]
        return self._subject_info('run', self.run_map)

    def _init_message(self, thread_id):
        # type: (Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]
        headers = {}  # type: Dict[str, Any]
        body = {}  # type: Dict[str, Any]

        artifact = self._artifact_info()
        contact = self._contact_info()
        run = self._run_info()

        headers.update(artifact)

        body['contact'] = contact
        body['run'] = run
        body['artifact'] = artifact

        body['note'] = self.option('note')

        body['generated_at'] = datetime.datetime.utcnow().isoformat(' ')
        body['version'] = self.option('version')

        body['pipeline'] = {
            'name': self.shared('eval_context').get('JENKINS_BUILD_URL') or self.option('pipeline-name')
        }

        if thread_id is not None:
            body['pipeline']['id'] = thread_id

        elif self.has_shared('thread_id'):
            body['pipeline']['id'] = self.shared('thread_id')

        return headers, body

    def report_pipeline_state(
        self,
        state,  # type: str
        thread_id=None,  # type: Optional[str]
        topic=None,  # type: Optional[str]
        test_category=None,  # type: Optional[str]
        test_docs=None,  # type: Optional[str]
        test_namespace=None,  # type: Optional[str]
        test_type=None,  # type: Optional[str]
        test_overall_result=None,  # type: Optional[str]
        test_results=None,  # type: Optional[str]
        distros=None,  # type: Optional[List[Tuple[str, str, str]]]
        error_message=None,  # type: Optional[str]
        error_url=None  # type: Optional[str]
    ):
        # type: (...) -> None
        """
        Send out the message reporting the pipeline state.

        If the argument is not set, its field won't be part of the message, with the exception
        of ``thread-id`` and ``artifact`` where shared functions could be called, if available.

        :param str state: State of the pipeline.
        :param str topic: Message bus topic to report to. If not set, ``bus-topic`` option is used.
        :param str test_category: Pipeline category - ``functional``, ``static-analysis``, etc.
        :param str test_docs: Link to test documentation, etc.
        :param str test_namespace: Test namespace, used to construct test case name in ResultsDB.
        :param str test_type: Pipeline type - ``tier1``, ``rpmdiff-analysis``, etc.
        :param str thread_id: The thread ID of the pipeline. If not set, shared function ``thread_id``
            is used to provide the ID.
        :param list(tuple(str, str, str)) distros: List of distros used by the systems in the testing
            process. Each item is a tuple of three strings:

            * ``label`` - arbitrary label of the system, e.g. ``master`` or ``client``.
            * ``os`` - identification of used distro, e.g. beaker distro name or OpenStack image name.
            * ``provider`` - what service provided the system, e.g. ``beaker`` or ``openstack``.
        :param str test_overall_result: Overall test result (``pass``, ``fail``, ``unknown``, ...).
        :param element test_results: Internal representation of gathered testing results. If provided,
            it is serialized into the message.
        :param str error_message: Error message which can be presented to the common user.
        :param str error_url: URL of the issue in a tracking system which tracks the error. For example,
            link to an automatically created Sentry issue, or link to a Jira issue discissing the error.
        """

        distros = distros or cast(List[Tuple[str, str, str]], ())
        topic = topic or self.option('bus-topic')

        headers, body = self._init_message(thread_id)

        body['test'] = {
            'category': test_category or self.option('test-category'),
            'docs': test_docs or self._get_test_docs(),
            'namespace': test_namespace or self._get_test_namespace(),
            'type': test_type or self.option('test-type'),
        }

        if state == STATE_COMPLETE:
            body['system'] = [
                {
                    'label': label,
                    'os': distro,
                    'provider': provider
                } for label, distro, provider in distros
            ]

            body['test']['result'] = test_overall_result

            if test_results is not None:
                compressed = zlib.compress(str(test_results))
                body['test']['xunit'] = base64.b64encode(compressed)

            if self.has_shared('notification_recipients'):
                body['recipients'] = self.shared('notification_recipients')

        # Send error properties in any case - despite the final state being e.g. 'complete',
        # an exception may have been raised and by always reporting the properties we can be
        # sure even the 'complete' report would be connected with the original issue, and
        # therefore open to investigation.
        body['reason'] = self._get_error_reason(error_message)

        # If the note wasn't been set by the module option, add error reason there.
        # CI dashboard will show the note as a reason to failed or skipped test.
        if not body['note']:
            body['note'] = self._get_error_reason(error_message)

        body['issue_url'] = error_url

        render_context = gluetool.utils.dict_update(self.shared('eval_context'), {
            'HEADERS': headers,
            'BODY': body,
            'STATE': state
        })

        topic = gluetool.utils.render_template(topic, logger=self.logger, **render_context)

        self.debug("topic: '{}'".format(topic))
        log_dict(self.debug, 'pipeline state headers', headers)
        log_dict(self.debug, 'pipeline state body', body)

        if not self.has_shared('publish_bus_messages'):
            return

        message = gluetool.utils.Bunch(headers=headers, body=body)

        self.shared('publish_bus_messages', message, topic=topic)

    def _set_pr_status(self, status, description):
        # type: (str, str) -> None
        self.require_shared('set_pr_status')

        # The PR_TESTING_ARTIFACTS_URL represents an URL where testing artifacts will be stored
        # The variable will be used by system roles pipelines to store link to artifacts in GitHub CI
        pr_status_url = self.shared('eval_context').get('PR_TESTING_ARTIFACTS_URL')
        if not pr_status_url:
            pr_status_url = self.shared('eval_context').get('JENKINS_BUILD_URL')

        self.shared('set_pr_status', status, description, context=self.option('pr-label'),
                    target_url=pr_status_url)

    def execute(self):
        # type: () -> None
        if normalize_bool_option(self.option('dont-report-running')):
            self.info('not reporting the beginning of the pipeline')
            return

        self.info('reporting pipeline beginning')

        if self.option('pr-label'):
            self._set_pr_status('pending', 'Test started')

        self.report_pipeline_state(STATE_RUNNING)

    def _get_test_namespace(self):
        # type: () -> str
        """
        Return a rendered test namespace.

        :returns: a rendered test namespace with one variable available in context.
        """

        return gluetool.utils.render_template(
            self.option('test-namespace'),
            logger=self.logger,
            **self.shared('eval_context')
        )

    def _get_overall_result_xunit(self, test_results):
        # type: (bs4.element.Tag) -> str
        """
        Decide what the overall result should be, based on xUnit representation of test results.

        It is quite simple - xUnit representation already carries necessary value.
        """

        return cast(str, test_results['overall-result'])

    def _get_overall_result_legacy(self, results):
        # type: (bs4.element.Tag) -> str
        """
        Decide what the overall result should be, based on internal representation of test results.
        """

        if not results:
            return 'unknown'

        if all([result.overall_result.lower() in ('info',) for result in results]):
            return 'info'

        if all([result.overall_result.lower() in ('pass', 'passed', 'info') for result in results]):
            return 'passed'

        return 'failed'

    def _get_final_overall_result(self, results, failure):
        # type: (str, Optional[gluetool.Failure]) -> str
        """
        Read instructions from a file, and find out what the final overall result of the current pipeline
        should be. If the instructions yield no decision, use default simple scheme to decide.
        """

        self.require_shared('evaluate_instructions')

        context = gluetool.utils.dict_update(self.shared('eval_context'), {
            'RESULTS': results,
            'FAILURE': failure
        })

        overall_result = argparse.Namespace(result=None)

        # Callback for 'result' command
        def _result_callback(instruction, command, argument, context):
            # type: (str, str, str, str) -> None
            overall_result.result = argument.strip()

            self.debug("final overall result set to '{}'".format(overall_result.result))

        self.shared('evaluate_instructions', self.final_overall_result_map, {
            'result': _result_callback
        }, context=context, default_rule='False')

        if overall_result.result is not None:
            return cast(str, overall_result.result)

        # No instruction applied, therefore fall back to default behavior.
        if isinstance(results, bs4.element.Tag):
            return self._get_overall_result_xunit(results)

        return self._get_overall_result_legacy(results)

    def _get_final_state(self, failure):
        # type: (Any) -> str
        """
        Read instructions from a file, and find out what the final state of the current pipeline
        should be.
        """

        context = gluetool.utils.dict_update(self.shared('eval_context'), {
            'FAILURE': failure
        })

        for instr in self.final_state_map:
            log_dict(self.debug, 'final state instruction', instr)

            if not self.shared('evaluate_rules', instr.get('rule', 'True'), context=context):
                self.debug('denied by rules')
                continue

            if 'state' not in instr:
                self.warn('Final state map matched but did not yield any state', sentry=True)
                continue

            self.debug("final state set to '{}'".format(instr['state']))

            return cast(str, instr['state'])

        return STATE_ERROR if failure else STATE_COMPLETE

    def _get_test_docs(self):
        # type: () -> Optional[str]
        """
        Read instructions from a file and find the documentation by evaluating the given rules.
        """

        # force test docs if specified
        if self.option('test-docs'):
            return cast(str, self.option('test-docs'))

        context = self.shared('eval_context')

        for instr in self.test_docs_map:
            log_dict(self.debug, 'test docs instruction', instr)

            if not self.shared('evaluate_rules', instr.get('rule', 'True'), context=context):
                self.debug('denied by rules')
                continue

            if 'docs' not in instr:
                self.warn('Docs rules matched but did not yield any documentation link', sentry=True)
                continue

            self.debug("test docs set to '{}'".format(instr['docs']))

            return cast(str, instr['docs'])

        return None

    def _get_error_reason(self, error_message):
        # type: (Optional[str]) -> Optional[str]
        """
        Read instructions from a file to determine the error reason. By default return the error message.
        """

        context = gluetool.utils.dict_update(self.shared('eval_context'), {
            'ERROR_MESSAGE': error_message
        })

        for instr in self.error_reason_map:
            log_dict(self.debug, 'error reason instruction', instr)

            if not self.shared('evaluate_rules', instr.get('rule', 'True'), context=context):
                self.debug('denied by rules')
                continue

            if 'reason' not in instr:
                self.warn('Error reason rules matched but did not yield any error reason', sentry=True)
                continue

            reason = gluetool.utils.render_template(instr['reason'], logger=self.logger, **context)
            self.debug("error reason set to '{}'".format(reason))

            return reason

        return error_message

    def destroy(self, failure=None):
        # type: (Optional[gluetool.Failure]) -> None
        if failure is not None and isinstance(failure.exc_info[1], SystemExit):
            return

        # if evaluate_instructions failed, it means we failed super early, just bail out silently
        # and let the user get the real error
        if not self.has_shared('evaluate_instructions'):
            self.warn('Skipping reporting as the pipeline failed too early')
            return

        self.info('reporting pipeline final state')

        test_results = self.shared('results')
        overall_result = self._get_final_overall_result(test_results, failure)

        kwargs = {
            'test_results': None,
            'test_overall_result': overall_result
        }  # type: Dict[str, Any]

        # If the result is already an XML tree, therefore serialized, do nothing.
        if isinstance(test_results, bs4.element.Tag):
            kwargs.update({
                'test_results': test_results
            })

        else:
            kwargs.update({
                'test_results': self.shared('serialize_results', 'xunit', test_results)
            })

        if failure:
            assert failure.exc_info[1] is not None
            kwargs.update({
                'error_message': str(failure.exc_info[1].message),
                'error_url': failure.sentry_event_url
            })

        if self.option('pr-label'):
            self._set_pr_status(overall_result, 'Test finished')

        self.report_pipeline_state(self._get_final_state(failure), **kwargs)
