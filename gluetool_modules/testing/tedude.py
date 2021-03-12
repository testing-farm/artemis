import gluetool
from gluetool.log import log_dict
from gluetool.utils import cached_property, new_xml_element
from gluetool_modules.libs.results import TestResult, publish_result

# Type annotations
from typing import Any, Dict, List, Optional, Tuple  # noqa


class TeDuDeTestResult(TestResult):
    """
    TeDuDe test result data container
    """

    def __init__(self, glue, overall_result, **kwargs):
        # type: (gluetool.glue.Glue, str, **Any) -> None
        super(TeDuDeTestResult, self).__init__(glue, 'tedude', overall_result, **kwargs)

    def _serialize_to_xunit(self):
        # type: () -> Any
        test_suite = super(TeDuDeTestResult, self)._serialize_to_xunit()
        test_suite = self.glue.shared('tedude_xunit_serialize', test_suite, self)
        return test_suite


class TeDuDe(gluetool.Module):
    """
    TeDuDe checks if all bugs mentioned in the git changelog meet the workflow requirement.
    The original TeDuDe process seeks for specific labels in cf_devel_whiteboard. However, since
    individual checks are performed using the rules_engine one can define a custom workflow.
    The requirement is that rules contain commands 'message' and 'result' (either 'passed' or 'failed')
    and that there is always a matching rule. Rules are being evaluated until the first match.
    Please see gluetool_modules/tests/assets/tedude/sst_platform_security.yaml file for an example.

    Details about TeDuDe workflow can be found at
    https://docs.google.com/document/d/1TFjYLiMMRWMFI78JzAt6jXWeH8g6DR4HBMy-EgztpwU
    """

    name = 'tedude'
    description = """
                  TeDuDe checks if all bugs mentioned in the changelog meet Testing During Development
                  workflow requirements.
                  """

    shared_functions = ['tedude_xunit_serialize']
    required_options = ('instructions',)

    options = {
        'bugzilla-attributes': {
            'help': """
                    Comma delimited list of bugzilla attributes to lookup. These attributes are then
                    available in a rules file.
                    """,
            'action': 'append'
        },
        'instructions': {
            'help': 'Path to a YAML file with instructions to be evaluated, e.g. by the rules-engine.',
        }
    }

    @cached_property
    def _instructions(self):
        # type: () -> Any
        return gluetool.utils.load_yaml(gluetool.utils.normalize_path(self.option('instructions')))

    @cached_property
    def _bugzilla_attributes(self):
        # type: () -> List[str]
        return gluetool.utils.normalize_multistring_option(self.option('bugzilla-attributes'))

    @cached_property
    def _tedude_test_statuses(self):
        # type: () -> Tuple[str, Dict[int, Dict[str,str]]]
        """
        Evaluates each bug using the provided instructions.

        :returns (str, dict[int, dict]) where str is an overall result and dict has Bugzilla IDs as keys
        and as values dictionaries with keys "result", "label", "message".
        """

        # results of testing
        results = {}

        # default overall result
        overall_result = 'passed'

        # get bug IDs from the changelog
        # need to convert bug_id from string to int since bugzilla xmlrpc has bug_id in dictionary as int
        bug_ids = map(int, self.shared('dist_git_bugs'))

        # read bug attributes from bugzilla
        if bug_ids:
            attributes = self.shared('bugzilla_attributes', bug_ids, self._bugzilla_attributes)
        else:
            self.info("No bug IDs have been parsed from the changelog")

        # method stores the instruction's 'result' and 'message' to a global dictionary with overall results
        def add_result(instruction, command, argument, context):
            # type: (Dict[str, Any], str, Any, Dict[str, Any]) -> None

            gluetool.log.log_dict(self.debug, 'add_result', {
                'instruction': instruction,
                'command': command,
                'argument': argument,
                'context': context
            })

            results[context['BUG_ID']] = {
                'result': instruction['result'],
                'message': instruction['message']
            }

        # evaluates instructions using a given context, returns result of a test ('passed' or 'failed'),
        # or raise exception when no rule has matched
        def check_instructions(instructions, context, current_key):
            # type: (Dict[str, Any], Dict[str, Any], str) -> Any

            # need to evaluate instructions one by one as we want to skip remaining on the first match
            for instruction in instructions:
                self.shared('evaluate_instructions', [instruction], {
                    'result': add_result,
                }, context=context, stop_at_first_hit=True, ignore_unhandled_commands=True)
                # skip remaining instructions
                if current_key in results:
                    return results[current_key]['result']

            # Q: Is is really appropriate here to raise and exception?
            #    We could make the test fail eventually
            raise gluetool.GlueError("'{}' did not match any rule in instructions.".format(current_key))

        # do the evaluation for each parsed bug
        if bug_ids:
            for bug_id in bug_ids:
                # handle a situation when bugzilla xmlrpc did not provide details for a bug
                bug_attributes = attributes[bug_id] if bug_id in attributes else {}

                # prepare context for insturctions evaluation
                context = gluetool.utils.dict_update(
                    self.shared('eval_context'),
                    {
                        'NO_BUGS_FOUND': False,
                        'BUG_ID': 'BZ#{}'.format(bug_id),
                        'BUG_NOT_FOUND': bug_id not in attributes,
                        'ATTRIBUTES': bug_attributes,
                        'ATTRIBUTE_NAMES': bug_attributes.keys()
                    }
                )

                result = check_instructions(self._instructions, context, 'BZ#{}'.format(bug_id))
                if result == 'failed':
                    overall_result = result

        # when no bugs have been parsed
        else:
            # prepare context for instruction evaluation
            context = gluetool.utils.dict_update(
                self.shared('eval_context'),
                {
                    'NO_BUGS_FOUND': True,
                    'BUG_ID': 'NO_BUGS_FOUND',  # to ease reuse of add_result() function
                    'BUG_NOT_FOUND': False,
                    'ATTRIBUTES': [],
                    'ATTRIBUTE_NAMES': []
                }
            )

            overall_result = check_instructions(self._instructions, context, 'NO_BUGS_FOUND')

        log_dict(self.debug, 'Detailed TeDuDe test results', results)
        self.info("Result of testing: {}".format(overall_result.upper()))
        return overall_result, results

    def execute(self):
        # type: () -> None
        self.require_shared('dist_git_bugs', 'bugzilla_attributes', 'evaluate_instructions')

        overall_result, statuses = self._tedude_test_statuses
        publish_result(self, TeDuDeTestResult, overall_result, payload=statuses)

    def tedude_xunit_serialize(self, test_suite, result):
        # type: (Any, Any, Any) -> Any

        if not result.payload:
            return test_suite

        for key, data in result.payload.items():

            outcome = data["result"]

            test_case = new_xml_element(
                'testcase',
                _parent=test_suite,
                name=key
            )

            # properties = new_xml_element('properties', _parent=test_case)
            # @new_xml_element('property', _parent=properties, name='outcome', value=data["result"])
            if outcome == 'failed':
                new_xml_element('failure', _parent=test_case, message=data["message"])

            elif outcome != 'passed':
                self.warn('Unknown outcome {} in test {}'.format(outcome, key), sentry=True)

            test_outputs = new_xml_element(
                'test-outputs',
                _parent=test_case
            )

            new_xml_element(
                'test-output',
                _parent=test_outputs,
                message=data["message"]
            )

        return test_suite
