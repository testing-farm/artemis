# Avoid importing this module instead of python-bugzilla in tests
from __future__ import absolute_import

from collections import defaultdict, namedtuple
from requests.exceptions import ConnectionError

import bugzilla
import six

import gluetool
from gluetool import GlueError
from gluetool.log import log_blob, log_dict
from gluetool.utils import cached_property, normalize_multistring_option, Result

# Type annotations
from typing import TYPE_CHECKING, cast, Any, Callable, Dict, List, Optional, Tuple  # noqa

TCMSTestCase = namedtuple('TCMSTestCase', ['id', 'description'])

DEFAULT_RETRY_TIMEOUT = 30
DEFAULT_RETRY_TICK = 10


class Bugzilla(gluetool.Module):
    """
    Provides access to a Bugzilla instance. Provides shared functions for:

    * `bugzilla_api` - accessing Bugzilla API

    * `bugzilla_attributes` - list attributes of given bugs

    * `bugzilla_post_comment` - post a comment to given bugs

    * `bugzilla_tcms_tests` - list TCMS tests of given bugs
    """

    name = 'bugzilla'
    description = 'Provides access to the Bugzilla XMLRPC interface.'

    options = [
        ('Connection Details', {
            'base-url': {
                'help': 'Bugzilla base URL'
            },
            'api-key': {
                'help': 'Bugzilla API key.'
            }
        }),
        ('API Options', {
            'retry-tick': {
                'help': 'Number of retries for failed API operations. (default: %(default)s)',
                'type': int,
                'default': DEFAULT_RETRY_TICK,
            },
            'retry-timeout': {
                'help': 'Timeout between API retries in seconds. (default: %(default)s)',
                'type': int,
                'default': DEFAULT_RETRY_TIMEOUT,
            }
        }),
        ('Configuration Options', {
            'external-tracker-id-tcms': {
                'help': 'ID of the external tracker for TCMS test cases.',
                'type': int
            },
        }),
        ('Test Options', {
            'bug-id': {
                'help': 'ID of the bug to use. Multiple bugs can be specified.',
                'action': 'append',
            },
            'list-tcms-tests': {
                'help': 'List bugs with attached TCMS test cases.',
                'action': 'store_true'
            },
            'post-comment': {
                'help': 'Post comment to a bug.',
                'metavar': 'COMMENT'
            },
            'private': {
                'help': 'Post comment as private.',
                'action': 'store_true'
            },
            'list-attributes': {
                'help': 'List specified bug attributes.',
                'action': 'store_true'
            },
            'attributes': {
                'help': 'Comma separated list of bug attribute names. (default: %(default)s)',
                'type': str,
                'default': 'summary'
            }
        })
    ]

    required_options = ('api-key', 'base-url', 'external-tracker-id-tcms')

    shared_functions = [
        'bugzilla_api',
        'bugzilla_attributes',
        'bugzilla_post_comment',
        'bugzilla_tcms_tests'
    ]

    @cached_property
    def bug_ids(self):
        # type: () -> List[int]

        return [int(id) for id in normalize_multistring_option(self.option('bug-id'))]

    def sanity(self):
        # type: () -> None

        bug_id_options = (
            'list-attributes',
            'list-tcms-tests',
            'post-comment',
        )

        # some test options are mutual exclusive
        if sum([bool(self.option(option)) for option in bug_id_options]) > 1:
            raise GlueError('Options {} are mutually exclusive'.format(", ".join(bug_id_options)))

        # bug_id is required for some options
        if any([self.option(option) for option in bug_id_options]) and not self.bug_ids:
            raise GlueError("Option 'bug-id' is required")

    def execute(self):
        # type: () -> None
        attributes = normalize_multistring_option(self.option('attributes'))

        api = self.bugzilla_api()

        self.info("connected to bugzilla instance '{}' version '{}.{}'".format(
            self.option('base-url'),
            api.bz_ver_major, api.bz_ver_minor
        ))

        if self.option('post-comment'):
            self.bugzilla_post_comment(self.bug_ids, self.option('post-comment'), self.option('private'), verbose=True)

        if self.option('list-tcms-tests'):
            self.bugzilla_tcms_tests(self.bug_ids, verbose=True)

        if self.option('list-attributes'):
            self.bugzilla_attributes(self.bug_ids, attributes, verbose=True)

    @gluetool.utils.cached_property
    def _api(self):
        # type: () -> bugzilla.Bugzilla
        base_url = self.option('base-url')

        try:
            return bugzilla.Bugzilla(
                '{}/xmlrpc.cgi'.format(base_url),
                api_key=self.option('api-key')
            )

        except ConnectionError as error:
            raise GlueError("Could not connect to '{}': {}".format(self.option('base-url'), error))

    def bugzilla_api(self):
        # type: () -> bugzilla.Bugzilla
        """ Provides initialized Bugzilla API object. """
        return self._api

    def bugzilla_tcms_tests(self, ids, verbose=False):
        # type: (List[int], Optional[bool]) -> Optional[Dict[int, List[TCMSTestCase]]]
        """
        Extracts TCMS test case IDs from bugs specified by bug IDs. Returns a unique
        list of TCMS tests for each bug.

        :param list(int) ids: List of Bugzilla IDs to use for extraction.
        :param bool verbose: Be verbose, output to 'info' log level.
        :rtype: dict(int, list(str))
        :returns: A dictionary mapping of bugzilla IDs to list of found TCMS tests or None
        """

        if not ids:
            raise GlueError("No bug ids given for 'bugzilla_tcms_tests', cannot continue")

        api = self.bugzilla_api()

        bz_tests = {}  # type: Dict[int, List[TCMSTestCase]]

        log_function = self.info if verbose else self.debug

        # initialize bugzilla bug instances from given bug ids and filter out bugs which we do not have access to
        bugs = [bug for bug in api.getbugs(ids, extra_fields=['external_bugs']) if bug]

        accessible_ids = [int(bug.bug_id) for bug in bugs]
        inaccessible_ids = [bug_id for bug_id in ids if bug_id not in accessible_ids]

        log_dict(
            log_function,
            'accessible bugs',
            accessible_ids
        )

        log_dict(
            log_function,
            'inaccessible bugs',
            inaccessible_ids
        )

        log_dict(self.debug, 'bugs', [
            bug.external_bugs for bug in bugs
        ])

        # fail early if not bugs
        if not bugs:
            self.warn('No TCMS tests found for the given bug.')
            return None

        external_tracker_id_tcms = self.option('external-tracker-id-tcms')

        # go through all links in the bug
        for bug in bugs:
            for link in bug.external_bugs:
                # skip non-TCMS links
                if not link['ext_bz_id'] == external_tracker_id_tcms:
                    continue

                # note: TCMS test case id is hidden under 'ext_bz_bug_id' key
                test_case = TCMSTestCase(link['ext_bz_bug_id'], link['ext_description'])

                # add new bug entry
                if bug.id not in bz_tests:
                    bz_tests[bug.id] = [test_case]

                # update existing bug entry, do not duplicate test cases
                else:
                    if test_case not in bz_tests[bug.id]:
                        bz_tests[bug.id].append(test_case)

        if bz_tests:
            # log_function is used to control the verbosity of the output, with "Test Options"
            # we want to be more verbose about the outcome
            log_dict(log_function, 'Found these bugs with attached TCMS test cases', {
                'BZ#{}'.format(bug_id): [
                    'TC#{} - {}'.format(test.id, test.description) for test in tests
                ] for bug_id, tests in six.iteritems(bz_tests)
            })

        else:
            self.debug('No TCMS tests found for given bugzillas.')
            return None

        return bz_tests

    def bugzilla_post_comment(self, ids, text, is_private=False, verbose=False):
        # type: (List[int], str, Optional[bool], Optional[bool]) -> None
        """
        Submits a new comment to the specified bug.

        :param list(int) ids: Bug IDs for submission
        :param str text: Text to submit as a comment.
        :param bool is_private: Submit the comment as private, by default ``False``
        :param bool verbose: Be verbose, output to 'info' log level.
        """

        if not ids:
            raise GlueError("No bug ids given for 'bugzilla_post_comment', cannot continue")

        api = self.bugzilla_api()

        log_function = self.info if verbose else self.debug

        def _post_comment():
            # type: () -> Result[bool, bool]
            update = api.build_update(comment=text, comment_private=is_private)

            try:
                api.update_bugs(ids, update)

            except bugzilla.BugzillaError as error:
                self.warn('Retrying posting comment due to exception: {}'.format(error))
                return Result.Error(False)

            return Result.Ok(True)

        # Post the comment to the bug with retries
        gluetool.utils.wait(
            "posting comment to {}:".format(' '.join(['BZ#{}'.format(bug) for bug in ids])),
            _post_comment,
            timeout=self.option('retry-timeout'),
            tick=self.option('retry-tick')
        )

        log_blob(log_function, 'Given bugs updated with following comment', text)

    def bugzilla_attributes(self, ids, attributes, verbose=False):
        # type: (List[int], List[str], Optional[bool]) -> Dict[int, Dict[str, str]]
        """
        Lists requested bug attributes from bugs specified by bug IDs.

        :param list(int) ids: List of Bugzilla IDs to use for extraction.
        :param list(str) attributes: List of bug attribute names to extract.
        :param bool verbose: Be verbose, output to 'info' log level.
        :rtype: dict
        :returns: A dictionary mapping of bug IDs to a dictionary with respective attributes and values.
        """

        if not ids:
            raise GlueError("No bug ids given for 'bugzilla_attributes', cannot continue")

        api = self.bugzilla_api()

        log_function = self.info if verbose else self.debug

        # use default dict with dict factory
        bz_attrs = defaultdict(dict)  # type: Dict[int, Dict[str, str]]

        # always add bug_id
        attributes.append('bug_id')

        # pass a copy of attributes list as `getbugs()` is rewriting it for some reason
        bugs = api.getbugs(ids, extra_fields=attributes[:])

        # go through found bugs,
        for bug in bugs:
            for attr in attributes:
                bz_attrs[bug.id][attr] = getattr(bug, attr, None)

        log_dict(log_function, 'Bugzilla attributes', bz_attrs)

        return bz_attrs
