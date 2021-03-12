from urlparse import urljoin
import simplejson.errors  # type: ignore  # no stubfile for simplejson

from requests.exceptions import ConnectionError, HTTPError, Timeout

import gluetool
from gluetool.utils import cached_property, requests
from gluetool.log import LoggerMixin, log_dict
from gluetool.result import Result

from jq import jq

# Type annotations
from typing import TYPE_CHECKING, cast, Any, Dict, List, Optional, Tuple, Union  # noqa

if TYPE_CHECKING:
    import requests as orig_requests  # noqa


DEFAULT_RETRY_TIMEOUT = 30
DEFAULT_RETRY_TICK = 10


class PESApi(LoggerMixin, object):
    """
    API to Package Evolution Service
    """

    def __init__(self, module):
        # type: (gluetool.Module) -> None

        super(PESApi, self).__init__(module.logger)

        self.api_url = module.option('api-url')  # type: str
        self.module = module  # type: gluetool.Module

    def _request_with_payload(self, method, location, payload):
        # type: (str, str, Dict[str, Any]) -> orig_requests.Response
        url = urljoin(self.api_url, location)

        self.debug('[PES API]: {}'.format(url))

        def _request_response():
            # type: () -> Result[orig_requests.Response, Exception]
            try:
                with requests() as req:
                    if method == 'post':
                        response = req.post(url, json=payload, verify=False)
                    elif method == 'get':
                        response = req.get(url, params=payload, verify=False)
                    else:
                        raise gluetool.GlueError("Unsupported method '{}'".format(method))

                # 404 is expected if no events were found for a component
                if response.status_code not in [200, 404]:
                    raise gluetool.GlueError(
                        "{} with payload '{}' to '{}' returned {}: {}".format(
                            method,
                            payload,
                            url,
                            response.status_code,
                            response.content)
                    )

                # show nice parsed output
                try:
                    log_dict(self.debug,
                             "[PES API] returned '{}' and following output".format(response.status_code),
                             response.json())

                # in case json decoding fails for the response, something is really wrong (e.g. wrong api-url)
                except simplejson.errors.JSONDecodeError:
                    raise gluetool.GlueError("Pes returned unexpected non-json output, needs investigation")

                return Result.Ok(response)

            except (ConnectionError, HTTPError, Timeout) as error:
                return Result.Error(error)

            return Result.Error('unknown error')

        # Wait until we get a valid response. For 200 or 404, we get valid result, for anything else _request_response
        # returns invalid result, forcing another attempt.
        return gluetool.utils.wait('getting {} response from {}'.format(method, url),
                                   _request_response,
                                   timeout=self.module.option('retry-timeout'),
                                   tick=self.module.option('retry-tick'))

    def get_ancestors(self, package):
        # type: (str) -> List[str]
        """
        Get ancestors of the given package by querying Package Evolution Service. This can be used
        for testing upgrades from the ancestor package(s) to the given package.

        :returns: List of ancestors of the package.
        """

        # Note: srpm-events endpoint MUST end with /
        response = self._request_with_payload('post', 'srpm-events/', {'name': package})

        # When no entries are found empty list is returned.
        # We can assume package has not changed between releases, but rather no guessing in this step.
        # Consumers of this function can guess the ancestor, or try to find them some other way.
        if response.status_code == 404:
            return []

        # Note state presence actually means two thing:
        #
        # 1. package was present in previous release
        # 2. it is a new package, previously not present in previous release
        #
        # The case 2. needs to be handled later in the pipeline, i.e. not existing ancestor build

        query = '.[] | .in_packageset.srpm | .[]'

        ancestors = jq(query).transform(response.json(), multiple_output=True)

        # remove duplicate ancestors and sort them, so their list is predictable
        return sorted(list(set(ancestors)))

    def get_successors(self, package, initial_release, release):
        # type: (str, str, str) -> List[str]
        """
        Get successors of the given package by querying Package Evolution Service. This can be used
        for testing upgrades from given package to the the successor package(s).

        :returns: List of ancestors of the package.
        """

        payload = {'srpm': package, 'initial_release': initial_release, 'release': release}
        response = self._request_with_payload('get', 'successors/', payload)

        # When no entries are found empty list is returned.
        # We can assume package has not changed between releases, but rather no guessing in this step.
        # Consumers of this function can guess the ancestor, or try to find them some other way.
        if response.status_code == 404:
            return []

        successors = response.json().keys()

        # remove duplicate ancestors and sort them, so their list is predictable
        return sorted(list(set(successors)))


class PES(gluetool.Module):
    """
    Provides API to Package Evolution Service via `pes_api` shared function.
    Provides function to find ancestors for a given package from previous major releases. Used for upgrades testing.
    """
    name = 'pes'
    description = 'Provides API to Package Evolution Service (PES)'

    options = [
        ('General options', {
            'api-url': {
                'help': 'PES API server URL',
                'type': str
            },
        }),
        ('Query options', {
            'retry-timeout': {
                'help': 'Wait timeout in seconds. (default: %(default)s)',
                'type': int,
                'default': DEFAULT_RETRY_TIMEOUT
            },
            'retry-tick': {
                'help': 'Number of times to retry the query. (default: %(default)s)',
                'type': int,
                'default': DEFAULT_RETRY_TICK
            },
        }),
        ('Testing options', {
            'map-primary-task': {
                'help': 'Finds ancestors for the component of the primary task',
                'action': 'store_true'
            }
        })
    ]

    required_options = ('api-url',)

    shared_functions = ['ancestors', 'successors', 'pes_api']

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None

        super(PES, self).__init__(*args, **kwargs)

        self._components = []  # type: List[str]

    @cached_property
    def _pes_api(self):
        # type: () -> PESApi
        return PESApi(self)

    def pes_api(self):
        # type: () -> PESApi
        """
        Returns PESApi instance.
        """
        return cast(PESApi, self._pes_api)

    def ancestors(self, package):
        # type: (str) -> List[str]
        """
        Returns list of package ancestors from a previous major release.

        Note that this currently expects PES only holds ancestors for a previous major release.

        :param str package: Package to find ancestors for.
        """
        ancestors = cast(List[str], self._pes_api.get_ancestors(package))

        self.info("Ancestors of '{}': {}".format(package, ', '.join(ancestors)))

        return ancestors

    def successors(self, package, initial_release, release):
        # type: (str, str, str) -> List[str]
        """
        Returns list of package successors from a next major release.

        Note that this currently expects PES only holds successors for a next major release.

        :param str package: Package to find successors for.
        :param str initial_release: Version of source system in a RHEL-X.Y format.
        :param str release: Version of targeted system in a RHEL-X.Y format.
        """
        successors = cast(List[str], self._pes_api.get_successors(package, initial_release, release))

        self.info("Successors ({}) of '{}' ({}): {}".format(initial_release, package, release, ', '.join(successors)))

        return successors

    def execute(self):
        # type: () -> None

        if self.option('map-primary-task'):

            self.require_shared('primary_task')

            try:
                component = self.shared('primary_task').component
            except AttributeError:
                raise gluetool.GlueError('No build available, cannot continue')

            self.ancestors(component)
