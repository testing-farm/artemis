import six

from functools import partial
from posixpath import join as urljoin

import gluetool
from gluetool.log import LoggerMixin
from gluetool.result import Result
from gluetool.utils import log_dict, requests

from requests.exceptions import ConnectionError, HTTPError, Timeout

# Type annotations
# pylint: disable=unused-import,wrong-import-order
from typing import cast, Any, Dict, List, Optional, Tuple, Union  # noqa

# Nucleus API documentation: https://testing-farm.gitlab.io/nucleus
STATE_RUNNING = 'running'
STATE_COMPLETE = 'complete'
STATE_ERROR = 'error'


class TestingFarmAPI(LoggerMixin, object):
    def __init__(self, module, api_url):
        super(TestingFarmAPI, self).__init__(module.logger)

        self._module = module
        self._api_url = api_url
        self._post_request = partial(self._request, type='post')
        self._put_request = partial(self._request, type='put')
        self._get_request = partial(self._request, type='get')
        self._delete_request = partial(self._request, type='delete')

    def _request(self, endpoint, payload=None, type=None):
        # type: (str, Optional[Dict], Optional[str]) -> Any
        """
        Post payload to the given API endpoint. Retry if failed to mitigate connection/service
        instabilities.
        """

        if not type:
            raise gluetool.GlueError('No request type specified')

        if type in ['post', 'put'] and not payload:
            raise gluetool.GlueError("payload is required for 'post' and 'put' requests")

        # construct post URL
        url = urljoin(self._api_url, endpoint)  # type: ignore
        log_dict(self.debug, "posting following payload to url '{}'".format(url), payload)

        def _response():
            # type: () -> Any
            try:
                with requests() as req:
                    response = getattr(req, type)(url, json=payload)

                try:
                    response_data = response.json()
                except ValueError:
                    response_data = response.text

                if response.status_code == 404:
                    return Result.Ok(None)

                if not response:
                    error_msg = 'Got unexpected response status code {}'.format(response.status_code)
                    log_dict(
                        self.error,
                        error_msg,
                        {
                            'post-url': url,
                            'payload': payload or '<not available>',
                            'response': response_data
                        }
                    )
                    return Result.Error(error_msg)

                return Result.Ok(response)

            except (ConnectionError, HTTPError, Timeout) as error:
                self.debug('retrying because of exception: {}'.format(error))
                return Result.Error(error)

            except AttributeError:
                raise gluetool.GlueError("Invalid request type '{}'".format(type))

        # wait until we get a valid response
        return gluetool.utils.wait('getting {} response from {}'.format(type, url),
                                   _response,
                                   timeout=self._module.option('retry-timeout'),
                                   tick=self._module.option('retry-tick'))

    def get_request(self, request_id, api_key):
        request = self._get_request('v0.1/requests/{}?api_key={}'.format(request_id, api_key))

        if not request:
            raise gluetool.GlueError("Request '{}' was not found".format(request_id))

        return request.json()

    def put_request(self, request_id, payload):
        request = self._put_request('v0.1/requests/{}'.format(request_id), payload=payload)
        if not request:
            raise gluetool.GlueError("Request failed: {}".format(request))

        return request.json()


class TestingFarmRequest(LoggerMixin, object):
    ARTIFACT_NAMESPACE = 'testing-farm-request'

    def __init__(self, module):
        super(TestingFarmRequest, self).__init__(module.logger)

        self._module = module
        self._api_key = module.option('api-key')
        self._api = module._tf_api

        self.id = self._module.option('request-id')

        request = self._api.get_request(self.id, self._api_key)

        # Select correct test, trust Testing Farm validation that only one test
        # is specified, as defined in the API standard
        test = request['test']
        type = self.type = [key for key in test.keys() if test[key]][0]

        self.url = test[type]['url']
        self.ref = test[type]['ref']

        self.playbooks = test[type]['playbooks'] if type == 'sti' else None

        self.environments_requested = request['environments_requested']

        self.webhook_url = None
        self.webhook_token = None

        if 'notification' in request and request['notification'] \
                and 'webhook' in request['notification'] and request['notification']['webhook']:

            if 'url' in request['notification']['webhook'] and request['notification']['webhook']['url']:
                self.webhook_url = request['notification']['webhook']['url']

            if 'token' in request['notification']['webhook'] and request['notification']['webhook']['token']:
                self.webhook_token = request['notification']['webhook']['token']

    def webhook(self):
        """
        Post to webhook, as defined in the API.
        """

        if not self.webhook_url:
            self.debug('No webhook, skipping')
            return

        payload = {'request_id': self.id}

        if self.webhook_token:
            payload.update({'token': self.webhook_token})

        def _response():
            # type: () -> Any
            try:
                with requests() as req:
                    response = req.post(self.webhook_url, json=payload)

                if not response:
                    return Result.Error('retrying because of status code {}'.format(response.status_code))

                return Result.Ok(None)

            except (ConnectionError, HTTPError, Timeout) as error:
                self.debug('retrying because of exception: {}'.format(error))
                return Result.Error(error)

            except AttributeError:
                raise gluetool.GlueError("Invalid request type '{}'".format(type))

        # wait until we get a valid response
        return gluetool.utils.wait('posting update to webhook {}'.format(self.webhook_url),
                                   _response,
                                   timeout=self._module.option('retry-timeout'),
                                   tick=self._module.option('retry-tick'))

    def update(self, state=None, overall_result=None, xunit=None, summary=None):
        payload = {}
        result = {}

        if self._api_key:
            payload.update({
                'api_key': self._api_key
            })

        if state:
            payload.update({
                'state': state
            })

        if overall_result:
            result.update({
                'overall': overall_result
            })

        if xunit:
            result.update({
                'xunit': xunit
            })

        if summary:
            result.update({
                'summary': summary
            })

        if result:
            payload.update({
                'result': result
            })

        self._api.put_request(self.id, payload)

        self.webhook()


class TestingFarmRequestModule(gluetool.Module):
    """
    Provides testing farm request.
    """

    name = 'testing-farm-request'
    description = "Module providing Testing Farm Request."
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = [
        ('API options', {
            'api-key': {
                'help': 'API key required for authentication',
            },
            'api-url': {
                'help': 'Root of Nucleus internal API endpoint',
            },
            'retry-timeout': {
                'help': 'Wait timeout in seconds. (default: %(default)s)',
                'type': int,
                'default': 30
            },
            'retry-tick': {
                'help': 'Number of times to retry a query. (default: %(default)s)',
                'type': int,
                'default': 10
            },
        }),
        ('Testing Farm Request', {
            'request-id': {
                'help': 'Testing Farm request ID to report against.'
            },
            'arch': {
                'help': 'Force given architecture in all environments.'
            }
        }),
    ]

    required_options = ('api-url', 'api-key', 'request-id')
    shared_functions = ['testing_farm_request', 'user_variables', 'tmt_context']

    def __init__(self, *args, **kwargs):
        super(TestingFarmRequestModule, self).__init__(*args, **kwargs)
        self._tf_request = None
        self._tf_api = None

    @property
    def eval_context(self):
        return {
            # common for all artifact providers
            'TESTING_FARM_REQUEST_ID': self._tf_request.id,
            'TESTING_FARM_REQUEST_TEST_TYPE': self._tf_request.type,
            'TESTING_FARM_REQUEST_TEST_URL': self._tf_request.url,
            'TESTING_FARM_REQUEST_TEST_REF': self._tf_request.ref,
        }

    def testing_farm_request(self):
        return self._tf_request

    def user_variables(self, **kwargs):
        request = self.testing_farm_request()

        if request.environments_requested \
                and 'variables' in request.environments_requested[0] \
                and request.environments_requested[0]['variables']:

            return {
                key: six.moves.shlex_quote(value)
                for key, value in six.iteritems(request.environments_requested[0]['variables'])
            }

        return {}

    def tmt_context(self):
        request = self.testing_farm_request()

        if request.environments_requested \
                and 'tmt' in request.environments_requested[0] \
                and request.environments_requested[0]['tmt'] \
                and 'context' in request.environments_requested[0]['tmt']:

            return request.environments_requested[0]['tmt']['context']

        return {}

    def execute(self):
        self._tf_api = TestingFarmAPI(self, self.option('api-url'))

        self.info(
            "Connected to Testing Farm Service '{}'".format(
                self.option('api-url'),
            )
        )

        self._tf_request = request = TestingFarmRequest(self)

        if self.option('arch'):
            for environment in request.environments_requested:
                environment['arch'] = self.option('arch')

        log_dict(self.info, "Initialized with {}".format(request.id), {
            'type': request.type,
            'url': request.url,
            'ref': request.ref,
            'variables': self.user_variables() or '<no variables specified>',
            'environments_requested': request.environments_requested,
            'webhook_url': request.webhook_url or '<no webhook specified>'
        })
