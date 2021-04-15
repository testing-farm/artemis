# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.utils import cached_property, normalize_multistring_option
from gluetool.log import log_dict

import requests


class PagureApi(object):

    def __init__(self, pagure_url, pagure_url_port, module):
        self.pagure_url = pagure_url
        self.pagure_url_port = pagure_url_port
        self.module = module

    def _get_json(self, location):
        url = '{}/{}'.format(self.pagure_url, location)

        self.module.debug('[Pagure API]: {}'.format(url))

        try:
            output = requests.get(url).json()
        except Exception:
            raise gluetool.GlueError('Unable to get: {}'.format(url))

        log_dict(self.module.debug, '[Pagure API] output', output)

        return output

    def get_pull_request_info(self, project_name, pull_request_id):
        return self._get_json('api/0/{}/pull-request/{}'.format(project_name, pull_request_id))

    def get_project_info(self, project_name):
        return self._get_json('api/0/{}'.format(project_name))

    def get_clone_url(self, full_name):
        return '{}/{}.git'.format(self.pagure_url_port, full_name)

    def get_pr_ui_url(self, full_name, pull_request_id):
        return '{}/{}/pull-request/{}'.format(self.pagure_url, full_name, pull_request_id)


class PullRequestID(object):
    """
    Pull Request ID consist of repository name, pull request id within project and optional comment id.
    This class covers both values and provides them like one string, with following format:
    '[repository_name]:[repository_pr_id]:[comment_id]'
    """

    def __init__(self, repository_name, repository_pr_id, comment_id=None):
        self.repository_name = repository_name
        self.repository_pr_id = repository_pr_id
        self.comment_id = int(comment_id) if comment_id else None

    def __str__(self):
        if self.comment_id:
            return '{}:{}:{}'.format(self.repository_name, self.repository_pr_id, self.comment_id)

        return '{}:{}'.format(self.repository_name, self.repository_pr_id)

    def __repr__(self):
        return self.__str__()


class PagureProject(object):
    def __init__(self, module, full_name):
        self.module = module
        self.logger = module.logger

        pagure_api = self.module.pagure_api()

        project_info = pagure_api.get_project_info(full_name)

        self.name = str(project_info['name'])
        self.full_name = str(project_info['fullname'])
        self.clone_url = pagure_api.get_clone_url(full_name)


class PagurePullRequest(object):
    ARTIFACT_NAMESPACE = 'dist-git-pr'

    def __init__(self, module, pull_request_id):
        self.module = module
        self.logger = module.logger

        self.id = self.dispatch_id = str(pull_request_id)
        self.pull_request_id = pull_request_id

        pagure_api = self.module.pagure_api()

        self.project = PagureProject(module, self.pull_request_id.repository_name)

        pull_request_info = pagure_api.get_pull_request_info(
            self.pull_request_id.repository_name,
            self.pull_request_id.repository_pr_id
        )

        self.uid = str(pull_request_info['uid'])
        self.source_branch = str(pull_request_info['branch_from'])
        self.destination_branch = str(pull_request_info['branch'])
        self.issuer = pull_request_info['user']['name']
        self.commit_start = pull_request_info['commit_start']
        self.commit_stop = pull_request_info['commit_stop']

        if self.pull_request_id.comment_id:
            last_comment_id = self.pull_request_id.comment_id

            all_comments = pull_request_info['comments']
            self.comments = [comment for comment in all_comments if comment['id'] <= last_comment_id]

            if last_comment_id != self.comments[-1]['id']:
                raise gluetool.GlueError('Comment with id {} not found'.format(last_comment_id))

        else:
            self.comments = []

    @cached_property
    def url(self):
        return self.module.pagure_api().get_pr_ui_url(
            self.pull_request_id.repository_name,
            self.pull_request_id.repository_pr_id
        )


class Pagure(gluetool.Module):
    name = 'pagure'
    description = 'Provides Pagure pull request information'

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = [
        ('Pagure options', {
            'pagure-url': {
                'help': 'URL of pagure server.',
                'type': str
            },
            'pagure-url-port': {
                'help': 'URL of pagure server with port specified.',
                'type': str
            }
        }),
        ('Build initialization options', {
            'pull-request': {
                'help': 'Unique identifier of pull request (default: none).',
                'action': 'append',
                'default': [],
                'metavar': 'repository-name:PR-ID[:comment-ID]'
            },
        }),
    ]

    required_options = ('pagure-url',)

    shared_functions = ['primary_task', 'tasks', 'pagure_api']

    def __init__(self, *args, **kwargs):
        super(Pagure, self).__init__(*args, **kwargs)
        self._pull_requests = []

    @property
    def eval_context(self):
        __content__ = {  # noqa
            'ARTIFACT_TYPE': """
                             Type of the artifact, ``dist-git-pr`` in the case of ``pagure`` module.
                             """,
            'PRIMARY_TASK': """
                            Primary task, represented as ``PagurePullRequest`` instance.
                            """,
            'TASKS': """
                     List of all pull requests known to this module instance.
                     """
        }

        primary_task = self.primary_task()

        if not primary_task:
            self.warn('No primary task available, cannot pass it to eval_context', sentry=True)
            return {}

        return {
            # common for all artifact providers
            'ARTIFACT_TYPE': primary_task.ARTIFACT_NAMESPACE,
            'PRIMARY_TASK': primary_task,
            'TASKS': self.tasks()
        }

    @cached_property
    def _pagure_api(self):
        return PagureApi(self.option('pagure-url'), self.option('pagure-url-port'), self)

    def pagure_api(self):
        # type: () -> PagureApi
        """
        Returns PagureApi instance.
        """
        return self._pagure_api

    def primary_task(self):
        # type: () -> PagurePullRequest
        """
        Returns first PagurePullRequest instance.
        """
        return self._pull_requests[0] if self._pull_requests else None

    def tasks(self):
        # type: () -> [PagurePullRequest]
        """
        Returns all available PagurePullRequest instance.
        """
        return self._pull_requests

    def execute(self):

        for pull_request_option in normalize_multistring_option(self.option('pull-request')):

            pull_request_id = PullRequestID(*pull_request_option.split(':'))
            pull_request = PagurePullRequest(self, pull_request_id)

            self._pull_requests.append(pull_request)

            self.info('Initialized with {} ({})'.format(
                pull_request.id,
                pull_request.url
            ))
