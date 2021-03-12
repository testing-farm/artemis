from typing import Any, Dict, List, Optional, cast  # noqa

import collections
import re
import requests

from six.moves.urllib.parse import quote as urlquote
from six.moves.urllib.parse import urlencode

import gluetool
from gluetool.log import log_dict
from gluetool.utils import cached_property


#: Information about task architectures.
#:
#: :ivar bool complete: If ``True``, the task was not limited by its issuer to any particular set of architectures.
#:     ``False`` signals the issuer requested task to build its artifact for specific list of architectures.
#: :ivar list(str) arches: List of architectures.
TaskArches = collections.namedtuple('TaskArches', ['complete', 'arches'])
VALID_STATUSES = ('error', 'failure', 'pending', 'success')


def is_json_response(response):
    # type: (requests.models.Response) -> bool

    content_type_list = re.split('[ ;]+', response.headers.get('content-type', ''))
    return 'application/json' in content_type_list


class GitHubAPI(object):
    def __init__(self, module, api_url, username, token):
        # type: (gluetool.Module, str, str, str) -> None

        self.module = module
        self.api_url = api_url
        self.username = username
        self.token = token

    def _compose_url(self, path, params=None):
        # type: (str, Optional[Dict[str, str]]) -> str

        if params is None:
            return '{}/{}'.format(self.api_url, urlquote(path))
        return '{}/{}?{}'.format(self.api_url, urlquote(path), urlencode(params))

    def _check_status(self, response, allow_statuses=None):
        # type: (requests.models.Response, Optional[List[int]]) -> None

        if response.status_code < 200 or response.status_code > 299:
            allow_statuses = allow_statuses or []
            if not allow_statuses or response.status_code not in allow_statuses:
                if is_json_response(response):
                    msg = 'Git API returned an error: {}\nURL: {}'.format(response.json()['message'], response.url)
                else:
                    msg = 'Git API returned an error: {}\nURL: {}'.format(response.status_code, response.url)
                raise gluetool.GlueError(msg)

    def _get(self, url, allow_statuses=None):
        # type: (str, Optional[List[int]]) -> requests.models.Response
        # The user can specify a list of additional http status codes
        # to allow.  This method will raise a GlueError if the http status
        # code is not in the 2xx range and not in the allow_statuses list

        self.module.debug('[GitHub API] GET: {}'.format(url))

        try:
            if self.username and self.token:
                response = requests.get(url, auth=(self.username, self.token))
            else:
                response = requests.get(url)
        except Exception:
            raise gluetool.GlueError('Unable to GET: {}'.format(url))
        self._check_status(response, allow_statuses)

        if is_json_response(response):
            log_dict(self.module.debug, '[GitHub API] output', response.json())
        else:
            log_dict(self.module.debug, '[GitHub API] output', response.status_code)

        return response

    def _post(self, url, data):
        # type: (str, Dict[str, str]) -> requests.models.Response

        log_dict(self.module.debug, '[GitHub API] POST: {}'.format(url), data)

        if not self.module.dryrun_allows('POSTing data to GitHub API'):
            empty_response = requests.Response()
            empty_response._content = b'{}'  # type: ignore
            return empty_response

        try:
            if self.username and self.token:
                response = requests.post(url, auth=(self.username, self.token), json=data)
            else:
                response = requests.post(url, json=data)
        except Exception:
            raise gluetool.GlueError('Unable to POST: {}'.format(url))
        self._check_status(response)

        log_dict(self.module.debug, '[GitHub API] output', response.json())

        return response

    def get_pull_request(self, owner, repo, pull_number):
        # type: (str, str, str) -> Any
        """
        Return general info about the specified pull request.

        Refer to https://developer.github.com/v3/pulls/#get-a-single-pull-request
        for the API endpoint documentation.
        """

        pr_path = 'repos/{owner}/{repo}/pulls/{pull_number}'.format(
            owner=owner, repo=repo, pull_number=pull_number
        )
        pr_url = self._compose_url(pr_path)
        pr_data = self._get(pr_url).json()
        return pr_data

    def get_commit_statuses(self, owner, repo, commit_sha):
        # type: (str, str, str) -> Any
        """
        Return combined state and commit statuses for the specified ref.

        Refer to https://developer.github.com/v3/repos/statuses/#get-the-combined-status-for-a-specific-ref
        for the API endpoint documentation.
        """

        statuses_path = 'repos/{owner}/{repo}/commits/{commit_sha}/status'.format(
            owner=owner, repo=repo, commit_sha=commit_sha
        )
        statuses_url = self._compose_url(statuses_path)
        statuses_data = self._get(statuses_url).json()
        return statuses_data

    def get_comment(self, owner, repo, comment_id):
        # type: (str, str, str) -> Any
        """
        Return the specified comment.

        Refer to https://developer.github.com/v3/issues/comments/#get-a-single-comment
        for the API endpoint documentation.
        """

        comment_path = 'repos/{owner}/{repo}/issues/comments/{comment_id}'.format(
            owner=owner, repo=repo, comment_id=comment_id
        )
        comment_url = self._compose_url(comment_path)
        comment_data = self._get(comment_url).json()
        return comment_data

    def get_commit(self, owner, repo, sha):
        # type: (str, str, str) -> Any
        """
        Return the specified commit.

        Refer to https://developer.github.com/v3/repos/commits/#get-a-single-commit
        for the API endpoint documentation.
        """

        commit_path = 'repos/{owner}/{repo}/commits/{commit_sha}'.format(
            owner=owner, repo=repo, commit_sha=sha
        )
        commit_url = self._compose_url(commit_path)
        commit_data = self._get(commit_url).json()
        return commit_data

    def get_pr_commits(self, owner, repo, pr):
        # type: (str, str, str) -> Any
        """
        Return a list of commits for a specified pr.

        Refer to https://developer.github.com/v3/pulls/#list-commits-on-a-pull-request
        for the API endpoint documentation.
        """

        commits_path = 'repos/{owner}/{repo}/pulls/{pull_number}/commits'.format(
                owner=owner, repo=repo, pull_number=pr)
        commits_url = self._compose_url(commits_path)
        return self._get(commits_url).json()

    def get_commit_by_timestamp(self, owner, repo, base_sha, timestamp):
        # type: (str, str, str, str) -> Any
        """
        Return commit preceding given timestamp from a branch specified by `base_sha`.

        `timestamp` has to be in ISO 8601 format `YYYY-MM-DDTHH:MM:SSZ`.

        When compared to the `get_commit` function, this API endpoint does not
        return `files` and `stats` fields.

        Refer to https://developer.github.com/v3/repos/commits/#list-commits-on-a-repository
        for the API endpoint documentation.
        """

        commit_path = 'repos/{owner}/{repo}/commits'.format(
            owner=owner, repo=repo
        )
        commit_params = {'sha': base_sha, 'until': timestamp, 'per_page': '1'}
        commit_url = self._compose_url(commit_path, params=commit_params)
        commit_data = self._get(commit_url).json()
        return commit_data[0] if len(commit_data) else None

    def is_collaborator(self, owner, repo, username):
        # type: (str, str, str) -> bool
        """
        Return true if the user with the given username is a collaborator in owner/repo

        This is primarily used for authn purposes e.g. who can trigger CI on a PR

        Refer to https://developer.github.com/v3/repos/collaborators/#check-if-a-user-is-a-repository-collaborator
        for the API endpoint documentation.
        """

        collaborators_path = 'repos/{owner}/{repo}/collaborators/{username}'.format(
            owner=owner, repo=repo, username=username
        )
        collaborators_url = self._compose_url(collaborators_path)
        response = self._get(collaborators_url, allow_statuses=[401, 403, 404])
        return (response.status_code == 204)

    def _set_commit_status(self, url, status_data):
        # type: (str, Dict[str, str]) -> Any
        return self._post(url, status_data).json()

    def set_commit_status(self, pull_request, status_data):
        # type: (GitHubPullRequest, Dict[str, str]) -> Any
        """
        Update status of the specified pull request.

        Refer to https://developer.github.com/v3/repos/statuses/#create-a-status
        for the API endpoint documentation.
        """

        path = 'repos/{owner}/{repo}/statuses/{sha}'.format(
            owner=pull_request.owner, repo=pull_request.repo, sha=pull_request.commit_sha
        )
        url = self._compose_url(path)

        return self._set_commit_status(url, status_data)


class GitHubPullRequest(object):
    ARTIFACT_NAMESPACE = 'github-pr'

    def __init__(self, module, pull_request_id):
        # type: (GitHub, PullRequestID) -> None

        self.has_artifacts = True

        self.pull_request_id = pull_request_id
        self.id = self.dispatch_id = str(pull_request_id)

        self.owner = self.pull_request_id.owner  # type: str
        self.repo = self.pull_request_id.repo  # type: str
        self.pull_number = self.pull_request_id.pull_number
        self.commit_sha = self.pull_request_id.commit_sha  # type: str
        self.comment_id = self.pull_request_id.comment_id
        self.depends_on = []  # type: List[str]

        self.component = self.repo

        github_api = module.github_api()

        pull_request = github_api.get_pull_request(self.owner, self.repo, self.pull_number)

        self.clone_url = pull_request['base']['repo']['clone_url']
        self.source_clone_url = pull_request['head']['repo']['clone_url']
        self.source_html_url = pull_request['head']['repo']['html_url']

        links = pull_request['_links']
        self.api_url = links['self']['href']
        self.html_url = links['html']['href']
        self.comments_url = links['comments']['href']

        self.source_branch = pull_request['head']['ref']
        self.source_repo_owner = pull_request['head']['repo']['owner']['login']
        self.source_repo_name = pull_request['head']['repo']['name']

        self.target_branch = pull_request['base']['ref']

        self.pull_author = pull_request['user']['login']
        self.pull_head_branch_owner = pull_request['head']['user']['login']

        if self.comment_id:
            comment = github_api.get_comment(self.owner, self.repo, self.comment_id)

            # if the triggering event was comment, commit sha is not available
            comment_created = comment['created_at']
            last_commit = pull_request['head']['sha']

            commit = github_api.get_commit_by_timestamp(self.owner, self.repo, last_commit, comment_created)
            self.commit_sha = commit['sha']

            self.comment = comment['body']
            self.comment_author = comment['user']['login']
            self.comment_author_role = comment['author_association']
        else:
            commit = github_api.get_commit(self.owner, self.repo, self.commit_sha)
            self.comment = None
            self.comment_author = None
            self.comment_author_role = None

        self.commit_author = commit['commit']['author']['name']
        self.commit_timestamp = commit['commit']['author']['date']
        self.commit_message = commit['commit']['message']

        commit_statuses = github_api.get_commit_statuses(self.owner, self.repo, self.commit_sha)

        self.commit_state = commit_statuses['state']
        self.commit_statuses = {}  # type: Dict[str, Dict[str, str]]
        for status in commit_statuses['statuses']:
            self.commit_statuses[status['context']] = {
                'state': status['state'],
                'description': status['description'],
                'updated_at': status['updated_at']
            }

        self.pull_author_is_collaborator = github_api.is_collaborator(self.owner, self.repo, self.pull_author)
        self.comment_author_is_collaborator = github_api.is_collaborator(self.owner, self.repo, self.comment_author)
        self.pull_head_branch_owner_is_collaborator = github_api.is_collaborator(
            self.owner, self.repo, self.pull_head_branch_owner
        )

        if "labels" in pull_request:
            self.labels = [item["name"] for item in pull_request["labels"]]
        else:
            self.labels = []

        commits = github_api.get_pr_commits(self.owner, self.repo, self.pull_number)
        depends_on_regex = re.compile(r'\s*Depends-On:\s*(.*/pull/|#)(\d+)', flags=re.IGNORECASE)
        depends_on = []  # type: List[str]
        for commit_message in [c['commit']['message'] for c in reversed(commits)]:
            match = depends_on_regex.search(commit_message)
            if match:
                try:
                    project = self.repo if match.group(1) == "#" else match.group(1).rsplit('/')[-3]
                except IndexError:
                    # NOTE(ivasilev) As the expected regex will have at least '/pull/' part there should always be at
                    # least 3 elements in the list after rsplit('/'), but let's be paranoid.
                    continue
                pr = match.group(2)
                depends_on.append("{}/PR{}".format(project, pr))
        # Remove duplicates while keeping order
        self.depends_on = list(collections.OrderedDict.fromkeys(depends_on))

    @cached_property
    def task_arches(self):
        # type: () -> TaskArches
        return TaskArches(True, ['noarch'])


class PullRequestID(object):
    """
    Representation of the pull request.

    The representation consists of the repository owner, repository name, pull
    request number, commit SHA and optionally comment id available as a string
    with the following format: 'owner:repo:pull_number:[commit_sha|:comment_id]'.
    """

    def __init__(self, owner, repo, pull_number, commit_sha, comment_id=None):
        # type: (str, str, str, str, Optional[str]) -> None

        self.owner = owner
        self.repo = repo
        self.pull_number = pull_number
        self.commit_sha = commit_sha
        self.comment_id = comment_id

    def __str__(self):
        # type: () -> str

        msg = '{}:{}:{}:{}'.format(self.owner, self.repo, self.pull_number, self.commit_sha)
        if self.comment_id:
            return '{}:{}'.format(msg, self.comment_id)

        return msg

    def __repr__(self):
        # type: () -> str

        return ('{0}(owner={1.owner!r}, repo={1.repo!r},'
                ' pull_number={1.pull_number!r}, commit_sha={1.commit_sha!r},'
                ' comment_id={1.comment_id!r})'.format(type(self).__name__, self))


class GitHub(gluetool.Module):
    """
    This module provides connection access to GitHub via its API.

    The module is dry-run safe by guarding the calls to ``GitHubAPI._post`` method.
    """

    name = 'github'
    description = 'Wrapper of GitHub API.'

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = [
        ('General options', {
            'api-url': {
                'help': 'GitHub API URL',
                'type': str
            },
            'api-username': {
                'help': 'Username used for API authentication.',
                'type': str
            },
            'api-token': {
                'help': 'Token used for API authentication.',
                'type': str
            },
            'upload-full-url': {
                'help': 'Upload full url instead of shortened one',
                'action': 'store_true'
            }
        }),
        ('Pull request initialization options', {
            'pull-request': {
                'help': 'Unique identifier of a pull request.',
                'metavar': 'owner:repo:pull_number:[commit_sha|:comment_id]'
            },
        }),
        ('Test options', {
            'set-status': {
                'help': 'Create a commit status for the initialized pull request.'
                        ' If ``context`` is not provided, status is created with'
                        ' context ``default`. ``status`` can be one of ``error``,'
                        ' ``failure``, ``pending`` or ``success``.',
                'metavar': 'status:message[:context[:target_url]]'
            },
            'print-pull-info': {
                'help': 'Print pull request info.',
                'action': 'store_true'
            },
        }),
    ]

    required_options = ['api-url', 'api-username', 'api-token']

    shared_functions = ['primary_task', 'tasks', 'github_api', 'set_pr_status']

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None

        super(GitHub, self).__init__(*args, **kwargs)
        self._pull_request = None  # type: Optional[GitHubPullRequest]

    @property
    def eval_context(self):
        # type: () -> Dict[str, Any]

        __content__ = {  # noqa
            'ARTIFACT_TYPE': """
                             Type of the artifact, ``github-pr`` in the case of ``github`` module.
                             """,
            'PRIMARY_TASK': """
                            Primary task, represented as ``GitHubPullRequest`` instance.
                            """,
            'TASKS': """
                     List of all pull requests known to this module instance.
                     """,
            'PR_DEPENDS_ON': """
                             List all pull requests this pr depends on in the module/PRXXX format.
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
            'TASKS': self.tasks(),
            'PR_DEPENDS_ON': primary_task.depends_on
        }

    @cached_property
    def _github_api(self):
        # type: () -> GitHubAPI

        return GitHubAPI(
            self,
            self.option('api-url'),
            self.option('api-username'),
            self.option('api-token'),
        )

    def github_api(self):
        # type: () -> GitHubAPI
        """
        Return GitHubAPI instance.
        """

        return cast(GitHubAPI, self._github_api)

    def primary_task(self):
        # type: () -> Optional[GitHubPullRequest]
        """
        Return the GitHubPullRequest instance.
        """

        return self._pull_request

    def tasks(self):
        # type: () -> List[GitHubPullRequest]
        """
        Return the available GitHubPullRequest instance as a list.
        """

        return [self._pull_request] if self._pull_request else []

    def _get_github_status(self, status):
        # type: (str) -> str
        """
        Translate overall pipeline result into GitHub status.
        """
        status_map = {
            'info': 'success',
            'passed': 'success',
            'failed': 'failure',
            'unknown': 'error'
        }

        return status_map.get(status, 'error')

    def set_pr_status(self, status, message, context=None, target_url=None):
        # type: (str, str, Optional[str], Optional[str]) -> None
        """
        Create a commit status for the initialized pull request.

        :param status: The state of the status.
        :type status: str
        :param message: A short description of the status.
        :type message: str
        :param context: A string label to differentiate this status. If not provided, ``default`` is used.
        :type  context: str
        :param target_url: The target URL to associate with this status.
        :type target_url: str
        """

        upload_full_url = gluetool.utils.normalize_bool_option(self.option('upload-full-url'))

        if status not in VALID_STATUSES:
            status = self._get_github_status(status)

        status_data = {
            'state': status,
            'description': message
        }

        if context:
            status_data['context'] = context
        if target_url:
            if upload_full_url:
                status_data['target_url'] = target_url
            else:
                self.require_shared('get_shortened_url')
                # shortening the target url using shortener only available from
                # internal network also helps, when `target_url` links to internal
                # network that must not be posted to external network
                status_data['target_url'] = self.shared('get_shortened_url', target_url)

        pull_request = self._pull_request

        assert pull_request is not None
        self.github_api().set_commit_status(pull_request, status_data)

        self.info('Status for {pull_id} with context \'{context}\' successfully set to \'{status}\''.format(
                  pull_id=pull_request.pull_request_id, context=context, status=status))

    def sanity(self):
        # type: () -> None

        if self.option('pull-request'):
            # pull-request = 'owner:repo:pull_number:[commit_sha|:comment_id]'
            pr_option = self.option('pull-request').split(':')
            if len(pr_option) < 4 or len(pr_option) > 5:
                raise gluetool.GlueError('Check pull-request option, invalid value provided.')

            if not pr_option[2].isdigit():
                raise gluetool.GlueError('Check pull-request option, pull_number has to be int.')

        if self.option('set-status'):
            # set-status = 'status:message[:context][:target_url]'
            status_option = self.option('set-status').split(':')
            if len(status_option) < 2:
                raise gluetool.GlueError('Check set-status option, invalid value provided.')

            if status_option[0] not in VALID_STATUSES:
                raise gluetool.GlueError('Check set-status option, vaild values for state are:'
                                         ' {}.'.format(VALID_STATUSES))

    def execute(self):
        # type: () -> None

        if self.dryrun_enabled:
            self.warn('DRY mode supported for functionality provided by this module, '
                      'without any changes on GitHub.')

        pull_request_option = self.option('pull-request')
        if pull_request_option:
            pull_request_id = PullRequestID(*pull_request_option.split(':'))
            log_dict(self.debug, 'PullRequestID object', vars(pull_request_id))

            self._pull_request = GitHubPullRequest(self, pull_request_id)
            log_dict(
                self.info if self.option('print-pull-info') else self.debug,
                'GitHubPullRequest object',
                vars(self._pull_request)
            )

            self.info('Initialized with {} ({})'.format(
                self._pull_request.pull_request_id,
                self._pull_request.html_url
            ))

        set_status_option = self.option('set-status')
        if set_status_option:
            self.set_pr_status(*set_status_option.split(':', 3))
