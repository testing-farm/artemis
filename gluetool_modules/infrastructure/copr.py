import re
import collections
import requests

import gluetool
from gluetool.utils import cached_property, dict_update, render_template
from gluetool.log import log_dict, log_blob

#: Information about task architectures.
#:
#: :ivar list(str) arches: List of architectures.
TaskArches = collections.namedtuple('TaskArches', ['arches'])


class CoprApi(object):

    def __init__(self, copr_url, module):
        self.copr_url = copr_url
        self.module = module

    def _api_request(self, url, label, full_url=False):
        if not full_url:
            url = '{}/{}'.format(self.copr_url, url)

        self.module.debug('[copr API] {}: {}'.format(label, url))

        try:
            request = requests.get(url)
        except Exception:
            raise gluetool.GlueError('Unable to GET: {}'.format(url))

        if request.status_code != 200:
            self.module.warn('Request to copr API ended up with status code {}'.format(request.status_code))

        return request

    def _get_text(self, url, label, full_url=None):
        # Using `.content` instead of `.text` - `text` provides unicode string, and we'd have to encode them
        # anyway.
        output = self._api_request(url, label, full_url=full_url).content
        log_blob(self.module.debug, '[copr API] {} output'.format(label), output)
        return output

    def _get_json(self, url, label, full_url=None):
        try:
            output = self._api_request(url, label, full_url=full_url).json()
        except Exception:
            raise gluetool.GlueError('Unable to get: {}'.format(url))

        log_dict(self.module.debug, '[copr API] {} output'.format(label), output)
        return output

    def _get_build_info(self, build_id):
        return self._get_json('api_2/builds/{}'.format(build_id), 'build info')

    def get_build_info(self, build_id):
        build_info = self._get_build_info(build_id)

        if build_info.get('message', '') == 'Build with id `{}` not found'.format(build_id):
            self.module.warn('Build {} not found'.format(build_id))

            return {
                'package_version': 'UNKNOWN-COPR-VERSION',
                'package_name': 'UNKNOWN-COPR-COMPONENT'
            }

        return build_info['build']

    def get_build_tasks(self, build_id):
        build_info = self._get_build_info(build_id)

        return self._get_json(build_info['_links']['build_tasks']['href'], 'build tasks')['build_tasks']

    def get_build_task_info(self, build_id, chroot_name):
        build_task_info = self._get_json('api_2/build_tasks/{}/{}'.format(build_id, chroot_name), 'build tasks info')

        # copr api actually returns message with {}, no .format() is missing
        if build_task_info.get('message', '') == 'Build task {} for build {} not found' or \
                build_task_info.get('error', '') == "Request wasn't successful, there is probably a bug in the API code.":  # noqa: E501  # line too long
            self.module.warn('Build task {}:{} not found'.format(build_id, chroot_name))
            return {
                'state': 'UNKNOWN-COPR-STATUS'
            }

        return build_task_info['build_task']

    def get_project_id(self, build_id):
        build_info = self._get_build_info(build_id)

        try:
            project_id = build_info['_links']['project']['href'].split('/')[-1]
        except KeyError:
            project_id = None

        return project_id

    def _get_project_info(self, project_id):

        if not project_id:
            return None

        return self._get_json('api_2/projects/{}'.format(project_id), 'project info')

    def get_project_info(self, project_id):
        unknown_project = {
            'owner': 'UNKNOWN-COPR-OWNER',
            'name': 'UNKNOWN-COPR-PROJECT'
        }

        if not project_id:
            self.module.warn('No project info obtained - invalid `project_id`.')
            return unknown_project

        project_info = self._get_project_info(project_id)

        if project_info.get('message', '') == 'Project with id `{}` not found'.format(project_id):
            self.module.warn('Project {} not found'.format(project_id))
            return unknown_project

        if project_info['project'] is None:
            self.module.warn('Api provided no information about project `{}`'.format(project_id))
            return unknown_project

        return project_info['project']

    def get_project_builds(self, project_id):
        project_info = self._get_project_info(project_id)

        return self._get_json(project_info['_links']['builds']['href'], 'project builds')['builds']

    def _result_dir_url(self, build_id, chroot_name):
        build_task_info = self.get_build_task_info(build_id, chroot_name)
        return build_task_info.get('result_dir_url', 'UNKNOWN-COPR-RESULT-DIR-URL')

    def _get_builder_live_log(self, build_id, chroot_name):
        result_dir_url = self._result_dir_url(build_id, chroot_name)

        if result_dir_url == 'UNKNOWN-COPR-RESULT-DIR-URL':
            return None

        result_dir_url = '{}/builder-live.log.gz'.format(result_dir_url)
        return self._get_text(result_dir_url, 'builder live log', full_url=True)

    def _find_in_log(self, regex, build_id, chroot_name):
        builder_live_log = self._get_builder_live_log(build_id, chroot_name)

        if not builder_live_log:
            return []

        return list(set(re.findall(regex, builder_live_log)))

    def get_rpm_names(self, build_id, chroot_name):
        return self._find_in_log(r'Wrote: /builddir/build/RPMS/(.*)\.rpm', build_id, chroot_name)

    def get_srpm_names(self, build_id, chroot_name):
        return self._find_in_log(r'Wrote: /builddir/build/SRPMS/(.*)\.src\.rpm', build_id, chroot_name)

    def add_result_dir_url(self, build_id, chroot_name, file_names):
        result_dir_url = self._result_dir_url(build_id, chroot_name)
        return ['{}{}.rpm'.format(result_dir_url, file_name) for file_name in file_names]

    def get_repo_url(self, owner, project, chroot):
        # strip architecture - string following last dash
        chroot = re.match('(.+)-.+', chroot).group(1)

        return '{0}/coprs/{1}/{2}/repo/{3}/{1}-{2}-{3}.repo'.format(
            self.copr_url,
            owner,
            project,
            chroot
        )


class BuildTaskID(object):
    """
    Build task ID consist of build ID and chroot name. This class covers both values and provides them like
    one string, with following format: '[build_id]:[chroot_name]'
    """

    def __init__(self, build_id, chroot_name):
        self.build_id = build_id
        self.chroot_name = chroot_name

    def __str__(self):
        return '{}:{}'.format(self.build_id, self.chroot_name)

    def __repr__(self):
        return self.__str__()


class CoprTask(object):
    """
    Covers copr build task and provides all necessary information about it.

    :param BuildTaskID task_id: Task id used to initialization.
    :param gluetool.Module module: Reference to parent's module (used eg. for logging).
    """

    ARTIFACT_NAMESPACE = 'copr-build'

    def __init__(self, task_id, module):
        # as an "official ID", use string representation - some users might be confused by the object,
        # despite it has proper __str__ and __repr__
        self.id = self.dispatch_id = str(task_id)
        self.task_id = task_id

        self.module = module

        self.copr_api = module.copr_api()

        build = self.copr_api.get_build_info(task_id.build_id)
        build_task = self.copr_api.get_build_task_info(task_id.build_id, task_id.chroot_name)
        project_id = self.copr_api.get_project_id(self.task_id.build_id)
        project = self.copr_api.get_project_info(project_id)

        self.status = build_task['state']
        self.component = build['package_name']
        self.target = task_id.chroot_name
        # required API for our modules providing artifacts, we have no tags in copr, use target
        self.destination_tag = self.target
        self.nvr = '{}-{}'.format(self.component, build['package_version'])
        self.owner = project['owner']
        self.project = project['name']
        # issuer is optional item
        self.issuer = build.get('submitter', 'UNKNOWN-COPR-ISSUER')
        self.repo_url = self.copr_api.get_repo_url(self.owner, self.project, self.task_id.chroot_name)

        # this string identifies component in static config file
        self.component_id = '{}/{}/{}'.format(self.owner, self.project, self.component)

    @cached_property
    def has_artifacts(self):
        # We believe Copr keeps artifacts "forever" - or, at least, long enough to matter to us - therefore
        # we don't even bother to check for their presence.
        return True

    @cached_property
    def rpm_names(self):
        return self.copr_api.get_rpm_names(self.task_id.build_id, self.task_id.chroot_name)

    @cached_property
    def srpm_names(self):
        return self.copr_api.get_srpm_names(self.task_id.build_id, self.task_id.chroot_name)

    @cached_property
    def rpm_urls(self):
        return self.copr_api.add_result_dir_url(self.task_id.build_id, self.task_id.chroot_name, self.rpm_names)

    @cached_property
    def srpm_urls(self):
        return self.copr_api.add_result_dir_url(self.task_id.build_id, self.task_id.chroot_name, self.srpm_names)

    @cached_property
    def task_arches(self):
        """
        :rtype: TaskArches
        :return: information about arches the task was building for
        """

        return TaskArches([self.target.split('-')[-1]])

    @cached_property
    def url(self):
        context = dict_update(self.module.shared('eval_context'), {
            'TASK': self
        })

        return render_template(self.module.option('copr-web-url-template'), **context)

    @cached_property
    def full_name(self):
        """
        String with human readable task details. Used for slightly verbose representation e.g. in logs.

        :rtype: str
        """

        name = [
            "package '{}'".format(self.component),
            "build '{}'".format(self.task_id.build_id),
            "target '{}'".format(self.task_id.chroot_name)
        ]

        return ' '.join(name)

    @cached_property
    def dist_git_repository_name(self):
        return self.component


class Copr(gluetool.Module):

    name = 'copr'
    description = 'Copr'
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = {
        'copr-url': {
            'help': 'Url of Copr build server',
            'type': str
        },
        'copr-web-url-template': {
            'help': """
                    Template of URL leading to the Copr website, displaying the artifact. It has
                    access to all variables available in the eval context, with ``TASK`` representing
                    the task module generates URL for. (default: %(default)s).
                    """,
            'type': str,
            'default': None
        },
        'task-id': {
            'help': 'Copr build task ID, in a form of ``build-id:chroot-name``.',
            'type': str
        }
    }

    required_options = ('copr-url', 'copr-web-url-template', 'task-id')

    shared_functions = ['primary_task', 'tasks', 'copr_api']

    def __init__(self, *args, **kwargs):
        super(Copr, self).__init__(*args, **kwargs)
        self.task = None
        self._tasks = None

    def primary_task(self):
        return self.task

    def tasks(self, task_ids=None):

        if not task_ids:
            return self._tasks

        self._tasks = []

        for task_id in task_ids:
            build_id, chroot_name = [s.strip() for s in task_id.split(':')]
            self._tasks.append(CoprTask(BuildTaskID(int(build_id), chroot_name), self))

        return self._tasks

    @property
    def eval_context(self):
        __content__ = {  # noqa
            'ARTIFACT_TYPE': """
                             Type of the artifact, ``copr-build`` in the case of ``copr`` module.
                             """,
            'BUILD_TARGET': """
                            Build target of the primary task, as known to Koji/Beaker.
                            """,
            'NVR': """
                   NVR of the primary task.
                   """,
            'PRIMARY_TASK': """
                            Primary task, represented as ``CoprTask`` instance.
                            """,
            'TASKS': """
                     List of all tasks known to this module instance.
                     """
        }

        primary_task = self.primary_task()

        if not primary_task:
            self.debug('No primary task available, cannot pass it to eval_context')
            return {}

        return {
            # common for all artifact providers
            'ARTIFACT_TYPE': primary_task.ARTIFACT_NAMESPACE,
            'BUILD_TARGET': primary_task.target,
            'NVR': primary_task.nvr,
            'PRIMARY_TASK': primary_task,
            'TASKS': self.tasks()
        }

    @cached_property
    def _copr_api(self):
        return CoprApi(self.option('copr-url'), self)

    def copr_api(self):
        return self._copr_api

    def execute(self):
        build_id, chroot_name = [s.strip() for s in self.option('task-id').split(':')]

        build_task_id = BuildTaskID(int(build_id), chroot_name)
        self.task = CoprTask(build_task_id, self)
        self._tasks = [self.task]

        self.info('Initialized with {}: {} ({})'.format(self.task.id, self.task.full_name, self.task.url))
