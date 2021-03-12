import collections
import re

import koji
import requests.exceptions

from bs4 import BeautifulSoup
from gluetool_modules.libs.artifacts import splitFilename
from rpm import labelCompare

import gluetool
from gluetool import GlueError, SoftGlueError
from gluetool.action import Action
from gluetool.log import Logging, LoggerMixin, log_dict
from gluetool.result import Result
from gluetool.utils import cached_property, dict_update, wait, normalize_multistring_option, render_template
from gluetool.utils import IncompatibleOptionsError


DEFAULT_COMMIT_FETCH_TIMEOUT = 300
DEFAULT_COMMIT_FETCH_TICKS = 30


class NotBuildTaskError(SoftGlueError):
    def __init__(self, task_id):
        super(NotBuildTaskError, self).__init__('Task is not a build task')

        self.task_id = task_id


#: Information about task architectures.
#:
#: :ivar bool complete: If ``True``, the task was not limited by its issuer to any particular set of architectures.
#:     ``False`` signals the issuer requested task to build its artifact for specific list of architectures.
#: :ivar list(str) arches: List of architectures.
TaskArches = collections.namedtuple('TaskArches', ['complete', 'arches'])

#: Represents ``request`` field of API response on ``getTaskInfo`` query for common build task.
#:
#: :ivar str source: source used for the building process.
#: :ivar str target: target the task built for.
#: :ivar dict options: additional task options.
BuildTaskRequest = collections.namedtuple('BuildTaskRequest', ['source', 'target', 'options'])

#: Represents ``request`` field of API response on ``getTaskInfo`` query for ``buildArch`` task.
#:
#: :ivar str source: source used for the building process.
#: :ivar something: some value of unknown purpose.
#: :ivar str arch: build architecture.
#: :ivar bool keep_srpm: whether the SRPM was stored among artifacts.
#: :ivar dict options: additional task options.
BuildArchTaskRequest = collections.namedtuple('BuildArchTaskRequest',
                                              ['source', 'something', 'arch', 'keep_srpm', 'options'])

#: Represents an image repository
#:
#: :ivar str arch: Image architecture.
#: :ivar str url: Repository URL.
#: :ivar list(str) alternatives: Other URLs leading to the same image as ``url``.
#: :ivar dict manifest: Manifest describing the image in the repository.
ImageRepository = collections.namedtuple('ImageRepository', ['arch', 'url', 'alternatives', 'manifest'])


#: Represents data we need to initialize a Koji task. A task ID would be enough, but, for some tasks,
#: we may need to override some data we'd otherwise get from Koji API.
#:
#: The specific use case: container builds. Container build B1 was built by Brew task T1. Later,
#: there may be a rebuild of B1, thanks to change in the parent image, yielding B2. But: B2 would
#: point to T1! Thankfully, we can initialize with build ID (starting with B2 then), but because
#: our implementation would try to detect task behind B2 - which is, wrongly but officialy, T1 -
#: and use this task for initialization. Task instance would then try to detect build attached to
#: the task, which would be, according to API, B1... Therefore, we'd initialize with B2, but *nothing*
#: in our state would have any connection to B2, because the task behind B2 would be T1, and build
#: created by T1 would be B1.
#:
#: To solve this trap, we need to preserve information about build after we reduce it to a task,
#: and when a task instance is initialized, we'd force this build to be the task is connected to.
#: Most of our code tries to use build when providing artifact attributes like NVR or component,
#: making it the information source number one.
#:
#: Therefore task initializer, to give us a single package we could pass between involved functions.
#:
#: :ivar int task_id: task ID.
#: :ivar int build_id: if set, it as build we should assign to the task. Otherwise we query API
#:     to find out which - if any - build belongs to the task.
TaskInitializer = collections.namedtuple('TaskInitializer', ['task_id', 'build_id'])


def _call_api(session, logger, method, *args, **kwargs):
    with Action('query Koji API', parent=Action.current_action(), logger=logger, tags={
        'method': method,
        'positional-arguments': args,
        'keyword-arguments': kwargs
    }):
        method_callable = getattr(session, method)

        return method_callable(*args, **kwargs)


class KojiTask(LoggerMixin, object):
    """
    Provides abstraction of a koji build task, specified by task ID. For initialization
    koji instance details need to be passed via the instance dictionary with the following keys:

        ``session`` - a koji session initialized via the koji.ClientSession function
        ``url`` - a base URL for the koji instance
        ``pkgs_url`` - a base URL for the packages location

    :param dict details: Instance details, see ``required_instance_keys``
    :param int task_id: Initialize from given Koji task ID.
    :param module: Module that created this task instance.
    :param gluetool.log.ContextLogger logger: logger used for logging
    :param int wait_timeout: Wait this many seconds for task to become non-waiting

    :ivar int id: unique ID of the task on the Koji instance.
    """

    ARTIFACT_NAMESPACE = 'koji-build'

    @staticmethod
    def _check_required_instance_keys(details):
        """
        Checks for required instance details for Koji.
        :raises: GlueError if instance is missing some of the required keys
        """
        required_instance_keys = ('session', 'url', 'pkgs_url', 'web_url')

        if not all(key in details for key in required_instance_keys):
            raise GlueError('instance details do not contain all required keys')

    def _call_api(self, method, *args, **kwargs):
        return _call_api(self.session, self.logger, method, *args, **kwargs)

    def _assign_build(self, build_id):
        # Helper method - if build_id is specified, don't give API a chance, use the given
        # build, and emit a warning.

        if build_id is None:
            return

        self._build = self._call_api('getBuild', build_id)

        log_dict(self.debug, 'build for task ID {}'.format(self.id), self._build)

        self.warn('for task {}, build was set explicitly to {}, {}'.format(
            self.id, build_id, self._build.get('nvr', '<unknown NVR>')
        ))

    def __init__(self, details, task_id, module, logger=None, wait_timeout=None, build_id=None):
        super(KojiTask, self).__init__(logger or Logging.get_logger())

        self._check_required_instance_keys(details)

        self._module = module

        self.id = self.dispatch_id = int(task_id)
        self.api_url = details['url']
        self.web_url = details['web_url']
        self.pkgs_url = details['pkgs_url']
        self.session = details['session']

        # first check if the task is valid for our case
        if not self._is_valid:
            raise NotBuildTaskError(self.id)

        # Wait for the task to be non-waiting
        wait(
            'waiting for task to be non waiting',
            self._check_nonwaiting_task,
            timeout=wait_timeout
        )

        # Wait for the task to be finished. This can take some amount of time after the task becomes non-waiting.
        wait_result = wait(
            'waiting for task to be finished (closed, canceled or failed)',
            self._check_finished_task,
            timeout=wait_timeout
        )

        if not gluetool.utils.normalize_bool_option(module.option('accept-failed-tasks')):
            if wait_result == koji.TASK_STATES['CANCELED']:
                raise SoftGlueError("Task '{}' was canceled".format(self.id))

            if wait_result == koji.TASK_STATES['FAILED']:
                raise SoftGlueError("Task '{}' has failed".format(self.id))

        self._assign_build(build_id)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.id)

    @cached_property
    def _is_valid(self):
        """
        Verify the task is valid by checking its ``method`` attribute. List of values that are considered
        `valid` is provided by the user via ``--valid-methods`` option of the module, and generaly limits
        what tasks the pipeline deals with, e.g. it is designed to run tests on Docker images, therefore
        disallows any other method than ``buildContainer``. If there is no specific list of valid methods,
        all methods are considered valid.

        :rtype: bool
        """

        if not self._module._valid_methods:
            return True

        return self._task_info['method'] in self._module._valid_methods

    def _flush_task_info(self):
        """
        Remove cached task info we got from API. Handle the case when such info does not yet exist.
        """

        try:
            del self._task_info

        except AttributeError:
            pass

    def _check_finished_task(self):
        """
        Verify that the task is finished (closed, canceled or failed).

        :returns: True if task is closed, canceled or failed, False otherwise
        """

        self._flush_task_info()

        final_states = [
            koji.TASK_STATES['CLOSED'],
            koji.TASK_STATES['CANCELED'],
            koji.TASK_STATES['FAILED']
        ]

        if self._task_info['state'] in final_states:
            return Result.Ok(self._task_info['state'])

        return Result.Error('task is not closed')

    def _check_nonwaiting_task(self):
        """
        Check if task is non-waiting, i.e. 'waiting: false' in task info.
        :returns: True if task is non-waiting, False otherwise
        """

        self._flush_task_info()

        return Result.Ok(True) if self._task_info['waiting'] is not True else Result.Error('task is still waiting')

    @cached_property
    def _subtasks(self):
        """
        A list of children tasks in raw form, as JSON data returned by Koji API.

        :rtype: list(dict)
        """

        subtasks = self._call_api('getTaskChildren', self.id, request=True)
        log_dict(self.debug, 'subtasks', subtasks)

        return subtasks

    @cached_property
    def _build_arch_subtasks(self):
        """
        A list of children task of ``buildArch`` type, as JSON data returned by Koji API.

        :rtype: list(dict)
        """

        subtasks = [task for task in self._subtasks if task['method'] == 'buildArch']

        log_dict(self.debug, 'buildArch subtasks', subtasks)

        for task in subtasks:
            KojiTask.swap_request_info(task, BuildArchTaskRequest, 5)

        return subtasks

    @staticmethod
    def swap_request_info(task_info, klass, nr_fields):
        """
        Replace ``request`` key of task info - a JSON structure, returned by API - with
        an object with properties, representing the content of ``request`` key.
        """

        request_info = task_info.get('request', None)

        if request_info is None:
            raise GlueError("Task {} has no request field in task info".format(task_info['id']))

        if len(request_info) < nr_fields:
            raise GlueError("Task {} has unexpected number of items in request field".format(task_info['id']))

        task_info['request'] = klass(*[request_info[i] for i in range(0, nr_fields)])

    @cached_property
    def _task_info(self):
        """
        Task info as returned by API.

        :rtype: dict
        """

        task_info = self._call_api('getTaskInfo', self.id, request=True)

        if not task_info:
            raise GlueError("Task '{}' not found".format(self.id))

        log_dict(self.debug, 'task info', task_info)

        KojiTask.swap_request_info(task_info, BuildTaskRequest, 3)

        return task_info

    @cached_property
    def _build(self):
        """
        Build info as returned by API, or ``None`` for scratch builds.

        :rtype: dict
        """

        if self.scratch:
            return None

        builds = self._call_api('listBuilds', taskID=self.id)
        log_dict(self.debug, 'builds for task ID {}'.format(self.id), builds)

        if not builds:
            return None

        return builds[0]

    @cached_property
    def _result(self):
        """
        Task result info as returned by API.

        :rtype: dict
        """

        result = self._call_api('getTaskResult', self.id)

        log_dict(self.debug, 'task result', result)

        return result

    @cached_property
    def _task_request(self):
        return self._task_info['request']

    @cached_property
    def has_build(self):
        """
        Whether there is a build for this task.

        If there is a ``self.build_id``, then we have a build. ``self.build_id`` is extracted from ``self._build``,
        therefore we can inject ``self._build`` - like Brew's ``buildContainer`` tasks do - and this will work
        like a charm.
        """

        return self.build_id is not None

    @cached_property
    def is_build_task(self):
        """
        Whether this task is a "build" task, i.e. building common RPMs.
        """

        return self._task_info['method'] == 'build'

    @cached_property
    def build_id(self):
        """
        Build ID for standard tasks, or ``None`` for scratch builds.

        :rtype: int
        """

        if not self._build:
            return None

        return self._build['build_id']

    @cached_property
    def owner(self):
        """
        Name of the owner of the task.

        :rtype: str
        """

        owner_id = self._task_info["owner"]
        return self._call_api('getUser', owner_id)["name"]

    @cached_property
    def issuer(self):
        """
        Name of the issuer of the task. The same as :py:attr:`owner`.

        :rtype: str
        """

        return self.owner

    @cached_property
    def target(self):
        """
        Build target name

        :rtype: str
        """

        if self._task_request.target:
            return self._task_request.target

        # inform admins about this weird build
        self.warn("task '{}' build '{}' has no build target".format(self.id, self.nvr), sentry=True)

        return '<no build target available>'

    def previous_tags(self, tags):
        """
        Return previous tags according to the inheritance tag hierarchy to the given tags.

        :param str tags: Tags used for checking.
        :rtype: list(str)
        :returns: List of previous tags, empty list if not previous tags found.
        :raises gluetool.glue.GlueError: In case previous tag search cannot be performed.
        """

        previous_tags = []

        for tag in tags:
            if tag == '<no build target available>':
                raise GlueError('Cannot check for previous tag as build target does not exist')

            try:
                previous_tags.append(self._call_api('getFullInheritance', tag)[0]['name'])
            except (KeyError, IndexError, koji.GenericError):
                self.warn("Failed to find inheritance tree for tag '{}'".format(tag), sentry=True)

        return previous_tags

    @cached_property
    def source(self):
        """
        Task's source, e.g. git+https://src.fedoraproject.org/rpms/rust-tokio-proto.git?#b59219

        By default try to get from build's info. Fallback to taskinfo's request[0] field.

        :rtype: str
        """

        if self.has_build and self._build.get('source', None):
            return self._build['source']

        if self._task_request.source:
            return self._task_request.source

        raise GlueError("task '{}' has no source defined in the request field".format(self.id))

    @cached_property
    def scratch(self):
        """
        Whether the task is a scratch build.

        :rtype: bool
        """

        return self._task_request.options.get('scratch', False)

    @cached_property
    def task_arches(self):
        """
        Return information about arches the task was building for.

        :rtype: TaskArches
        """

        arches = self._task_request.options.get('arch_override', None)

        if arches is not None:
            return TaskArches(False, [arch.strip() for arch in arches.split(' ')])

        return TaskArches(True, [child['arch'] for child in self._build_arch_subtasks])

    @cached_property
    def url(self):
        """
        URL of the task info web page.

        :rtype: str
        """

        return "{}/taskinfo?taskID={}".format(self.web_url, self.id)

    def latest_released(self, tags=None):
        """
        Returns task of the latest builds tagged with the same destination tag or build target.

        If no builds are found ``None`` is returned.

        In case the build found is the same as this build, the previous build is returned.

        The tags for checking can be overriden with the ``tags`` parameter. First match wins.

        :param list(str) tags: Tags to use for searching.
        :rtype: :py:class:`KojiTask`
        """
        tags = tags or [self.destination_tag, self.target]

        for tag in tags:
            try:
                builds = self._call_api('listTagged', tag, None, True, latest=2, package=self.component)
            except koji.GenericError as error:
                self.warn(
                    "ignoring error while listing latest builds tagged to '{}': {}".format(tag, error),
                    sentry=True
                )
                continue
            if builds:
                break
        else:
            log_dict(self.debug, "no latest builds found for package '{}' on tags".format(self.component), tags)
            return None

        # for scratch builds the latest released package is the latest tagged
        if self.scratch:
            build = builds[0]

        # for non scratch we return the latest released package, in case it is the same, the previously
        # released package
        else:
            if self.nvr != builds[0]['nvr']:
                build = builds[0]
            else:
                build = builds[1] if len(builds) > 1 else None

        if 'task_id' not in build:
            raise GlueError("No 'task_id' found for the build.")

        if build['task_id'] is None:
            raise GlueError('Could not fetch the build task_id.')

        return self._module.task_factory(TaskInitializer(task_id=build['task_id'], build_id=None)) if build else None

    @cached_property
    def latest(self):
        """
        NVR of the latest released package with the same build target, or ``None`` if none found.

        In case the latest package is the same as this task, the previosly released package's NVR is returned.

        :rtype: str
        """

        latest_released = self.latest_released()

        return latest_released.nvr if latest_released else None

    @cached_property
    def _tags_from_map(self):
        """
        Unfortunately tags used for looking up baseline builds need to be resolved
        from a rules file due to contradicting use cases.

        Nice examples for this are:

        * rhel-8 builds, which have ``destination_tag`` set to rhel-8.x.y-gate, but that
          is incorrrect for the lookup, we need to use the ``build_target``, which
          in this case is the final destination of the builds after gating

        * for some non-rhel products we have to use ``destination_tag`` only, because
          ``build_target`` is not a tag to which builds get tagged
        """

        self._module.require_shared('evaluate_instructions', 'evaluate_rules')

        # use dictionary which can be altered in _tags_callback
        map = {
            'tags': []
        }

        def _tags_callback(instruction, command, argument, context):
            map['tags'] = []

            for arg in argument:
                map['tags'].append(self._module.shared('evaluate_rules', arg, context=context))

        context = dict_update(self._module.shared('eval_context'), {
            'TASK': self
        })

        commands = {
            'tags': _tags_callback,
        }

        self._module.shared(
            'evaluate_instructions', self._module.baseline_tag_map,
            commands=commands, context=context
        )

        log_dict(self.debug, 'Tags from baseline tag map', map['tags'])

        return map['tags']

    @cached_property
    def baseline(self):
        """
        Return baseline task NVR if `baseline-method` specified, otherwise return None.

        :rtype: str
        """
        if not self._module.option('baseline-method'):
            return None

        return self.baseline_task.nvr

    @cached_property
    def baseline_task(self):
        """
        Return baseline task. For documentation of the baseline methods see the module's help.

        :rtype: KojiTask
        :returns: Initialized task for the baseline build or None if not baseline found.
        :raises gluetool.glue.GlueError: if specific build does not exist or no baseline-method specified.
        """
        method = self._module.option('baseline-method')

        if not method:
            raise GlueError("Cannot get baseline because no 'baseline-method' specified")

        if method == 'previous-released-build':
            previous_tags = self.previous_tags(tags=self._tags_from_map)
            if not previous_tags:
                return None

            baseline_task = self.latest_released(tags=previous_tags)

        elif method == 'previous-build':
            baseline_task = self.latest_released(tags=self._tags_from_map)

        elif method == 'specific-build':
            nvr = self._module.option('baseline-nvr')
            task_initializers = self._module._find_task_initializers(nvrs=[nvr])
            if not task_initializers:
                raise GlueError("Specific build with nvr '{}' not found".format(nvr))
            # we know we have just one initializer ...
            baseline_task = self._module.task_factory(task_initializers[0])

        else:
            # this really should not happen ...
            self.warn("Unknown baseline method '{}'".format(method), sentry=True)
            return None

        return baseline_task

    @cached_property
    def branch(self):
        return None

    @cached_property
    def task_artifacts(self):
        """
        Artifacts of ``buildArch`` subtasks, in a mapping where subtask IDs are the keys
        and lists of artifact names are the values.

        Usually, this is a mix of logs and RPMs, and gets empty when task's directory
        on the server is removed.

        :rtype: dict(int, list(str))
        """

        artifacts = {}

        for task in self._build_arch_subtasks:
            task_id = task['id']

            task_output = self._call_api('listTaskOutput', task_id)

            log_dict(self.debug, 'task output of subtask {}'.format(task_id), task_output)

            artifacts[task_id] = task_output

        log_dict(self.debug, 'subtask artifacts', artifacts)

        return artifacts

    @cached_property
    def build_artifacts(self):
        """
        Artifacts of the build, in a mapping where architectures are the keys
        and lists of artifact names are the values.

        Usualy, the set consists of RPMs only, and makes sense for builds only, since it is
        not possible to get task RPMs this way.

        :rtype: dict(str, list(str))
        """

        if not self.has_build:
            return {}

        build_rpms = self._call_api('listBuildRPMs', self.build_id)

        log_dict(self.debug, 'build RPMs', build_rpms)

        artifacts = collections.defaultdict(list)

        for rpm in build_rpms:
            artifacts[rpm['arch']].append(rpm)

        log_dict(self.debug, 'build rpms', artifacts)

        return artifacts

    @cached_property
    def build_archives(self):
        """
        A list of archives of the build.

        :rtype: list(dict)
        """

        if not self.has_build:
            return []

        archives = self._call_api('listArchives', buildID=self.build_id)
        log_dict(self.debug, 'build archives', archives)

        return archives

    @cached_property
    def has_artifacts(self):
        """
        Whether there are any artifacts on for the task.

        :rtype: bool
        """

        has_task_artifacts = [bool(subtask_artifacts) for subtask_artifacts in self.task_artifacts.itervalues()]
        has_build_artifacts = [bool(arch_artifacts) for arch_artifacts in self.build_artifacts.itervalues()]

        return bool(has_task_artifacts and all(has_task_artifacts)) \
            or bool(has_build_artifacts and all(has_build_artifacts))

    @cached_property
    def _srcrpm_subtask(self):
        """
        Search for SRPM-like artifact in ``buildArch`` subtasks, and if there is such artifact,
        provide its name and ID of its subtask. If no such artifact exists, both values are ``None``.

        :rtype: tuple(int, str)
        """

        if not self.has_artifacts:
            self.debug('task has no artifacts, it is pointless to search them for srpm')
            return None, None

        for subtask, artifacts in self.task_artifacts.iteritems():
            for artifact in artifacts:
                if not artifact.endswith('.src.rpm'):
                    continue

                return subtask, artifact

        return None, None

    @cached_property
    def srpm_names(self):
        """
        List of source RPM name or empty list if it's impossible to find it.

        :rtype: list(str)
        """

        if self._task_info['state'] != koji.TASK_STATES["CLOSED"]:
            raise GlueError('Task {} is not a successfully completed task'.format(self.id))

        # "build container" tasks have no SRPM
        if not self.is_build_task:
            return []

        # For standard (non-scratch) builds, we may fetch an associated build and dig info from it
        if self.has_build:
            self.debug('srpm name deduced from build')
            return ['{}.src.rpm'.format(self._build['nvr'])]

        # Search all known artifacts for SRPM-like files
        _, srcrpm = self._srcrpm_subtask

        if srcrpm is not None:
            self.debug('srpm name deduced from a subtask artifact')
            return [srcrpm]

        # Maybe it's in Source option!
        source = self._task_request.options.get('Source', None)
        if source:
            self.debug('srpm name deduced from task Source option')
            return [source.split('/')[-1].strip()]

        # Or in one of the subtasks!
        for subtask in self._build_arch_subtasks:
            if not subtask['request'].source:
                continue

            self.debug('srpm name deduced from subtask Source option')
            return [subtask['request'].source.split('/')[-1].strip()]

        # Nope, no SRPM anywhere.
        return []

    @cached_property
    def distgit_ref(self):
        """
        Distgit ref id from which package has been built or ``None`` if it's impossible to find it.

        :rtype: str
        """
        try:
            return self._task_request.source.split('#')[1].encode('ascii')
        except IndexError:
            self.debug('Distgit ref not found')
        return None

    @cached_property
    def _rpm_urls_from_subtasks(self):
        """
        Resolves RPM urls from subtasks' results. This is the only
        option for scratch rpm builds.
        """
        rpms = []

        for task in self._build_arch_subtasks:
            try:
                rpms.extend(self._call_api('getTaskResult', task['id'])['rpms'])
            except AttributeError:
                self.warn("No rpms found for task '{}'".format(task['id']))

        return ['/'.join([self.pkgs_url, 'work', rpm]) for rpm in rpms]

    @cached_property
    def _rpm_urls_from_build(self):
        """
        Resolves RPM urls from build rpms.
        """
        return [
            "{0}/packages/{1}/{2}/{3}/{4}/{5}.{4}.rpm".format(
                self.pkgs_url,
                self._build['package_name'],
                self._build['version'],
                self._build['release'],
                rpm['arch'],
                rpm['nvr'])
            for rpm in self._call_api('listBuildRPMs', self.build_id) if rpm['arch'] != 'src'
        ]

    @cached_property
    def rpm_urls(self):
        """
        List of URLs of all RPMs in the build.
        """
        if not self.is_build_task:
            return []

        # If build_id is around, use listRPMs to get all the builds
        if self.build_id:
            return self._rpm_urls_from_build

        # For scratch build tasks, our only option is to resolve RPMs from task.
        # If the task is expired (i.e. has no artifacts), the links will be 404.
        return self._rpm_urls_from_subtasks

    @cached_property
    def srpm_urls(self):
        """
        List of URL of the SRPM (:py:attr:`srcrpm`) or empty list if SRPM is not known.
        """

        if not self.srpm_names:
            return []

        if not self.scratch:
            return ["{}/packages/{}/{}/{}/src/{}.src.rpm".format(
                self.pkgs_url,
                self._build['package_name'],
                self._build['version'],
                self._build['release'],
                self._build['nvr']
            )]

        srcrpm_task, srcrpm = self._srcrpm_subtask

        # we have SRPM name but no parent task, i.e. it's not possible to construct URL
        if srcrpm_task is None:
            return []

        base_path = koji.pathinfo.taskrelpath(srcrpm_task)

        return ['/'.join(['{0}/work'.format(self.pkgs_url), base_path, srcrpm])]

    @cached_property
    def _split_srcrpm(self):
        """
        SRPM name split into its NVREA pieces.

        :raises gluetool.glue.GlueError: when SRPM name is not known.
        :rtype: tuple(str)
        """

        if not self.srpm_names:
            raise GlueError('Cannot find SRPM name')

        return splitFilename(self.srpm_names[0])

    @cached_property
    def nvr(self):
        """
        NVR of the built package.

        :rtype: str
        """

        if self.is_build_task:
            name, version, release, _, _ = self._split_srcrpm

            return '-'.join([name, version, release])

        raise GlueError('Cannot deduce NVR for task {}'.format(self.id))

    @cached_property
    def component(self):
        """
        Package name of the built package (``N`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_task:
            return self._split_srcrpm[0]

        raise GlueError('Cannot find component info for task {}'.format(self.id))

    @cached_property
    def dist_git_repository_name(self):
        """
        Extract dist-git repository name from the source field. This can be different from the package name.

        If repository name cannot be extracted from source (e.g. build built from src.rpm, not git) `component`
        property is returned.

        :rtype: str
        """

        try:
            # Examples of possible sources:
            #   git://pkgs.fedoraproject.org/rpms/bash?#d430777020da4c1e68807f59b0ffd38324adbdb7
            #   git://pkgs/rpms/mead-cron-scripts#dcdc64da7180ae49361756a373c8a5de3a59e732
            #   git+https://src.fedoraproject.org/rpms/bash.git#1f2779c9385142e93c875274eba0621e29a49146
            return re.match(r'.*/([^#\?]*)\??#.*', self.source).group(1)
        except (AttributeError, re.error) as error:
            self.debug('Could not extract component name from source field: {}'.format(error))

        return self.component

    @cached_property
    def version(self):
        """
        Version of the built package (``V`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_task:
            return self._split_srcrpm[1]

        raise GlueError('Cannot find version info for task {}'.format(self.id))

    @cached_property
    def release(self):
        """
        Release of the built package (``R`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_task:
            return self._split_srcrpm[2]

        raise GlueError('Cannot find release info for task {}'.format(self.id))

    @cached_property
    def full_name(self):
        """
        String with human readable task details. Used for slightly verbose representation e.g. in logs.

        :rtype: str
        """

        name = [
            "task '{}'".format(self.id),
            "build '{}'".format(self.nvr),
            "target '{}'".format(self.target)
        ]

        if self.scratch:
            name.append('(scratch)')

        if not self.has_artifacts:
            name.append('(no artifacts)')

        return ' '.join(name)

    @cached_property
    def short_name(self):
        """
        Short version of :py:attr:`full_name``.

        :rtype: str
        """

        return "{t.id}:{scratch}{t.nvr}".format(t=self, scratch='S:' if self.scratch else '')

    @cached_property
    def destination_tag(self):
        """
        Build destination tag
        """

        try:
            return self._call_api('getBuildTarget', self.target)["dest_tag_name"]
        except TypeError:
            return None

    @cached_property
    def component_id(self):
        """
        Used by task dispatcher to search their configurations. Identifies the component the task belongs to.

        :rtype: str
        """

        return self.component

    def compare_nvr(self, nvr):
        """
        Do an NVR comparison with given nvr.

        :rtype: int
        :returns: 0 if NVRs are same, 1 if artifact has higher version, -1 if artifact has lower version
        """

        if not nvr:
            return 1

        try:
            (name, version, release) = re.match(r'(.*)-(.*)-(.*)', nvr).groups()
        except AttributeError:
            raise GlueError("nvr '{}' seems to be invalid".format(nvr))

        if self.component != name:
            raise GlueError("Compared nvrs belong to different components {} {}".format(self.component, nvr))

        # Since `labelCompare` compares EVR (epoch, version, release) and we have only VR
        # we have to add `0` as dummy epoch to both sides
        return labelCompare(('0', self.version, self.release), ('0', version, release))

    @cached_property
    def is_newer_than_latest(self):
        return self.compare_nvr(self.latest) > 0


class BrewTask(KojiTask):
    """
    Provides abstraction of a brew build task, specified by task ID. For initialization
    brew instance details need to be passed via the instance dictionary with the following keys:

        ``automation_user_ids`` - list of user IDs that trigger resolving of user from dist git
        ``session`` - a koji session initialized via the koji.ClientSession function
        ``url`` - a base URL for the koji instance
        ``pkgs_url`` - a base URL for the packages location

    This class extends :py:class:`KojiTask` with Brew only features.

    :param dict instance: Instance details, see ``required_instance_keys``
    :param int task_id: Initialize from given TaskID
    :param module: Module that created this task instance.
    :param gluetool.log.ContextLogger logger: logger used for logging
    :param bool wait_timeout: Wait for task to become non-waiting
    """

    ARTIFACT_NAMESPACE = 'brew-build'

    def _check_required_instance_keys(self, details):
        """
        Checks for required instance details for Brew.
        :raises: GlueError if instance is missing some of the required keys
        """
        required_instance_keys = ('automation_user_ids', 'session', 'url', 'pkgs_url')

        if not all(key in details for key in required_instance_keys):
            raise GlueError('instance details do not contain all required keys')

    def __init__(self, details, task_id, module, logger=None, wait_timeout=None, build_id=None):
        super(BrewTask, self).__init__(details, task_id, module,
                                       logger=logger,
                                       wait_timeout=wait_timeout,
                                       build_id=build_id)

        self.automation_user_ids = details['automation_user_ids']

        if self.is_build_container_task:
            # Try to assign build for container task only when there was no build ID specified.
            # If `build_id` is set, we already have a build, specified explicitly by the caller.

            if build_id is None:
                if not self._result:
                    raise GlueError('Container task {} does not have a result'.format(self.id))

                if 'koji_builds' not in self._result or not self._result['koji_builds']:
                    self.warn('Container task {} does not have a build assigned'.format(self.id))

                else:
                    self._assign_build(int(self._result['koji_builds'][0]))

            # Container builds need specific dispatch ID - given how broken is the integration
            # between Brew and image building service, build ID nor task ID are not enough.
            if self.build_id:
                self.dispatch_id = '{}:{}'.format(self.build_id, self.id)

    @cached_property
    def is_build_container_task(self):
        return self._task_info['method'] == 'buildContainer'

    @cached_property
    def has_artifacts(self):
        """
        Whether there are any artifacts on for the task.

        :rtype: bool
        """

        if self.is_build_container_task:
            return bool(self.build_archives) or (self.image_repositories)

        return super(BrewTask, self).has_artifacts

    @cached_property
    def source_members(self):
        """
        Return :py:attr:`source` attribute split into its pieces, a component and a GIT commit hash.

        :rtype: tuple(str, str)
        """

        # It might be worth moving this into a config file, it's way too dependant on Brew internals

        def _split(namespace):
            try:
                git_hash = re.search("#[^']*", self.source).group()[1:]
                component = re.search("/{}/([^#?]*)".format(namespace), self.source).group(1)

                return component, git_hash

            except AttributeError:
                return None, None

        self.debug("source '{}'".format(self.source))

        component, git_hash = None, None

        # docker containers are usualy under "containers" namespace
        if self.is_build_container_task:
            component, git_hash = _split('containers')

        log_dict(self.debug, 'source members after "containers" namespace split attempt', [
            component, git_hash
        ])

        # but, some containers still reside under "rpms", like the common components
        if component is None and git_hash is None:
            component, git_hash = _split('rpms')

        log_dict(self.debug, 'source members after "rpms" namespace split attempt', [
            component, git_hash
        ])

        return component, git_hash

    @cached_property
    def _parsed_commit_html(self):
        """
        :returns: BeatifulSoup4 parsed html from cgit for given component and commit hash
        """

        component, git_hash = self.source_members

        if not component or not git_hash:
            return None

        context = dict_update(self._module.shared('eval_context'), {
                'SOURCE_COMPONENT': component,
                'SOURCE_COMMIT': git_hash
            })

        overall_urls = []

        # Callback for 'url' command
        def _url_callback(instruction, command, argument, context):
            overall_urls[:] = [
                render_template(arg, **context) for arg in argument
            ]

            self.debug("final dist git url set to '{}'".format(overall_urls))

        commands = {
            'url': _url_callback,
        }

        self._module.shared(
            'evaluate_instructions', self._module.repo_url_map,
            commands=commands, context=context
        )

        # get git commit html
        for url in overall_urls:
            # Using `wait` for retries would be much easier if we wouldn't be interested
            # in checking another URL - that splits errors into two sets, with different
            # solutions: the first one are "accepted" errors (e.g. URL is wrong), and we
            # want to move on and try another URL, the second set is not so good, and we
            # have to retry once again for the same URL, hoping for better results.

            # We can safely ignore "Cell variable url defined in loop" warning - yes, `url`
            # is updated by the loop and `_fetch` is called with the most actual value of
            # `url`, but that is correct.
            def _fetch():
                try:
                    with gluetool.utils.requests(logger=self.logger) as req:
                        res = req.get(url, timeout=self._module.option('commit-fetch-timeout'))

                    if res.ok:
                        return Result.Ok(BeautifulSoup(res.content, 'html.parser'))

                    # Special case - no such URL, we should stop dealing with this one and try another.
                    # Tell `wait` control code to quit.
                    if res.status_code == 404:
                        return Result.Ok(True)

                    # Ignore (possibly transient) HTTP errors 5xx - server knows it encountered an error
                    # or is incapable of finishing the request now. Try again.
                    if 500 <= res.status_code <= 599:
                        return Result.Error('transient HTTP error')

                    # Other not-ok-ish codes should be reported, they probably are not going do disappear
                    # on their own and signal something is really wrong.
                    res.raise_for_status()

                except (requests.exceptions.Timeout,
                        requests.exceptions.ConnectionError,
                        requests.exceptions.RequestException):

                    # warn as we needed to retry
                    self.warn("Failed to fetch commit info from '{}' (retrying)".format(url))

                    return Result.Error('connection error')

                return Result.Error('unknown error')

            ret = wait('fetching commit web page', _fetch,
                       logger=self.logger,
                       timeout=self._module.option('commit-fetch-timeout'),
                       tick=self._module.option('commit-fetch-tick'))

            # If our `_fetch` returned `True`, it means it failed to fetch the commit
            # page *in the expected* manner - e.g. the page does not exist. Issues like
            # flapping network would result in another spin of waiting loop.
            if ret is True:
                continue

            return ret

        return None

    @cached_property
    def nvr(self):
        """
        NVR of the built package.

        :rtype: str
        """

        if self.is_build_container_task:
            if self.has_build:
                return self._build['nvr']

            return '-'.join([self.component, self.version, self.release])

        return super(BrewTask, self).nvr

    @cached_property
    def component(self):
        """
        Package name of the built package (``N`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_container_task:
            if self.has_build:
                return self._build['package_name']

            component, _ = self.source_members

            if component:
                # Source repository is named 'foo-bar', but the component name - as known to Brew and Bugzilla - is
                # actually foo-bar-container. Add the suffix.
                # This is not necessary when there's a build (which means non-scratch tasks), in that case we're
                # using build's package_name as the source, and that's correct already.

                # This is another good candidate for a mapping file - insert task, let configuration
                # yield the component.
                return '{}-container'.format(component)

        return super(BrewTask, self).component

    @cached_property
    def version(self):
        """
        Version of the built package (``V`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_container_task:
            # if there's a build, the versions should be there
            if self.has_build:
                return self._build['version']

            # It's not there? Ah, we have to inspect manifests, it might be there. So much work :/
            # It should be the same in all repositories - it's the same image, with the same metadata.
            # Just check all manifests we have.
            for i, repository in enumerate(self.image_repositories):
                for j, entry in enumerate(repository.manifest.get('history', [])):
                    data = gluetool.utils.from_json(entry.get('v1Compatibility', '{}'))
                    log_dict(self.debug, 'repository #{}, history entry #{}'.format(i, j), data)

                    version = data.get('config', {}).get('Labels', {}).get('version', None)
                    self.debug("version extracted: '{}'".format(version))

                    if version:
                        return version

            # Nope, no idea where else to look for release...
            return 'UNKNOWN-VERSION'

        return super(BrewTask, self).version

    @cached_property
    def release(self):
        """
        Release of the built package (``R`` of ``NVR``).

        :rtype: str
        """

        if self.is_build_container_task:
            # if there's a build, the release should be there
            if self.has_build:
                return self._build['release']

            # ok, it might be in task request!
            release = self._task_request.options.get('release', None)

            if release:
                return release

            # It's not there? Ah, we have to inspect manifests, it might be there. So much work :/
            # It should be the same in all repositories - it's the same image, with the same metadata.
            # Just check all manifests we have
            for i, repository in enumerate(self.image_repositories):
                for j, entry in enumerate(repository.manifest.get('history', [])):
                    data = gluetool.utils.from_json(entry.get('v1Compatibility', '{}'))
                    log_dict(self.debug, 'repository #{}, history entry #{}'.format(i, j), data)

                    release = data.get('config', {}).get('Labels', {}).get('release', None)
                    self.debug("release extracted: '{}'".format(release))

                    if release:
                        return release

            # Nope, no idea where else to look for release...
            return 'UNKNOWN-RELEASE'

        return super(BrewTask, self).release

    @cached_property
    def branch(self):
        """
        :returns: git branches of brew task or None if branch could not be found
        """

        # Docker image builds provide this in task' options. If it's not there, just fall back to the old way.
        if self.is_build_container_task:
            git_branch = self._task_request.options.get('git_branch', None)

            if git_branch:
                return git_branch

        if self._parsed_commit_html is None:
            return None

        try:
            branches = [branch.string for branch in self._parsed_commit_html.find_all(class_='branch-deco')]
            return ' '.join(branches)
        except AttributeError:
            raise GlueError("could not find 'branch-deco' class in html output of cgit, please inspect")

    @cached_property
    def issuer(self):
        """
        :returns: issuer of brew task and in case of build from automation, returns issuer of git commit
        """
        owner_id = self._task_info["owner"]
        if owner_id not in self.automation_user_ids:
            return self.owner

        if self.source.endswith('.src.rpm'):
            self.info('Build was built from src.rpm, skipping detection from dist-git as commit is unknown')
            return self.owner

        self.info("Automation user detected, need to get git commit issuer")

        if self._parsed_commit_html is None:
            self.warn('could not find git commit issuer', sentry=True)
            return self.owner

        issuer = self._parsed_commit_html.find(class_='commit-info').find('td')
        issuer = re.sub(".*lt;(.*)@.*", "\\1", str(issuer))

        return issuer

    @cached_property
    def rhel(self):
        """
        :returns: major version of RHEL
        """
        return re.sub(".*rhel-(\\d+).*", "\\1", self.target)

    @cached_property
    def task_arches(self):
        """
        Return information about arches the task was building for.

        :rtype: TaskArches
        """

        if self.is_build_container_task:
            arches = []

            if self.has_build:
                for archive in self.build_archives:
                    if archive['btype'] != 'image':
                        continue

                    arches.append(archive['extra']['image']['arch'])

            else:
                # This is workaround for Brew deficiency: the image architecture is *not* mentioned anywhere
                # in Brew API responses. For regular builds, it's in build info, for scratch builds - nowhere :/
                # Only relevant source is the actual image itself...
                arches = [
                    repository.arch for repository in self.image_repositories
                ]

            return TaskArches(False, arches)

        return super(BrewTask, self).task_arches

    @cached_property
    def build_archives(self):
        """
        A list of archives of the build.

        Overriding parent method to enhance image archives with image URL.

        :rtype: list(dict)
        """

        archives = super(BrewTask, self).build_archives

        if self.is_build_container_task:
            context = dict_update(self._module.shared('eval_context'), {
                'MODULE': self._module,
                'TASK': self
            })

            for archive in archives:
                if archive.get('btype', None) != 'image':
                    continue

                archive['image_url'] = render_template(self._module.option('docker-image-url-template'),
                                                       logger=self.logger,
                                                       ARCHIVE=archive, **context)

        return archives

    @cached_property
    def image_repositories(self):
        """
        A list of Docker image repositories build by the task.

        :rtype: list(dict)
        """

        if not self._result:
            return []

        if 'repositories' not in self._result:
            return []

        log_dict(self.debug, 'raw image repositories', self._result['repositories'])

        # Task provides usually more than one repository, and often some of them lead to the same image.
        # We want to provide our users list of unique repositories (images). To do that, we have to check
        # each repository, find out what is the ID of the image, and group them by their corresponding images.
        # By checking the image manifest, we get access to image architecture as well - this is important,
        # there is no other place to get this info from for scratch container builds, it's not in Brew task
        # info nor result.

        images = {}

        for repository_url in self._result['repositories']:
            # split repository URL into parts
            match = re.match('(.*?)/(.*?):(.*)$', repository_url)
            if match is None:
                self.warn("Cannot decypher repository URL '{}'".format(repository_url), sentry=True)
                continue

            netloc, image_name, reference = match.groups()

            manifest_url = 'http://{}/v2/{}/manifests/{}'.format(netloc, image_name, reference)
            self.debug("manifest URL: '{}'".format(manifest_url))

            # manifest = requests.get(manifest_url).json()
            _, content = gluetool.utils.fetch_url(manifest_url, logger=self.logger)
            manifest = gluetool.utils.from_json(content)

            log_dict(self.debug, '{} manifest'.format(repository_url), manifest)

            # With v2 manifests, we'd just look up image ID. With v1, there's no such field, but different URLs,
            # leading to the same image, should have same FS layers.
            image_id = tuple([
                layer['blobSum'] for layer in manifest['fsLayers']
            ])

            image_arch = manifest['architecture']

            # translate arch from dockerish to our world
            if image_arch == 'amd64':
                image_arch = 'x86_64'

            if image_id in images:
                # We've already seen this image
                image = images[image_id]

            else:
                # First time seeing this image
                image = images[image_id] = {
                    'arch': image_arch,
                    # there can be multiple "repositories", URLs leading to this image
                    'repositories': [],
                    # they should provide the same manifest though - no list then, just store the first one
                    'manifest': manifest
                }

            if image['arch'] != image_arch:
                # This should not happen. URLs leading to the same image should have the same architecture.
                # If it happens, must investigate.
                raise GlueError('Mismatching repository architectures')

            image['repositories'].append(repository_url)

        # Now, we must find the most specific URL for each image - under `repositories` key, there's a list
        # of URLs leading to the same image. Pretty naive but quite successfull method could be finding the
        # longest one - whatever the image name might be, the longest URL should have a timestamp-like value
        # at the end, which would make it longer than any other.

        # And we're still returning "repositories", not "images" - above, we've been gathering images, to deal
        # with different URLs leading to the same image, but we want to return them as repositories, as these
        # are the task artifacts.
        repositories = [
            ImageRepository(image['arch'], max(image['repositories'], key=len), image['repositories'], image['manifest'])  # noqa
            for image in images.itervalues()  # noqa
        ]

        log_dict(self.debug, 'image repositories', repositories)

        return repositories


class Koji(gluetool.Module):
    """
    Provide various information related to a task from Koji build system.

    The task can be specified using on the command line with
        - option ``--build-id`` with a build ID
        - options ``--name`` and ``--tag`` with the latest build from the given tag
        - option ``--nvr`` with a string with an NVR of a build
        - option ``--task-id`` with a build task ID

    The task can be specified also by using the ``task`` shared function. The shared function
    supports only initialization from task ID.

    If option ``--baseline-method`` is specified, the module finds a baseline build according
    to given method and exposes it under ``baseline_task`` attribute of the primary task. The following
    baseline methods are supported:

    * ``previous-build`` - finds the previously built package on the same tag
    * ``previous-released-build`` - finds the previously released build, i.e. build tagged to the previous
                                  tag according to the tag inheritance
    * ``specific-build`` - finds the build specified with ``--baseline-nvr`` option

    For the baseline methods it is expected to provide a rules file via the ``--baseline-tag-map`` option
    which provides a list of tags which will be used to lookup. Each rule needs to provide `tags` attribute
    with list of possible values. Each list item is interpreted as a rule. All rules are evaluated and the
    last matching wins. Below is an example we use now:

    .. code-block:: yaml

        - tags:
            - TASK.destination_tag
            - TASK.target

        - rule: MATCH('.*-gate$', TASK.destination_tag)
          tags:
            - SUB(r'([^-]*)-([^-]*)-.*', r'\1-\2-candidate', TASK.target)
    """

    name = 'koji'
    description = 'Provide Koji task details to other modules'
    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    options = (
        ('General options', {
            'url': {
                'help': 'Koji Hub instance base URL',
            },
            'pkgs-url': {
                'help': 'Koji packages base URL',
            },
            'web-url': {
                'help': 'Koji instance web ui URL',
            },
            'task-id': {
                'help': 'Initialize from task ID (default: none).',
                'action': 'append',
                'default': [],
                'type': int
            },
            'build-id': {
                'help': 'Initialize from build ID (default: none).',
                'action': 'append',
                'default': [],
                'type': int
            },
            'name': {
                'help': """
                        Initialize from package name, by choosing latest tagged build (requires ``--tag``)
                        (default: none).
                        """,
                'action': 'append',
                'default': []
            },
            'nvr': {
                'help': 'Initialize from package NVR (default: none).',
                'action': 'append',
                'default': []
            },
            'tag': {
                'help': 'Use given build tag.',
            },
            'valid-methods': {
                'help': """
                        List of task methods that are considered valid, e.g. ``build`` or ``buildContainer``
                        (default: none, i.e. any method is considered valid).
                        """,
                'metavar': 'METHOD1,METHOD2,...',
                'action': 'append',
                'default': []
            },
            'wait': {
                'help': 'Wait timeout for task to become non-waiting and closed (default: %(default)s)',
                'type': int,
                'default': 60,
            }
        }),
        ('Baseline options', {
            'baseline-method': {
                'help': 'Method for choosing the baseline package.',
                'choices': ['previous-build', 'specific-build', 'previous-released-build'],
                'metavar': 'METHOD',
            },
            'baseline-nvr': {
                'help': "NVR of the build to use with 'specific-build' baseline method",
            },
            'baseline-tag-map': {
                'help': 'Optional rules providing tags which are used for finding baseline package'
            }
        }),
        ('Workarounds', {
            'accept-failed-tasks': {
                'help': """
                        If set, even failed task will be accepted without stopping the pipeline (default: %(default)s).
                        """,
                'metavar': 'yes|no',
                'default': 'no'
            },
            'commit-fetch-timeout': {
                'help': """
                        The maximum time for trying to fetch one (dist-git) URL with commit info
                        (default: %(default)s).
                        """,
                'metavar': 'SECONDS',
                'type': int,
                'default': DEFAULT_COMMIT_FETCH_TIMEOUT
            },
            'commit-fetch-tick': {
                'help': """
                        Delay between attempts to fetch one (dist-git) URL with commit info failed
                        (default: %(default)s).
                        """,
                'metavar': 'SECONDS',
                'type': int,
                'default': DEFAULT_COMMIT_FETCH_TICKS
            },
        })
    )

    options_note = """
    Options ``--task-id``, ``--build-id``, ``--name`` and ``--nvr`` can be used multiple times, and even mixed
    together, to specify tasks for a single pipeline in many different ways.
    """

    required_options = ['url', 'pkgs-url', 'web-url']
    shared_functions = ('tasks', 'primary_task', 'koji_session')

    def __init__(self, *args, **kwargs):
        super(Koji, self).__init__(*args, **kwargs)

        self._session = None
        self._tasks = []

    @cached_property
    def _valid_methods(self):
        return gluetool.utils.normalize_multistring_option(self.option('valid-methods'))

    @cached_property
    def baseline_tag_map(self):
        if not self.option('baseline-tag-map'):
            return []

        return gluetool.utils.load_yaml(self.option('baseline-tag-map'))

    def task_factory(self, task_initializer, wait_timeout=None, details=None, task_class=None):
        task_class = task_class or KojiTask

        details = dict_update({
            'session': self._session,
            'url': self.option('url'),
            'pkgs_url': self.option('pkgs-url'),
            'web_url': self.option('web-url'),
        }, details or {})

        task = task_class(details, task_initializer.task_id, self,
                          logger=self.logger,
                          wait_timeout=wait_timeout if wait_timeout else self.option('wait'),
                          build_id=task_initializer.build_id)

        return task

    def _call_api(self, method, *args, **kwargs):
        return _call_api(self._session, self.logger, method, *args, **kwargs)

    def _objects_to_builds(self, name, object_ids, finder):
        if not object_ids:
            return []

        log_dict(self.debug, 'finding builds for {} ids'.format(name), object_ids)

        builds = []

        for object_id in object_ids:
            build = finder(object_id)

            log_dict(self.debug, "for '{}' found".format(object_id), build)

            if None in build:
                self.warn('Looking for {} {}, remote server returned None - skipping this ID'.format(name, object_id))
                continue

            builds += build

        log_dict(self.debug, 'found builds', builds)

        return builds

    def _find_task_initializers(self,
                                task_initializers=None,
                                task_ids=None,
                                build_ids=None,
                                nvrs=None,
                                names=None):
        """
        Tries to gather all available task IDs for different given inputs - build IDs, NVRs, package names
        and actual task IDs as well. Some of these may be unknown to the backend, some of them may not lead
        to a task ID. This helper method will find as many task IDs as possible.

        :param list(TaskInitializer) task_initializers: if set, it is a list of already found tasks. New ones
            are added to this list.
        :param list(int) task_ids: Task IDs
        :param list(int) build_ids: Build IDs.
        :param list(str) nvrs: Package NVRs.
        :param list(str) names: Package names. The latest build with a tag - given via module's ``--tag``
            option - is the possible solution.
        :rtype: list(TaskInitializer)
        :return: Gathered task initializers.
        """

        log_dict(self.debug, '[find task initializers] task initializers', task_initializers)
        log_dict(self.debug, '[find task initializers] from task IDs', task_ids)
        log_dict(self.debug, '[find task initializers] from build IDs', build_ids)
        log_dict(self.debug, '[find task initializers] from NVRs', nvrs)
        log_dict(self.debug, '[find task initializers] from names', names)

        task_initializers = task_initializers or []

        # Task IDs are easy.
        task_ids = task_ids or []

        task_initializers += [
            TaskInitializer(task_id=task_id, build_id=None) for task_id in task_ids
        ]

        # Other options represent builds, and from those builds we must extract their tasks. First, let's find
        # all those builds.
        builds = []

        builds += self._objects_to_builds('build', build_ids,
                                          lambda build_id: [self._call_api('getBuild', build_id)])
        builds += self._objects_to_builds('nvr', nvrs,
                                          lambda nvr: [self._call_api('getBuild', nvr)])
        builds += self._objects_to_builds('name', names,
                                          lambda name: self._call_api('listTagged',
                                                                      self.option('tag'),
                                                                      package=name,
                                                                      inherit=True,
                                                                      latest=True))

        # Now extract task IDs.
        for build in builds:
            if 'task_id' not in build or not build['task_id']:
                log_dict(self.debug, '[find task initializers] build does not provide task ID', build)
                continue

            task_initializers.append(
                TaskInitializer(task_id=int(build['task_id']), build_id=int(build['build_id']))
            )

        log_dict(self.debug, '[find task initializers] found initializers', task_initializers)

        return task_initializers

    def koji_session(self):
        return self._session

    def _assert_tasks(self):
        if not self._tasks:
            self.debug('No tasks specified.')

    def tasks(self, task_initializers=None, task_ids=None, build_ids=None, nvrs=None, names=None, **kwargs):
        """
        Returns a list of current tasks. If options are specified, new set of tasks is created using
        the provided options to find all available tasks, and this set becomes new set of current tasks,
        which is then returned.

        Method either returns non-empty list of tasks, or raises an exception

        :param list(TaskInitializer) task_initializers: Task initializers.
        :param list(int) task_ids: Task IDs
        :param list(int) build_ids: Build IDs.
        :param list(str) nvr: Package NVRs.
        :param list(str) names: Package names. The latest build with a tag - given via module's ``--tag``
            option - is the possible solution.
        :param dict kwargs: Additional arguments passed to :py:meth:`task_factory`.
        :rtype: list(KojiTask)
        :returns: Current task instances.
        :raises gluetool.glue.GlueError: When there are no tasks.
        """

        # Re-initialize set of current tasks only when any of the options is set.
        # Otherwise leave it untouched.
        task_initializers = task_initializers or []

        if any([task_initializers, task_ids, build_ids, nvrs, names]):
            task_initializers = self._find_task_initializers(
                task_initializers=task_initializers,
                task_ids=task_ids,
                build_ids=build_ids,
                nvrs=nvrs, names=names
            )

            self._tasks = [
                self.task_factory(task_initializer, **kwargs)
                for task_initializer in task_initializers
            ]

        self._assert_tasks()

        return self._tasks

    def primary_task(self):
        """
        Returns a `primary` task, the first task in the list of current tasks.

        Method either returns a task, or raises an exception.

        :rtype: :py:class:`KojiTask`
        :raises gluetool.glue.GlueError: When there are no tasks, therefore not even a primary one.
        """

        log_dict(self.debug, 'primary task - current tasks', self._tasks)

        self._assert_tasks()

        return self._tasks[0] if self._tasks else None

    @property
    def eval_context(self):
        __content__ = {  # noqa
            # common for all artifact providers
            'ARTIFACT_TYPE': """
                             Type of the artifact, either ``koji-build`` or ``brew-build``.
                             """,
            'BUILD_TARGET': """
                            Build target of the primary task, as known to Koji/Brew.
                            """,
            'NVR': """
                   NVR of the primary task.
                   """,
            'PRIMARY_TASK': """
                            Primary task, represented as ``KojiTask`` or ``BrewTask`` instance.
                            """,
            'TASKS': """
                     List of all tasks known to this module instance.
                     """,

            # Brew/Koji specific
            'SCRATCH': """
                       ``True`` if the primary task represents a scratch build, ``False`` otherwise.
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
            'TASKS': self.tasks(),

            # Brew/Koji specific
            'SCRATCH': primary_task.scratch
        }

    def sanity(self):
        # make sure that no conflicting options are specified

        # name option requires tag
        if self.option('name') and not self.option('tag'):
            raise IncompatibleOptionsError("You need to specify 'tag' with package name")

        # name option requires tag
        if self.option('tag') and not self.option('name'):
            raise IncompatibleOptionsError("You need to specify package name with '--name' option")

        method = self.option('baseline-method')
        if method and method == 'specific-build' and not self.option('baseline-nvr'):
            raise IncompatibleOptionsError("You need to specify build NVR with '--baseline-nvr' option")

    def execute(self):
        url = self.option('url')
        wait_timeout = self.option('wait')

        self._session = koji.ClientSession(url)
        version = self._call_api('getAPIVersion')
        self.info('connected to {} instance \'{}\' API version {}'.format(self.unique_name, url, version))

        task_initializers = self._find_task_initializers(
            task_ids=self.option('task-id'),
            build_ids=self.option('build-id'),
            nvrs=normalize_multistring_option(self.option('nvr')),
            names=normalize_multistring_option(self.option('name'))
        )

        if task_initializers:
            self.tasks(task_initializers=task_initializers, wait_timeout=wait_timeout)

        for task in self._tasks:
            self.info('Initialized with {}: {} ({})'.format(task.id, task.full_name, task.url))

            # init baseline build if requested
            if self.option('baseline-method'):
                if task.baseline_task:
                    self.info('Baseline build: {} ({})'.format(task.baseline_task.nvr, task.baseline_task.url))
                else:
                    self.warn('Baseline build was not found')


class Brew(Koji, (gluetool.Module)):
    """
    Provide various information related to a task from Brew build system.

    The task can be specified using on the command line with
        - option ``--build-id`` with a build ID
        - options ``--name`` and ``--tag`` with the latest build from the given tag
        - option ``--nvr`` with a string with an NVR of a build
        - option ``--task-id`` with a build task ID

    The task can be specified also by using the ``task`` shared function. The shared function
    supports only initialization from task ID.

    If option ``--baseline-method`` is specified, the module finds a baseline build according
    to given method and exposes it under ``baseline_task`` attribute of the primary task. The following
    baseline methods are supported:

    * ``previous-build`` - finds the previously built package on the same tag
    * ``previous-released-build`` - finds the previously released build, i.e. build tagged to the previous
                                  tag according to the tag inheritance
    * ``specific-build`` - finds the build specified with ``--baseline-nvr`` option

    For the baseline methods it is expected to provide a rules file via the ``--baseline-tag-map`` option
    which provides a list of tags which will be used to lookup. Each rule needs to provide `tags` attribute
    with list of possible values. Each list item is interpreted as a rule. All rules are evaluated and the
    last matching wins. Below is an example we use now:

    .. code-block:: yaml

        - tags:
            - TASK.destination_tag
            - TASK.target

        - rule: MATCH('.*-gate$', TASK.destination_tag)
          tags:
            - SUB(r'([^-]*)-([^-]*)-.*', r'\1-\2-candidate', TASK.target)
    """
    name = 'brew'
    description = 'Provide Brew task details to other modules'

    # Koji.options contain hard defaults
    options = Koji.options + (
        ('Brew options', {
            'automation-user-ids': {
                'help': 'List of comma delimited user IDs that trigger resolving of issuer from dist git commit instead'
            },
            'docker-image-url-template': {
                'help': """
                        Template for constructing URL of a Docker image. It is given a task (``TASK``)
                        and an archive (``ARCHIVE``) describing the image, as returned by the Koji API.
                        """
            },
            'repo-url-map': {
                'help': 'File with URLs of repositories.'
            }
        }),  # yes, the comma is correct - `)` closes inner tuple, `,` says it is part of the outer tuple
    )

    required_options = Koji.required_options + [
        'automation-user-ids', 'docker-image-url-template'
    ]

    @cached_property
    def repo_url_map(self):
        if not self.option('repo-url-map'):
            return []

        return gluetool.utils.load_yaml(self.option('repo-url-map'), logger=self.logger)

    def task_factory(self, task_initializer, wait_timeout=None, details=None, task_class=None):
        # options checker does not handle multiple modules in the same file correctly, therefore it
        # raises "false" negative for the following use of parent's class options
        details = dict_update({}, {
            'automation_user_ids': [int(user.strip()) for user in self.option('automation-user-ids').split(',')]
        }, details or {})

        return super(Brew, self).task_factory(task_initializer, details=details, task_class=BrewTask,
                                              wait_timeout=wait_timeout if wait_timeout else self.option('wait'))

    def _find_task_initializers(self, task_initializers=None, build_ids=None, **kwargs):
        """
        Containers integration with Brew is messy.

        Some container builds may not set their ``task_id`` property, instead there's
        an ``extra.container_koji_task_id`` key. This method tries to extract task ID
        from such builds.

        If such build is detected, this method creates a task initializer, preserving
        the build ID. The original ``_find_task_initializers`` is then called to deal
        with the rest of arguments. Given that this method tries to extract data from
        builds, extending list of task initializers, it is interested only in a limited
        set of parameters its original accepts, therefore all remaining keyword arguments
        are passed to the overriden ``_find_task_initializers``.

        :param list(TaskInitializer) task_initializers: if set, it is a list of already found tasks. New ones
            are added to this list.
        :param list(int) build_ids: Build IDs.
        :rtype: list(int)
        :return: Gathered task IDs.
        """

        log_dict(self.debug, '[find task initializers - brew] task initializers', task_initializers)
        log_dict(self.debug, '[find task initializers - brew] from build IDs', build_ids)
        log_dict(self.debug, '[find task initializers - brew] other params', kwargs)

        task_initializers = task_initializers or []
        build_ids = build_ids or []

        # Just like the original, fetch builds for given build IDs
        builds = self._objects_to_builds('build', build_ids,
                                         lambda build_id: [self._call_api('getBuild', build_id)])

        # Check each build - if it does have task_id, it passes through. If it does not have task_id,
        # but it does have extras.container_koji_task_id, we create an initializer (with the correct
        # task and build IDs), but we drop the build from list of builds we were given - we don't
        # want it there anymore because it was already converted to a task initializer.
        #
        # If there's no task ID at all, just let the build pass through, our parent will deal with
        # it somehow, we don't have to care.
        cleansed_build_ids = []

        for build_id, build in zip(build_ids, builds):
            if 'task_id' in build and build['task_id']:
                cleansed_build_ids.append(build_id)
                continue

            if 'extra' not in build or not 'container_koji_task_id':
                cleansed_build_ids.append(build_id)
                continue

            log_dict(self.debug, 'build provides container koji task ID', build)

            task_initializers.append(
                TaskInitializer(task_id=int(build['extra']['container_koji_task_id']), build_id=int(build_id))
            )

        log_dict(self.debug, '[find task initializers - brew] found task initializers', task_initializers)

        return super(Brew, self)._find_task_initializers(
            task_initializers=task_initializers,
            build_ids=cleansed_build_ids,
            **kwargs
        )
