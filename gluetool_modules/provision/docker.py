# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import random
import time

import gluetool
from gluetool import GlueError, GlueCommandError
from gluetool.result import Result
import gluetool_modules.libs.guest

from gluetool_modules.libs.testing_environment import TestingEnvironment

from typing import Any, Dict, List, Optional, Tuple, cast  # noqa


DEFAULT_NAME = 'citool'


def rand_id():
    # type: () -> int
    return random.randint(0, 999999999)


class Image(object):
    """
    Thin wrapper around Docker's image instance, providing few helper methods.

    :param str image: image ID as understood by Docker.
    :param str name: image name as presented to the user - often consits of "repository" and "tag" elements.
    :ivar str name: image name as presented to the user - often consits of "repository" and "tag" elements.
    :ivar str full_id: Docker image ID in its long form.
    :ivar str short_id: Docker image ID in its short form (cca 12 characters).
    """

    @staticmethod
    def image_by_id(docker, image_id):
        # type: (Any, str) -> Image
        """
        Create ``Image`` instance from Docker image ID.
        """

        return Image(docker.images.get(image_id))

    @staticmethod
    def image_by_name(docker, image_name):
        # type: (Any, str) -> Image
        """
        Create ``Image`` instance from human-readable name.
        """

        return Image(docker.images.get(image_name), name=image_name)

    def __init__(self, image, name=None):
        # type: (Any, Optional[str]) -> None
        self._image = image
        self.name = name

        self.full_id = image.id.split(':')[1]
        self.short_id = image.short_id.split(':')[1]

    def __repr__(self):
        # type: () -> str
        name = self.name if self.name is not None else '<unknown name>'

        return "'{}' ({})".format(name, self.full_id)

    @property
    def attrs(self):
        # type: () -> Any
        """
        Return image attributes as provided by Docker API.

        :rtype: dict
        """

        self._image.reload()

        return self._image.attrs


class DockerGuest(gluetool_modules.libs.guest.Guest):
    """
    Guest backed by Docker containers and images.

    During its lifetime Docker guest can create many images, and to keep their names
    readable, each guest has its own "namespace". Docker image can be identified using
    different identificators:

    * SHA256 ID - it is unique, each image has one and only one ID. It's long and somewhat
      readable.
    * short ID - shortened variant of ID. Much better.
    * repository + tag - it looks like a "name", e.g. ``rhscl/devtoolset-4-toolchain-rhel7:latest``.
      ``latest`` is the tag, the rest is called repository. One image can have multiple "names"
      pointing to the same ID with different repository/tag labels.

    To identify images that belong to the guest we create a "namespace":

        ``<guest name>-<random string>/<base image ID>``

    This namespace then represents **repository** part of guest's image names, and each image
    in this repository gets a tag, representing a "generation" of the base image - with each change,
    generation is raised by one, and together with namespace creates a trail of unique, followable
    image names. This way we can referr to images using their IDs while we still can print somewhat
    readable names to follow in logs.

    Base image has usually completely different name but we add it into our namespace as a
    "generation zero" image.

    :param gluetool.Module module: module that created this guest.
    :param str name: name of the guest.
    :param docker: connection to the Docker server.
    :param Image image: image to instantiate.
    """

    def __init__(self, module, name, docker, image, volumes=None):
        # type: (DockerProvisioner, str, Any, Image, Optional[Dict[str, Dict[str, str]]]) -> None
        super(DockerGuest, self).__init__(module, name)

        self._docker = docker
        self._name = name

        # volumes to mount when running the container
        self._volumes = volumes or {}

        # each guest has its own namespace where it keeps its private images
        self._namespace = '{}-{}/{}'.format(self.name, rand_id(), image.full_id)
        self._generation = 0

        self.debug("using namespace '{}'".format(self._namespace))

        # tag base image into our namespace
        image_name, namespace, tag = self._current_image

        self._docker.images.get(image.full_id).tag(repository=namespace, tag=tag)

        # and use it as the initial image
        self._image = Image.image_by_name(self._docker, image_name)
        self._container = None

        self.debug("base image '{}' tagged as guest image {}".format(image.name, self._image))

        # initialize lists of things we created for this guest, so we could clean up after it
        self._created_images = [self._image]
        self._created_containers = []  # type: List[Any]

        self.debug("current image is {}".format(self._image))

    def __repr__(self):
        # type: () -> str
        return '{}'.format(self._namespace)

    @property
    def supports_snapshot(self):
        # type: () -> bool
        return True

    @property
    def _current_image(self):
        # type: () -> Tuple[str, str, str]
        """
        Return parts of current image.

        It's easily possible there is *no* current image but that's not important - it
        may be created and named using the parts this method returns.

        :returns: (full name, namespace, tag)
        """

        tag = 'gen{}'.format(self._generation)

        return ('{}:{}'.format(self._namespace, tag), self._namespace, tag)

    def _instantiate_container(self, creator, *args, **kwargs):
        # type: (Any, Any, Any) -> Any
        """
        Create the container from the current image.

        :param creator: one of :py:func:`docker.containers.create` or :py:func:`docker.containers.run`.
        :param args: arguments for ``creator``.
        :param kwargs: keyword arguments for ``creator``.
        :returns: :py:mod:`docker`'s ``Container`` instance.
        """

        assert self._image is not None

        self.debug("creating a container from '{}'".format(self._image.name))

        if self._volumes and 'volumes' not in kwargs:
            kwargs['volumes'] = self._volumes

        container = creator(self._image.full_id, *args, **kwargs)

        self.debug("container is '{}'".format(container.id))

        self._container = container
        self._created_containers.append(container)

        return container

    def _create_container(self):
        # type: () -> Any
        """
        ``docker create`` analogue - create a container, but don't start it.

        :returns: :py:mod:`docker`'s ``Container`` instance.
        """

        return self._instantiate_container(self._docker.containers.create)

    def _run_container(self, cmd):
        # type: (str) -> Tuple[Any, Optional[Exception]]
        """
        ``docker run`` analogue - create container and run a command in it.

        :param str: command to run.
        :returns: :py:mod:`docker`'s ``Container`` instance.
        """

        container = self._instantiate_container(self._docker.containers.create, command=cmd)

        error = None  # type: Optional[Exception]

        try:
            container.start()

        except Exception as exc:
            error = exc

        return container, error

    def _commit_container(self):
        # type: () -> None
        assert self._container is not None

        container, self._container = self._container, None

        self.debug("committing the container '{}'".format(container.id))

        container.reload()
        assert container.status in ('created', 'exited'), \
            'Unexpected container status found {}'.format(container.status)

        self._generation += 1
        self.debug('generation raised to {}'.format(self._generation))

        image_name, namespace, tag = self._current_image
        container.commit(repository=namespace, tag=tag)

        self.debug("commited as image '{}'".format(image_name))

        self._image = Image.image_by_name(self._docker, image_name)
        self._created_images.append(self._image)

        self.debug("current image is {}".format(self._image))

    def _execute_shell(self, cmd, **kwargs):
        # type: (List[str], Any) -> gluetool.utils.ProcessOutput
        return cast(gluetool.utils.ProcessOutput, gluetool.utils.run_command(cmd, logger=self.logger, **kwargs))

    def execute(self, cmd, **kwargs):
        # type: (str, Any) -> gluetool.utils.ProcessOutput
        self.debug("execute: '%s'" % (cmd))

        if self._container is not None:
            # there is container, left by some previous execute call. commit its image
            # and use it for our command

            self._commit_container()

        container, error = self._run_container(cmd)

        if error is None:
            # wait for it to finish the execution
            def _check_exited():
                # type: () -> Result[bool, str]
                container.reload()
                return Result.Ok(True) if container.status == 'exited' else Result.Error('still running')

            self.wait('container exits', _check_exited, tick=2)

        # refresh container's data - we don't expect them to change anymore, container
        # is finished
        container.reload()

        # construct process output package, just like run_command does
        stdout = container.logs(stdout=True, stderr=False, stream=False)
        stderr = container.logs(stdout=False, stderr=True, stream=False)

        gluetool.log.log_dict(self.debug, 'container attributes', container.attrs)

        output = gluetool.utils.ProcessOutput([cmd], container.attrs['State']['ExitCode'], stdout, stderr, {})

        output.log(self.logger)

        if output.exit_code != 0:
            raise GlueCommandError([cmd], output)

        return output

    def copy_to(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, Any) -> gluetool.utils.ProcessOutput
        if recursive is False:
            self.warn("Cannot disable recursive behavior of 'cp' command")

        if self._container is None:
            self._create_container()

        assert self._container is not None

        return self._execute_shell(['docker', 'cp', src, '{}:{}'.format(self._container.id, dst)])

    def copy_from(self, src, dst, recursive=False, **kwargs):
        # type: (str, str, bool, Any) -> gluetool.utils.ProcessOutput
        if recursive is False:
            self.warn("Cannot disable recursive behavior of 'cp' command")

        if self._container is None:
            self._create_container()

        assert self._container is not None

        return self._execute_shell(['docker', 'cp', '{}:{}'.format(self._container.id, src), dst])

    def add_volume(self, host_path, guest_path, mode='ro'):
        # type: (str, str, str) -> None
        """
        Add a volume that should be mounted when running a command.

        :param str host_path: path on the host system.
        :param str guest_path: path on the guest - a mount point.
        :param str mode: either ``ro`` for read-only access, or ``rw`` for read-write.
        """

        assert mode in ('rw', 'ro')

        self._volumes[host_path] = {
            'bind': guest_path,
            'mode': mode
        }

    def remove_volume(self, host_path):
        # type: (str) -> None
        """
        Remove previously configured volume.

        :param str host_path: path on the host system, used in the previous call
            to :py:ref:`DockerGuest.add_volume`.
        """

        if host_path not in self._volumes:
            return

        del self._volumes[host_path]

    def create_snapshot(self, start_again=True):
        # type: (bool) -> Image
        self.debug('creating a snapshot')

        if self._container is not None:
            self._commit_container()

        self.debug('snapshot is {}'.format(self._image))
        return self._image

    def restore_snapshot(self, snapshot):
        # type: (Image) -> DockerGuest
        self.debug("restoring snapshot {}".format(snapshot))

        return cast(DockerProvisioner, self._module).guest_factory(
            self._module,
            '{}-{}'.format(self._name, rand_id()),
            self._docker, snapshot
        )

    def destroy(self):
        # type: () -> None
        # reversing the lists does not seem to be necessary - newer images do not
        # depend on older ones, only containers must be removed before removing
        # the images they were created from.

        for container in self._created_containers:
            self.debug("removing container '{}'".format(container.id))
            container.remove()

        # We *must* refer to images using their names. Using the image SHA ID would work
        # for images we created by commiting containers. We didn't create the base image
        # we received from guest's creator, therefore we shouldn't remove it. Unfortunately,
        # the very first image we tagged into our namespace shares the ID with the base image
        # - we didn't create our initial image from the base one, we simply gave it another
        # name. Therefore we must remove the *name* and docker will simply remove the name
        # and leave the image itself untouched. For all images we created from containers
        # removing name will lead to removing the image as well - these images have no other
        # names that would keep them "alive".

        for image in self._created_images:
            self.debug("removing image {}".format(image))
            self._docker.images.remove(image=image.name)

    def setup(self, variables=None, **kwargs):
        # type: (Optional[Dict[str, Any]], Any) -> None
        variables = variables or {}

        if 'IMAGE_NAME' not in variables:
            variables['IMAGE_NAME'] = self._current_image

        super(DockerGuest, self).setup(variables=variables, **kwargs)


class DockerProvisioner(gluetool.Module):
    """
    Provision guests backed by docker containers.
    """

    name = 'docker-provisioner'
    description = 'Provision guests backed by docker containers.'

    options = [
        ('Environment options', {
            'environment-map': {
                'help': 'Mapping translating testing environments to Docker images.',
                'action': 'store'
            }
        }),
        ('Direct provisioning', {
            'provision': {
                'help': """
                        Provision given number of guests. Use ``--environment`` or ``--image``
                        to specify what should the guests provide.
                        """,
                'metavar': 'COUNT',
                'type': int
            },
            'environment': {
                'help': 'Environment to provision, e.g. ``arch=x86_64,compose=rhel-7.6``.',
                'metavar': 'key1=value1,key2=value2,...'
            },
            'image': {
                'help': 'Image to provision.'
            },
            'setup-provisioned': {
                'help': "Setup guests after provisioning them. See 'guest-setup' module",
                'action': 'store_true'
            },
            'execute': {
                'help': 'Execute command in provisioned containers.'
            }
        })
    ]

    required_options = ('environment-map',)

    shared_functions = ['provision']

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        super(DockerProvisioner, self).__init__(*args, **kwargs)

        self._guests = []  # type: List[DockerGuest]

    @gluetool.utils.cached_property
    def environment_map(self):
        # type: () -> Any
        return gluetool.utils.load_yaml(self.option('environment-map'), logger=self.logger)

    def guest_factory(self, *args, **kwargs):
        # type: (Any, Any) -> DockerGuest
        """
        Create a docker guest, and add it to the list of guests. All arguments are passed
        directly to :py:class:`DockerGuest`.

        :rtype: DockerGuest
        :returns: new guest instance.
        """

        guest = DockerGuest(*args, **kwargs)
        self._guests.append(guest)

        return guest

    def _determine_image_name(self, image_name):
        # type: (str) -> Image
        """
        Find a Docker image reference based on its supposed name.

        :param str name: image name as presented to the user - often consits of "repository" and "tag" elements.
        :rtype: Image
        """

        self.info('finding image for name {}'.format(image_name))

        self.require_shared('docker')

        image = Image.image_by_name(self.shared('docker'), image_name)

        self.info('image is {}'.format(image))

        return image

    def _determine_image_environment(self, environment):
        # type: (TestingEnvironment) -> Image
        """
        Find a Docker image reference based on its Docker ID.

        :param str image: image ID as understood by Docker.
        :rtype: Image
        """

        self.info('finding image for environment {}'.format(environment))

        self.require_shared('docker', 'evaluate_filter')

        context = gluetool.utils.dict_update(self.shared('eval_context'), {
            'ENVIRONMENT': environment
        })

        image_entries = self.shared('evaluate_filter', self.environment_map, context=context, stop_at_first_hit=True)

        if not image_entries:
            raise GlueError('No image configured for environment {}'.format(environment))

        image = Image.image_by_name(self.shared('docker'), image_entries[0]['image'])

        self.info('image is {}'.format(image))

        return image

    def _determine_image(self, environment, image_name):
        # type: (TestingEnvironment, Optional[str]) -> Image
        if image_name:
            return self._determine_image_name(image_name)

        return self._determine_image_environment(environment)

    def provision(self, environment, count=1, image_name=None, name=DEFAULT_NAME, **kwargs):
        # type: (TestingEnvironment, int, Optional[str], str, Any) -> List[DockerGuest]
        """
        Provision guest for the given environment.

        :param tuple environment: description of the envronment caller wants to provision.
            Follows :doc:`Testing Environment Protocol </protocols/testing-environment>`.
        :param int count: provision this many guests.
        :param str image_name: instead of environment, force use of image of this name.
        :param str name: name prefix used for naming guests.
        """

        self.require_shared('docker')

        if count < 1:
            raise GlueError('You must provision at least one guest')

        image = self._determine_image(environment, image_name)

        docker = self.shared('docker')

        return [
            self.guest_factory(self, name, docker, image) for _ in range(0, count)
        ]

    def sanity(self):
        # type: () -> None
        if self.option('provision') and not self.option('image') and not self.option('environment'):
            raise GlueError('You must specify either ``--image`` or ``--environment`` when using direct provisioning')

        if self.option('environment'):
            self._config['environment'] = TestingEnvironment.unserialize_from_string(self.option('environment'))

    def execute(self):
        # type: () -> None
        random.seed(int(time.time()))

        if self.option('provision'):
            # ``provision``` will chose one of ``environment``` or ``image_name``, at least
            # one of them is not ``None``.
            guests = self.provision(self.option('environment'),
                                    count=self.option('provision'),
                                    image_name=self.option('image'))

            if self.option('setup-provisioned'):
                for guest in guests:
                    guest.setup()

            if self.option('execute'):
                for guest in guests:
                    try:
                        output = guest.execute(self.option('execute'))

                    except GlueCommandError as exc:
                        output = exc.output

                    output.log(self.logger)

    def destroy(self, failure=None):
        # type: (Any) -> None
        for guest in self._guests:
            guest.destroy()
