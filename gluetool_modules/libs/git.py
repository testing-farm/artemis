# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# Note: avoid relative import of this git module instead of GitPython's git module
# https://www.python.org/dev/peps/pep-0328/
from __future__ import absolute_import

import os
import os.path
import stat
import tempfile

import git

import gluetool.log
import gluetool.utils

# Type annotations
from typing import cast, Any, Optional, List  # cast, Callable, Dict, List, NamedTuple, Optional, Tuple  # noqa


class RemoteGitRepository(gluetool.log.LoggerMixin):
    """
    A remote Git repository representation.

    :param gluetool.log.ContextLogger logger: Logger used for logging.
    :param str clone_url: remote URL to use for cloning the repository.
    :param str branch: if set, it is the default branch to use in actions on the repository.
    :param path str: Initialize :py:class:`git.Git` instance from given path.
    :param str ref: if set, it it is the default point in repo history to manipulate.
    :param str web_url: if set, it is the URL of web frontend of the repository.
    """

    def __init__(
        self,
        logger,  # type: gluetool.log.ContextAdapter
        clone_url=None,  # type: Optional[str]
        branch=None,  # type: Optional[str]
        path=None,  # type: Optional[str]
        ref=None,  # type: Optional[str]
        web_url=None,  # type: Optional[str]
        clone_args=None  # type: Optional[List[str]]
    ):
        # type: (...) -> None

        super(RemoteGitRepository, self).__init__(logger)

        self.clone_url = clone_url
        self.branch = branch
        self.ref = ref
        self.web_url = web_url
        self.path = path
        self.clone_args = clone_args or []

        # holds git.Git instance, GitPython has no typing support
        self._instance = None  # type: Any

        # initialize from given path if given
        if self.path:
            self.initialize_from_path(self.path)

    @property
    def is_cloned(self):
        # type: () -> bool
        """
        Repository is considered cloned if there is a git repository available on the local host
        and instance of :py:class:`git.Git` was initialized from it.
        """
        return bool(self._instance)

    def clone(
        self,
        logger=None,  # type: Optional[gluetool.log.ContextAdapter]
        clone_url=None,  # type: Optional[str]
        branch=None,  # type: Optional[str]
        ref=None,  # type: Optional[str]
        path=None,  # type: Optional[str]
        prefix=None,  # type: Optional[str]
        clone_args=None  # type: Optional[List[str]]
    ):
        # type: (...) -> str
        """
        Clone remote repository and initialize :py:class:`git.Git` from it.

        :param gluetool.log.ContextAdapter logger: logger to use, default to instance logger.
        :param str clone_url: remote URL to use for cloning the repository. If not set, the one specified during
            ``RemoteGitRepository`` initialization is used.
        :param str ref: checkout specified git ref. If not set, the one specified during ``RemoteGitRepository``
            initialization is used. If none of these was specified, top of the branch is checked out.
        :param str branch: checkout specified branch. If not set, the one specified during ``RemoteGitRepository``
            initialization is used. If none of these was specified, ``master`` is used by default.
        :param str path: if specified, clone into this path. Otherwise, a temporary directory is created.
        :param str prefix: if specified and `path` wasn't set, it is used as a prefix of directory created
            to hold the clone.
        :returns: path to the cloned repository. If `path` was given explicitly, it is returned as-is. Otherwise,
            function created a temporary directory and its path relative to CWD is returned.
        """

        # repository already initialized - nothing to clone
        if self._instance:
            if path and self.path != path:
                raise gluetool.GlueError('Clone path does not match initialized repository, misunderstood arguments?')

            assert self.path
            return self.path

        logger = logger or self.logger

        branch = branch or self.branch or 'master'
        clone_url = clone_url or self.clone_url
        ref = ref or self.ref

        if not clone_url:
            raise gluetool.GlueError('No clone url specified, cannot continue')

        path = path or self.path
        original_path = path  # save the original path for later

        if path:
            actual_path = path

        elif prefix:
            actual_path = tempfile.mkdtemp(dir=os.getcwd(), prefix=prefix)

        else:
            actual_path = tempfile.mkdtemp(dir=os.getcwd())
        self.path = actual_path

        logger.info('cloning repo {} (branch {}, ref {})'.format(
            clone_url,
            branch,
            ref if ref else 'not specified'
        ))
        cmd = gluetool.utils.Command(['git', 'clone'], logger=logger)

        cmd.options += clone_args or self.clone_args

        if not ref:
            cmd.options += [
                '--depth', '1',
                '-b', branch
            ]

        cmd.options += [
            clone_url,
            actual_path
        ]

        try:
            cmd.run()

        except gluetool.GlueCommandError as exc:
            raise gluetool.GlueError('Failed to clone git repository: {}'.format(exc.output.stderr))

        # Make sure it's possible to enter this directory for other parties. We're not that concerned with privacy,
        # we'd rather let common users inside the repository when inspecting the pipeline artifacts. Therefore
        # setting clone directory permissions to ug=rwx,o=rx.

        os.chmod(
            actual_path,
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH  # noqa: E501  # line too long
        )

        if ref:
            try:
                gluetool.utils.Command([
                    'git',
                    '-C', actual_path,
                    'checkout', ref
                ]).run()

            except gluetool.GlueCommandError as exc:
                raise gluetool.GlueError('Failed to checkout ref {}: {}'.format(ref, exc.output.stderr))

        # Since we used `dir` when creating repo directory, the path we have is absolute. That is not perfect,
        # we have an agreement with the rest of the world that we're living in current directory, which we consider
        # a workdir (yes, it would be better to have an option to specify it explicitly), we should get the relative
        # path instead.
        # This applies to path *we* generated only - if we were given a path, we won't touch it.
        path = actual_path if original_path else os.path.relpath(actual_path, os.getcwd())

        self.initialize_from_path(path)

        return path

    def initialize_from_path(self, path):
        # type: (str) -> Any
        """
        Initialize a :py:class:`git.Git` instance from given path.

        :param str path: path to git repository which should be used for initialization
        :raises gluetool.glue.GlueError: if failed to initialize instance from the given path
        """
        try:
            self._instance = git.Git(path)
        except git.exc.GitError as error:
            raise gluetool.GlueError("Failed to initialize git repository from path '{}': {}".format(path, error))

    def gitlog(self, *args):
        # type: (*str) -> Any
        """
        Return git log according to given parameters. Note that we cannot call this method `log` as it would
        collide with method `log` of our parent :py:class:`gluetool.log.LoggerMixin`
        """
        gluetool.utils.log_dict(self.debug, 'git log args', args)

        log = self._instance.log(*args)

        gluetool.utils.log_blob(self.debug, 'logs found', log)

        return log
