# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool

# Type annotations
from typing import TYPE_CHECKING, cast, Any, Optional, Tuple  # noqa

if TYPE_CHECKING:
    from gluetool.log import ContextAdapter  # noqa


class NoArtifactsError(gluetool.glue.SoftGlueError):
    """
    Raised when the artifact (e.g. Brew task or MBS build) contain no artifacts anymore.
    This can - and does - happen in case of scratch builds: only the record the build
    was performed stays in a build system database, and its artifacts (RPMs, logs, etc.)
    are removed to save the space.

    :param task_id: ID of the task without artifacts.
    """

    def __init__(self, task_id):
        # type: (Any) -> None

        super(NoArtifactsError, self).__init__('No artifacts found for task')

        self.task_id = task_id


def has_artifacts(*tasks):
    # type: (Any) -> None
    """
    Check whether tasks have artifacts, any artifacts at all - no constraints like architecture are imposed,
    we're not trying to check whether the artifacts are testable with environments we have at our disposal.

    :param tasks: list of tasks to check.
    :raises: :py:class:`NoArtifactsError` if any task has no artifacts.
    """

    for task in tasks:
        if not task.has_artifacts:
            raise NoArtifactsError(task.id)


def artifacts_location(module, local_path, logger=None):
    # type: (gluetool.Module, str, Optional[ContextAdapter]) -> str
    """
    If we have access to ``artifacts_location`` shared function, return its output. Otherwise, return
    the input string.

    The goal si to simplify the code when``artifacts_location`` shared function is not available.
    """

    if module.has_shared('artifacts_location'):
        return cast(
            str,
            module.shared('artifacts_location', local_path, logger=logger)
        )

    return local_path


# With python3 we can use `Subject` from `dnf` package
# see https://bugzilla.redhat.com/show_bug.cgi?id=1452801#c7

def splitFilename(filename):
    # type: (str) -> Tuple[str, ...]
    """
    Split N(E)VRA to its pieces

    :param nevra to split
    :returns: a name, version, release, epoch, arch

    Code taken from rpmUtils.miscutils.splitFilename,
    which is unavailable in Fedora 31.
    Original code modified to accept N(E)VRA instead (E)NVRA
    """
    if filename[-4:] == '.rpm':
        filename = filename[:-4]

    archIndex = filename.rfind('.')
    arch = filename[archIndex+1:]

    relIndex = filename[:archIndex].rfind('-')
    rel = filename[relIndex+1:archIndex]

    verIndex = filename[:relIndex].rfind('-')
    ver = filename[verIndex+1:relIndex]

    epochIndex = ver.find(':')
    if epochIndex == -1:
        epoch = ''
    else:
        epoch = ver[:epochIndex]
        ver = ver[epochIndex+1:]

    name = filename[:verIndex]

    return name, ver, rel, epoch, arch
