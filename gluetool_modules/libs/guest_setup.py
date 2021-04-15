# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Common API for modules providing ``setup_guest``  shared functions.

The ``setup_guest`` should perform actions to prepare the given guest for more work. The whole process is often
implemented by multiple modules in a chain. To ease cooperation, this module provides simple definition of
structure all ``setup_guest`` functions should return, and states few basic rules.

* every ``setup_guest`` function returns a list of :py:class:`GuestSetupOutput`.
* if ``setup_guest`` function called its predecessors, its output structures should be added to the list it obtained
  from the predecessors.
* every ``setup_guest`` function focuses on a single guest at a time. If user needs a parallel execution,
  we can provide :py:mod:`gluetool_modules.libs.jobs` for that purpose.
* every ``setup_guest`` should accept ``log_dirpath`` parameter - all files produced by the setup process should
  land in this directory. Module is free to create subdirectories for subtasks.
"""

import os

from gluetool_modules.libs import GlueEnum
import gluetool.log
from gluetool.result import Result

# Type annotations
from typing import TYPE_CHECKING, Any, Dict, List, NamedTuple, Optional, NamedTuple, Tuple  # noqa
from typing_extensions import Protocol

if TYPE_CHECKING:
    import gluetool_modules.libs.guest  # noqa


class GuestSetupStage(GlueEnum):
    """
    Different stages supported by guest setup workflow.
    """

    #: This is the first stage, and as such serves as the default, initial stage.
    #:
    #: Everything that should happen before pipeline can install the artifact, except...
    PRE_ARTIFACT_INSTALLATION = 'pre-artifact-installation'

    #: ... except artifact- and workflow-specific tasks requested by users or dictated by infrastructure
    #: issues we need to overcome.
    #:
    #: There is an obvious overlap with ``PRE_ARTIFACT_INSTALLATION``, the difference is that the previous
    #: stage should cover the generic steps while this one is supposed to cover only the very component
    #: and workflow exceptions and workarounds. Easy, right? Things like "ignore AVC denials for component X"
    #: or "add repository Y when testing component Z".
    #:
    #: ``PRE_ARTIFACT_INSTALLATION`` should remain clean of these exceptions as much as possible for us to be
    #: able to use just that stage to set up the guest for any generic testing/work.
    PRE_ARTIFACT_INSTALLATION_WORKAROUNDS = 'pre-artifact-installation-workarounds'

    #: Everything that should happen to install the artifact.
    ARTIFACT_INSTALLATION = 'artifact-installation'

    #: Optional rollback of workarounds/exceptions performed in ``PRE_ARTIFACT_INSTALLATION_WORKAROUNDS``.
    #: The very same set of rules applies when it comes to the difference between this stage and the next one.
    POST_ARTIFACT_INSTALLATION_WORKAROUNDS = 'post-artifact-installation-workarounds'

    #: Everything that should happen after the pipeline installed the artifact.
    POST_ARTIFACT_INSTALLATION = 'post-artifact-installation'


STAGES_ORDERED = [
    GuestSetupStage.PRE_ARTIFACT_INSTALLATION,
    GuestSetupStage.PRE_ARTIFACT_INSTALLATION_WORKAROUNDS,
    GuestSetupStage.ARTIFACT_INSTALLATION,
    GuestSetupStage.POST_ARTIFACT_INSTALLATION_WORKAROUNDS,
    GuestSetupStage.POST_ARTIFACT_INSTALLATION
]


class GuestSetupStageAdapter(gluetool.log.ContextAdapter):
    def __init__(self, logger, stage):
        # type: (gluetool.log.ContextAdapter, GuestSetupStage) -> None

        super(GuestSetupStageAdapter, self).__init__(logger, {
            'ctx_guest_setup_stage': (300, stage.value)
        })


#: Represents one action taken by "guest setup" module and pointer to its logs.
#:
#: :ivar str label: human-readable name for what this particular guest setup bit represents.
#: :ivar str log_path: local path to a directory or file where log lives.
#: :ivar additional_data: anything else module considers interesting for its users.
GuestSetupOutput = NamedTuple('GuestSetupOutput', (
    ('stage', GuestSetupStage),
    ('label', str),
    ('log_path', str),
    ('additional_data', Any)
))


SetupGuestReturnType = Result[List[GuestSetupOutput], Tuple[List[GuestSetupOutput], Exception]]


class SetupGuestType(Protocol):
    def __call__(
        self,
        guest,  # type: gluetool_modules.libs.guest.NetworkedGuest
        stage=GuestSetupStage.PRE_ARTIFACT_INSTALLATION,  # type: GuestSetupStage
        variables=None,  # type: Optional[Dict[str, str]]
        log_dirpath=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> SetupGuestReturnType

        pass


def guest_setup_log_dirpath(guest, log_dirpath):
    # type: (gluetool_modules.libs.guest.NetworkedGuest, Optional[str]) -> str

    if not log_dirpath:
        log_dirpath = 'guest-setup-{}'.format(guest.name)

    if not os.path.exists(log_dirpath):
        os.mkdir(log_dirpath)

    return log_dirpath
