# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from .v0_0_72 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: ``beaker`` HW requirement
    """

    _VERSION = (0, 0, 73)
    _PREVIOUS = PreviousAPIMilestone
