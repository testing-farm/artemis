# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from .v0_0_67 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: ``zcrypt`` HW requirement
    * Added: ``disk.model-name`` HW requirement
    """

    _VERSION = (0, 0, 69)
    _PREVIOUS = PreviousAPIMilestone
