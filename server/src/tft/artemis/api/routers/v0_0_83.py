# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from .v0_0_74 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: ``beaker.panic-watchdog`` HW requirement
    * Added: ``iommu`` HW requirements
    * Added: ``system.model-name`` HW requirement
    * Added: ``device`` HW requirements
    """

    _VERSION = (0, 0, 83)
    _PREVIOUS = PreviousAPIMilestone
