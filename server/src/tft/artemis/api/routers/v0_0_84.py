# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# flake8: noqa: FS003 f-string missing prefix

from .v0_0_83 import APIMilestone as PreviousAPIMilestone


class APIMilestone(PreviousAPIMilestone):
    """
    * Added: ``cpu.vendor`` and ``cpu.vendor-name`` HW requirements
    """

    _VERSION = (0, 0, 84)
    _PREVIOUS = PreviousAPIMilestone
