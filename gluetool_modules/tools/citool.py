# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
citool - A convenience wrapper around gluetool.

This tool is part of our history, deserves to stay for us as a wrapper forever!
"""

import os
import sys

import gluetool.utils

CONFIG_PATHS = ', '.join([
    "/etc/gluetool.d/gluetool", "~/.gluetool.d/gluetool", "./.gluetool.d/gluetool",
    "/etc/citool.d/citool", "~/.citool.d/citool", "./.citool.d/citool"
])

MODULE_CONFIG_PATHS = ', '.join([
    "/etc/gluetool.d/config", "~/.gluetool.d/config", "./.gluetool.d/config",
    "/etc/citool.d/config", "~/.citool.d/config", "./.citool.d/config"
])


def run():
    # type: () -> None

    env = gluetool.utils.dict_update(os.environ.copy(), {
        'GLUETOOL_CONFIG_PATHS': CONFIG_PATHS,
        'GLUETOOL_MODULE_CONFIG_PATHS': MODULE_CONFIG_PATHS,
    })

    os.execvpe('gluetool', sys.argv, env)
