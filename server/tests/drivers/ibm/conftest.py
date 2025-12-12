# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import pytest

import tft.artemis.drivers.ibmcloudvpc


@pytest.fixture(name='ibmvpc_pool', scope='function')
def fixture_ibmvpc_pool(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.ibmcloudvpc.IBMCloudVPCDriver:
    return tft.artemis.drivers.ibmcloudvpc.IBMCloudVPCDriver(logger, 'ibmcloud-vpc', {})
