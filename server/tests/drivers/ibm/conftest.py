# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import pytest

import tft_artemis.drivers.ibmcloud.vpc


@pytest.fixture(name='ibmvpc_pool', scope='function')
def fixture_ibmvpc_pool(logger: gluetool.log.ContextAdapter) -> tft_artemis.drivers.ibmcloud.vpc.IBMCloudVPCDriver:
    return tft_artemis.drivers.ibmcloud.vpc.IBMCloudVPCDriver(logger, 'ibmcloud-vpc', {})
