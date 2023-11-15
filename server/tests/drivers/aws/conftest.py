# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import pytest

import tft.artemis.drivers.aws


@pytest.fixture(name='aws_pool', scope='function')
def fixture_aws_pool(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.aws.AWSDriver:
    return tft.artemis.drivers.aws.AWSDriver(
        logger,
        'aws',
        {
            'access-key-id': 'dummy-access-key-id',
            'secret-access-key': 'dummy-secret-access-key',
            'default-region': 'dummy-default-region'
        }
    )
