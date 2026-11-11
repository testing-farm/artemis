# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import pytest

import tft.artemis.drivers.openstack


@pytest.fixture(name='openstack_pool', scope='function')
def fixture_openstack_pool(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.openstack.OpenStackDriver:
    return tft.artemis.drivers.openstack.OpenStackDriver(
        logger,
        'dummy-openstack-pool',
        {
            'auth-url': 'https://openstack.example.com',
            'api-version': '3',
            'user-domain-name': 'dummy-user-domain',
            'project-name': 'dummy-project',
            'username': 'dummy-user',
            'password': 'dummy-password',
        },
    )
