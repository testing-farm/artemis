# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import gluetool.log
import pytest

import tft.artemis.drivers.azure


@pytest.fixture(name='azure_pool', scope='function')
def fixture_azure_pool(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.azure.AzureDriver:
    pool_config = {
        "login": "service-principal",
        "tenant": "TENANT_ID",
        "username": "USERNAME",
        "password": "PASSWORD",

        "default-location": "eastus",
        "default-flavor": "Standard_B2ms",
        "post-install-script": "./configuration/userdata_allow_root",

        "capabilities": {
            "supports-spot-instances": False,
            "supported-architectures": ["X86_64"]
        },

        "flavor-regex": "Standard_B2*",

        "image-filters": [
            {
                "publisher": "RedHat",
                "name-regex": "(.*RHEL:7_.*)|(.*RHEL:8_.*)|(.*RHEL:9_.*)"
            }
        ],
    }
    return tft.artemis.drivers.azure.AzureDriver(logger, 'beaker', pool_config)


@pytest.fixture(name='azure_pool_no_filters', scope='function')
def fixture_azure_pool_no_image_filters(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.azure.AzureDriver:
    pool_config = {
        "login": "service-principal",
        "tenant": "TENANT_ID",
        "username": "USERNAME",
        "password": "PASSWORD",

        "default-location": "eastus",
        "default-flavor": "Standard_B2ms",
        "post-install-script": "./configuration/userdata_allow_root",

        "capabilities": {
            "supports-spot-instances": False,
            "supported-architectures": ["X86_64"]
        },
    }
    return tft.artemis.drivers.azure.AzureDriver(logger, 'beaker', pool_config)
