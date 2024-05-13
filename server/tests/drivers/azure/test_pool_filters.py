# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
from typing import Any, List, Optional
from unittest import mock

import gluetool.log
from gluetool.result import Error, Ok, Result

from tft.artemis import Failure
from tft.artemis.drivers.azure import AzureDriver

AZURE_IMAGE_LIST = [
    {
        "architecture": "x64",
        "offer": "rh-ansible-self-managed",
        "publisher": "RedHat",
        "sku": "rh-aap2",
        "urn": "RedHat:rh-ansible-self-managed:rh-aap2:9.0.20231213",
        "version": "9.0.20231213"
    },
    {
        "architecture": "x64",
        "offer": "rh-rhel",
        "publisher": "redhat-limited",
        "sku": "rh-rhel7",
        "urn": "redhat-limited:rh-rhel:rh-rhel7:7.9.2023042712",
        "version": "7.9.2023042712"
    },
    {
        "architecture": "x64",
        "offer": "rh-rhel",
        "publisher": "RedHat",
        "sku": "rh-rhel7-gen1",
        "urn": "RedHat:rh-rhel:rh-rhel7-gen1:7.9.2023090617",
        "version": "7.9.2023090617"
    },
    {
        "architecture": "x64",
        "offer": "RHEL",
        "publisher": "RedHat",
        "sku": "7_9",
        "urn": "RedHat:RHEL:7_9:7.9.2021051701",
        "version": "7.9.2021051701"
    },
    {
        "architecture": "x64",
        "offer": "RHEL",
        "publisher": "RedHat",
        "sku": "8",
        "urn": "RedHat:RHEL:8:8.0.2019101800",
        "version": "8.0.2019101800"
    },
]

AZURE_SIZE_LIST = [
    {
        "maxDataDiskCount": 16,
        "memoryInMB": 65536,
        "name": "Standard_L8as_v3",
        "numberOfCores": 8,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 81920
    },
    {
        "maxDataDiskCount": 32,
        "memoryInMB": 131072,
        "name": "Standard_L16as_v3",
        "numberOfCores": 16,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 163840
    },
    {
        "maxDataDiskCount": 32,
        "memoryInMB": 262144,
        "name": "Standard_L32as_v3",
        "numberOfCores": 32,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 327680
    },
    {
        "maxDataDiskCount": 32,
        "memoryInMB": 393216,
        "name": "Standard_L48as_v3",
        "numberOfCores": 48,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 491520
    },
    {
        "maxDataDiskCount": 4,
        "memoryInMB": 8192,
        "name": "Standard_B2ms",
        "numberOfCores": 2,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 16384
    },
    {
        "maxDataDiskCount": 32,
        "memoryInMB": 81920,
        "name": "Standard_B20ms",
        "numberOfCores": 20,
        "osDiskSizeInMB": 1047552,
        "resourceDiskSizeInMB": 163840
    },
]


class AzureSessionMock:
    def run_az(logger: gluetool.log.ContextAdapter,  # type: ignore[misc]
               options: List[str],
               commandname: Optional[str] = None) -> Result[List[dict[str, Any]], Failure]:
        if commandname == 'az.vm-image-list':
            return Ok(AZURE_IMAGE_LIST)
        elif commandname == 'az.vm-flavors-list':
            return Ok(AZURE_SIZE_LIST)

        return Error(Failure(f'Mock not set up for command {commandname}'))


@mock.patch('tft.artemis.drivers.azure.AzureSession')
def test_fetch_pool_info(mock_az_session: 'mock.MagicMock', azure_pool: AzureDriver) -> None:
    mock_az_session.return_value.__enter__.return_value = AzureSessionMock
    images = azure_pool.fetch_pool_image_info().unwrap()
    # Only one image matching pool filters can be found
    assert len(images) == 1
    image = images[0]
    assert image.name == 'RedHat:RHEL:7_9:7.9.2021051701'


@mock.patch('tft.artemis.drivers.azure.AzureSession')
def test_fetch_pool_info_no_filters(mock_az_session: 'mock.MagicMock',
                                    azure_pool_no_filters: AzureDriver) -> None:
    mock_az_session.return_value.__enter__.return_value = AzureSessionMock
    images = azure_pool_no_filters.fetch_pool_image_info().unwrap()
    assert len(images) == len(AZURE_IMAGE_LIST)


@mock.patch('tft.artemis.drivers.azure.AzureSession')
def test_fetch_pool_flavor_info(mock_az_session: 'mock.MagicMock', azure_pool: AzureDriver) -> None:
    mock_az_session.return_value.__enter__.return_value = AzureSessionMock
    flavors = azure_pool.fetch_pool_flavor_info().unwrap()
    # Only 2 flavors matching pool flavor regex
    assert len(flavors) == 2


@mock.patch('tft.artemis.drivers.azure.AzureSession')
def test_fetch_pool_flavor_info_no_filters(mock_az_session: 'mock.MagicMock',
                                           azure_pool_no_filters: AzureDriver) -> None:
    mock_az_session.return_value.__enter__.return_value = AzureSessionMock
    flavors = azure_pool_no_filters.fetch_pool_flavor_info().unwrap()
    assert len(flavors) == len(AZURE_SIZE_LIST)
