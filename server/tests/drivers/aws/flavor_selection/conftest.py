# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

# import sqlalchemy.orm.session
from typing import List
from unittest.mock import MagicMock

# import gluetool.log
import pytest

from tft.artemis.drivers import PoolImageSSHInfo
from tft.artemis.drivers.aws import AWSFlavor, AWSPoolImageInfo
from tft.artemis.environment import UNITS, FlavorBoot


@pytest.fixture(name='guest_request', scope='function')
def fixture_guest_request(name: str = 'dummy-guest-request') -> MagicMock:
    return MagicMock(
        name=name
    )


@pytest.fixture(name='image', scope='function')
def fixture_image() -> AWSPoolImageInfo:
    return AWSPoolImageInfo(
        name='dummy-image',
        id='dummy-image',
        arch='x86_64',
        boot=FlavorBoot(),
        ssh=PoolImageSSHInfo(),
        platform_details='Linux/UNIX',
        block_device_mappings=[],
        ena_support=False,
        boot_mode=None
    )


@pytest.fixture(name='flavors', scope='function')
def fixture_flavors() -> List[AWSFlavor]:
    return [
        AWSFlavor(
            name='generic x86_64 flavor',
            id='x86_64.1',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='supported',
            boot=FlavorBoot(
                method=[
                    'bios'
                ]
            )
        ),
        AWSFlavor(
            name='generic x86_64 flavor',
            id='x86_64.2',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='unsupported',
            boot=FlavorBoot(
                method=[
                    'bios'
                ]
            )
        ),

        AWSFlavor(
            name='nitro-backed x86_64 flavor',
            id='x86_64.3',
            arch='x86_64',
            memory=UNITS('4 GiB'),
            ena_support='required',
            boot=FlavorBoot(
                method=[
                    'bios',
                    'uefi'
                ]
            )
        ),

        AWSFlavor(
            name='generic aarch64 flavor',
            id='aarch64.1',
            arch='aarch64',
            memory=UNITS('4 GiB'),
            ena_support='required',
            boot=FlavorBoot(
                method=[
                    'uefi'
                ]
            )
        )
    ]
