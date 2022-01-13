# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0


import tft.artemis.drivers.aws


def test_bdm_find_free_device_name_empty() -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings()

    r_name = mappings.find_free_device_name()

    assert r_name.is_ok
    assert r_name.unwrap() == tft.artemis.drivers.aws.EBS_DEVICE_NAMES[0]


def test_bdm_find_free_device_name_real_root() -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings([
        # Root device, for those /dev/sda1 is reserved
        {
            'DeviceName': '/dev/sda1',
            'Ebs': {}
        }
    ])

    r_name = mappings.find_free_device_name()

    assert r_name.is_ok
    assert r_name.unwrap() == tft.artemis.drivers.aws.EBS_DEVICE_NAMES[0]


def test_bdm_find_free_device_name() -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings([
        # Root device, for those /dev/sda1 is reserved
        {
            'DeviceName': '/dev/sda1',
            'Ebs': {}
        },
        {
            'DeviceName': '/dev/sdb',
            'Ebs': {}
        },
        {
            'DeviceName': '/dev/sdf',
            'Ebs': {}
        },
        {
            'DeviceName': '/dev/sdg',
            'Ebs': {}
        },
        {
            'DeviceName': '/dev/sdp',
            'Ebs': {}
        }
    ])

    r_name = mappings.find_free_device_name()

    assert r_name.is_ok
    assert r_name.unwrap() == '/dev/sdh'
