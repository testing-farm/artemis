# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import _pytest.monkeypatch

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


def test_bdm_find_free_device_name_exhausted(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings()
    monkeypatch.setattr(tft.artemis.drivers.aws, 'EBS_DEVICE_NAMES', [])

    r = mappings.find_free_device_name()

    assert r.is_error
    assert r.unwrap_error().message == 'cannot find any free EBS device name'


def test_bdm_enlarge() -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings()

    assert len(mappings) == 0

    assert mappings.enlarge(5).is_ok

    assert len(mappings) == 5

    assert mappings.enlarge(4).is_ok

    assert len(mappings) == 5


def test_bdm_enlarge_exhausted_names(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    mappings = tft.artemis.drivers.aws.BlockDeviceMappings()
    monkeypatch.setattr(tft.artemis.drivers.aws, 'EBS_DEVICE_NAMES', [])

    r = mappings.enlarge(5)

    assert r.is_error
    assert r.unwrap_error().message == 'cannot find any free EBS device name'

    assert len(mappings) == 0
