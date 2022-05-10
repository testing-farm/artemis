# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Dict, Optional

import _pytest.monkeypatch
import pytest

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


AWS_TAGS_EXAMPLES: Dict[str, str] = {
    'tag1': 'value1',
    'tag2': 'value2',
    # TODO: wrong type, but that's on purpose: our code expects `str`, but we already encountered `None` there.
    # We must handle such an invalid value, but in the long term, we need to prevent `None` sneaking in.
    'tag3': None,  # type: ignore[dict-item]
    'tag4': '',
    'tag5': 'foo bar',
    'tag6': 'foo "bar"',
    'tag7': 'foo \'bar\''
}


def test_serialize_tags() -> None:
    assert tft.artemis.drivers.aws._serialize_tags(AWS_TAGS_EXAMPLES) == [
        'Key=tag1,Value=value1',
        'Key=tag2,Value=value2',
        'Key=tag3,Value=""',
        'Key=tag4,Value=""',
        'Key=tag5,Value=foo bar',
        'Key=tag6,Value=foo <quote>bar<quote>',
        'Key=tag7,Value=foo <singlequote>bar<singlequote>'
    ]


def test_tags_to_tags_specifications() -> None:
    assert tft.artemis.drivers.aws._tags_to_tag_specifications(AWS_TAGS_EXAMPLES, 'instance', 'volume') == [
        'ResourceType=instance,Tags=[{Key=tag1,Value=value1},{Key=tag2,Value=value2},{Key=tag3,Value=""},{Key=tag4,Value=""},{Key=tag5,Value=foo bar},{Key=tag6,Value=foo <quote>bar<quote>},{Key=tag7,Value=foo <singlequote>bar<singlequote>}]',  # noqa: E501,FS003
        'ResourceType=volume,Tags=[{Key=tag1,Value=value1},{Key=tag2,Value=value2},{Key=tag3,Value=""},{Key=tag4,Value=""},{Key=tag5,Value=foo bar},{Key=tag6,Value=foo <quote>bar<quote>},{Key=tag7,Value=foo <singlequote>bar<singlequote>}]',  # noqa: E501,FS003
    ]


@pytest.mark.parametrize(('api_arch', 'artemis_arch'), [
    ('x86_64', 'x86_64'),
    ('arm64', 'aarch64'),
    ('i386', 'i386'),
    ('x86_64_mac', 'x86_64_mac')
])
def test_aws_arch_to_arch(api_arch: str, artemis_arch: Optional[str]) -> None:
    assert tft.artemis.drivers.aws._aws_arch_to_arch(api_arch) == artemis_arch
