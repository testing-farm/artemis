# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
from typing import Optional

import gluetool.log
import pytest

import tft.artemis.db
import tft.artemis.drivers.aws

AWS_TAGS_EXAMPLES: dict[str, str] = {
    'tag1': 'value1',
    'tag2': 'value2',
    # TODO: wrong type, but that's on purpose: our code expects `str`, but we already encountered `None` there.
    # We must handle such an invalid value, but in the long term, we need to prevent `None` sneaking in.
    'tag3': None,  # type: ignore[dict-item]
    'tag4': '',
    'tag5': 'foo bar',
    'tag6': 'foo "bar"',
    'tag7': "foo 'bar'",
}


def test_serialize_tags() -> None:
    assert tft.artemis.drivers.aws._serialize_tags(AWS_TAGS_EXAMPLES) == [
        'Key=tag1,Value=value1',
        'Key=tag2,Value=value2',
        'Key=tag3,Value=""',
        'Key=tag4,Value=""',
        'Key=tag5,Value=foo bar',
        'Key=tag6,Value=foo <quote>bar<quote>',
        'Key=tag7,Value=foo <singlequote>bar<singlequote>',
    ]


def test_tags_to_tags_specifications() -> None:
    assert tft.artemis.drivers.aws._tags_to_tag_specifications(AWS_TAGS_EXAMPLES, 'instance', 'volume') == [
        'ResourceType=instance,Tags=[{Key=tag1,Value=value1},{Key=tag2,Value=value2},{Key=tag3,Value=""},{Key=tag4,Value=""},{Key=tag5,Value=foo bar},{Key=tag6,Value=foo <quote>bar<quote>},{Key=tag7,Value=foo <singlequote>bar<singlequote>}]',  # noqa: E501,FS003
        'ResourceType=volume,Tags=[{Key=tag1,Value=value1},{Key=tag2,Value=value2},{Key=tag3,Value=""},{Key=tag4,Value=""},{Key=tag5,Value=foo bar},{Key=tag6,Value=foo <quote>bar<quote>},{Key=tag7,Value=foo <singlequote>bar<singlequote>}]',  # noqa: E501,FS003
    ]


@pytest.mark.parametrize(
    ('api_arch', 'artemis_arch'),
    [('x86_64', 'x86_64'), ('arm64', 'aarch64'), ('i386', 'i386'), ('x86_64_mac', 'x86_64_mac')],
)
def test_aws_arch_to_arch(api_arch: str, artemis_arch: Optional[str]) -> None:
    assert tft.artemis.drivers.aws._aws_arch_to_arch(api_arch) == artemis_arch


@pytest.mark.parametrize(
    ('user_data', 'pool_config_use_spot', 'expected'),
    [
        ({'ArtemisUseSpot': 'true'}, False, True),
        ({'ArtemisUseSpot': 'true'}, True, True),
        ({'ArtemisUseSpot': 'false'}, True, False),
        ({'ArtemisUseSpot': 'false'}, False, False),
        ({}, True, True),
        ({}, False, False),
        ({}, None, False),
    ],
)
def test_should_use_spot_request(
    logger: gluetool.log.ContextAdapter,
    user_data: dict[str, Optional[str]],
    pool_config_use_spot: Optional[bool],
    expected: bool,
) -> None:
    pool_config: dict[str, object] = {
        'access-key-id': 'dummy',
        'secret-access-key': 'dummy',
        'default-region': 'dummy',
    }

    if pool_config_use_spot is not None:
        pool_config['use-spot-request'] = pool_config_use_spot

    driver = tft.artemis.drivers.aws.AWSDriver(logger, 'dummy-aws-pool', pool_config)
    guest_request = tft.artemis.db.GuestRequest(
        guestname='dummy-guest',
        _environment={},
        ownername='dummy-user',
        priorityname='dummy-priority-group',
        poolname='dummy-aws-pool',
        ctime=datetime.datetime.utcnow(),
        state='ROUTING',
        address=None,
        ssh_keyname='dummy-key',
        ssh_port=22,
        ssh_username='root',
        _pool_data={},
        _user_data=user_data,
    )

    assert driver._should_use_spot_request(guest_request) is expected
