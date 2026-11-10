# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
from typing import Any
from unittest import mock

import gluetool.log
import pytest
from gluetool.result import Ok, Result

from tft.artemis import Failure
from tft.artemis.drivers.aws import AWSDriver


@pytest.fixture(name='guest_request')
def fixture_guest_request() -> mock.MagicMock:
    guest_request = mock.MagicMock(name='guest_request')
    guest_request.guestname = 'dummy-guest'
    guest_request.user_data = {}

    return guest_request


@pytest.fixture(name='custom_tags')
def fixture_custom_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('ARTEMIS_INSTANCE_GUEST_NAME_TAG', 'CustomGuestName')
    monkeypatch.setenv('ARTEMIS_INSTANCE_GUEST_LABEL_TAG', 'CustomGuestLabel')


@pytest.mark.usefixtures('custom_tags')
def test_get_guest_tags(
    aws_pool: AWSDriver, logger: gluetool.log.ContextAdapter, guest_request: mock.MagicMock
) -> None:
    with mock.patch('tft.artemis.drivers.GuestTag') as mock_guest_tag:
        mock_guest_tag.fetch_system_tags.return_value = Ok([])
        mock_guest_tag.fetch_pool_tags.return_value = Ok([])

        tags = aws_pool.get_guest_tags(logger, mock.MagicMock(), guest_request).unwrap()

    assert tags == {'CustomGuestName': 'dummy-guest', 'CustomGuestLabel': 'artemis-dummy-guest'}


@pytest.mark.usefixtures('custom_tags')
def test_query_instances(
    aws_pool: AWSDriver, logger: gluetool.log.ContextAdapter, guest_request: mock.MagicMock
) -> None:
    commands: list[list[str]] = []

    def _aws_command(args: list[str], **kwargs: Any) -> Result[Any, Failure]:
        commands.append(args)

        if args[1] == 'describe-spot-instance-requests':
            return Ok([])

        return Ok(
            [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1',
                            'LaunchTime': '2026-01-01T00:00:00.000Z',
                            'State': {'Name': 'running'},
                            'Tags': [
                                {'Key': 'CustomGuestName', 'Value': 'dummy-guest'},
                                {'Key': 'CustomGuestLabel', 'Value': 'artemis-dummy-guest-1'},
                            ],
                        }
                    ]
                }
            ]
        )

    with mock.patch.object(aws_pool, '_aws_command', side_effect=_aws_command):
        instances = aws_pool._query_instances_by_guest_request(logger, mock.MagicMock(), guest_request).unwrap()

    assert [instance.name for instance in instances] == ['artemis-dummy-guest-1']

    for command in commands:
        assert 'Name=tag:CustomGuestName,Values=dummy-guest' in command
