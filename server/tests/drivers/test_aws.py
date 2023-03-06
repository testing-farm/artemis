# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
import json
from typing import Dict, Optional, cast
from unittest.mock import ANY, MagicMock

import _pytest.monkeypatch
import pytest
import sqlalchemy
from gluetool.log import ContextAdapter
from gluetool.result import Ok, Result

import tft.artemis.drivers.aws

WATCHDOG_COMPLETE: Result[tft.artemis.drivers.WatchdogState, tft.artemis.Failure] = Ok(
    tft.artemis.drivers.WatchdogState.COMPLETE
)

WATCHDOG_CONTINUE: Result[tft.artemis.drivers.WatchdogState, tft.artemis.Failure] = Ok(
    tft.artemis.drivers.WatchdogState.CONTINUE
)


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


@pytest.mark.parametrize(
    ('pool_data', 'state', 'code', 'expected_state', 'expected_log_msg'),
    [
        # No tracking for non-spot instances regardless of state
        ({'instance_id': '42', 'spot_instance_id': None}, 'ready', '', WATCHDOG_COMPLETE, ''),
        ({'instance_id': '42', 'spot_instance_id': None}, 'open', '', WATCHDOG_COMPLETE, ''),
        ({'instance_id': '42', 'spot_instance_id': None}, 'closed', 'instance-terminated-by-user',
         WATCHDOG_COMPLETE, ''),
        # continue tracking active spot instances
        ({'instance_id': '42', 'spot_instance_id': 'sir-42'}, 'open', '', WATCHDOG_CONTINUE, ''),
        ({'instance_id': '42', 'spot_instance_id': 'sir-42'}, 'active', '', WATCHDOG_CONTINUE, ''),
        # normally terminated instance
        ({'instance_id': '42', 'spot_instance_id': 'sir-42'}, 'cancelled', 'instance-terminated-by-user',
         WATCHDOG_COMPLETE, ''),
        # terminated instance not in expected state
        ({'instance_id': '42', 'spot_instance_id': 'sir-42'}, 'some-other-untypical-of-user-termination-code',
         'instance-terminated-by-user',
         WATCHDOG_COMPLETE, 'spot instance terminated prematurely'),
        # no-capacity-event
        ({'instance_id': '42', 'spot_instance_id': 'sir-42'}, 'closed', 'spot-instance-terminated-no-capacity',
         WATCHDOG_COMPLETE, 'spot instance terminated prematurely'),
    ]
)
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_aws_guest_watchdog(
    pool_data: tft.artemis.JSONType,
    state: str,
    code: str,
    expected_state: Result[tft.artemis.drivers.WatchdogState, tft.artemis.Failure],
    expected_log_msg: str,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    logger: ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    guest_request = tft.artemis.db.GuestRequest(
        guestname='dummy-guest',
        _environment={},
        ownername='dummy-user',
        priorityname='dummy-priority-group',
        poolname='dummy-aws-pool',
        ctime=datetime.datetime.utcnow(),
        # TODO: sqlalchemy uses enum member names, not values, and GuestState values are lowercased,
        # therefore they don't match the enum members in DB. upper() is needed, but the correct
        # fix would be to change values of GuestState members to uppercased versions.
        state=state.upper(),
        address=None,
        ssh_keyname='dummy-key',
        ssh_port=22,
        ssh_username='root',
        pool_data=json.dumps(pool_data),
        _user_data={}
    )
    monkeypatch.setattr(tft.artemis.drivers.aws.AWSDriver, '_describe_spot_instance',
                        MagicMock(return_value=Ok({'State': state, 'Status': {'Code': code, 'Message': ''}})))
    monkeypatch.setattr(guest_request, 'log_error_event', MagicMock())
    aws_driver = tft.artemis.drivers.aws.AWSDriver(poolname='dummy-aws-pool',
                                                   logger=logger,
                                                   pool_config={'access-key-id': '42',
                                                                'secret-access-key': '42secret',
                                                                'default-region': 'some-region',
                                                                'command': 'aws'})
    res_state = aws_driver.guest_watchdog(logger=logger, session=session, guest_request=guest_request)
    assert res_state == expected_state
    if not expected_log_msg:
        # Check that no error has been logged
        cast(MagicMock, guest_request.log_error_event).assert_not_called()
    else:
        cast(MagicMock, guest_request.log_error_event).assert_called()
        cast(MagicMock, guest_request.log_error_event).assert_called_once_with(
            logger, session, 'spot instance terminated prematurely', ANY)
        failure = cast(MagicMock, guest_request.log_error_event).call_args.args[3]
        assert isinstance(failure, tft.artemis.Failure)
        assert failure.message == 'spot instance terminated prematurely'
        assert failure.details['guestname'] == 'dummy-guest'
        assert failure.details['spot_instance_id'] == cast(Dict[str, str], pool_data)['spot_instance_id']
