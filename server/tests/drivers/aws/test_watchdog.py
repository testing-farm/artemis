# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
from typing import cast
from unittest.mock import ANY, MagicMock

import _pytest.monkeypatch
import pytest
import sqlalchemy
from gluetool.log import ContextAdapter
from gluetool.result import Ok, Result

import tft_artemis.db
import tft_artemis.drivers.aws

WATCHDOG_COMPLETE: Result[tft_artemis.drivers.WatchdogState, tft_artemis.Failure] = Ok(
    tft_artemis.drivers.WatchdogState.COMPLETE
)

WATCHDOG_CONTINUE: Result[tft_artemis.drivers.WatchdogState, tft_artemis.Failure] = Ok(
    tft_artemis.drivers.WatchdogState.CONTINUE
)


@pytest.mark.parametrize(
    ('pool_data', 'state', 'code', 'expected_state', 'expected_log_msg'),
    [
        # No tracking for non-spot instances regardless of state
        ({'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': None}}, 'ready', '', WATCHDOG_COMPLETE, ''),
        ({'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': None}}, 'open', '', WATCHDOG_COMPLETE, ''),
        (
            {'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': None}},
            'closed',
            'instance-terminated-by-user',
            WATCHDOG_COMPLETE,
            '',
        ),
        # continue tracking active spot instances
        ({'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': 'sir-42'}}, 'open', '', WATCHDOG_CONTINUE, ''),
        ({'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': 'sir-42'}}, 'active', '', WATCHDOG_CONTINUE, ''),
        # normally terminated instance
        (
            {'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': 'sir-42'}},
            'cancelled',
            'instance-terminated-by-user',
            WATCHDOG_COMPLETE,
            '',
        ),
        # terminated instance not in expected state
        (
            {'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': 'sir-42'}},
            'some-other-untypical-of-user-termination-code',
            'instance-terminated-by-user',
            WATCHDOG_COMPLETE,
            'spot instance terminated prematurely',
        ),
        # no-capacity-event
        (
            {'dummy-aws-pool': {'instance_id': '42', 'spot_instance_id': 'sir-42'}},
            'closed',
            'spot-instance-terminated-no-capacity',
            WATCHDOG_COMPLETE,
            'spot instance terminated prematurely',
        ),
    ],
)
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_aws_guest_watchdog(
    pool_data: tft_artemis.db.SerializedPoolDataMapping,
    state: str,
    code: str,
    expected_state: Result[tft_artemis.drivers.WatchdogState, tft_artemis.Failure],
    expected_log_msg: str,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    logger: ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
) -> None:
    guest_request = tft_artemis.db.GuestRequest(
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
        _pool_data=pool_data,
        _user_data={},
    )
    monkeypatch.setattr(
        tft_artemis.drivers.aws.AWSDriver,
        '_describe_spot_instance',
        MagicMock(return_value=Ok({'State': state, 'Status': {'Code': code, 'Message': ''}})),
    )
    monkeypatch.setattr(guest_request, 'log_error_event', MagicMock())
    aws_driver = tft_artemis.drivers.aws.AWSDriver(
        poolname='dummy-aws-pool',
        logger=logger,
        pool_config={
            'access-key-id': '42',
            'secret-access-key': '42secret',
            'default-region': 'some-region',
            'command': 'aws',
        },
    )
    res_state = aws_driver.guest_watchdog(logger=logger, session=session, guest_request=guest_request)
    assert res_state == expected_state
    if not expected_log_msg:
        # Check that no error has been logged
        cast(MagicMock, guest_request.log_error_event).assert_not_called()
    else:
        cast(MagicMock, guest_request.log_error_event).assert_called()
        cast(MagicMock, guest_request.log_error_event).assert_called_once_with(
            logger, session, 'spot instance terminated prematurely', ANY
        )
        failure = cast(MagicMock, guest_request.log_error_event).call_args.args[3]
        assert isinstance(failure, tft_artemis.Failure)
        assert failure.message == 'spot instance terminated prematurely'
        assert failure.details['guestname'] == 'dummy-guest'
        assert failure.details['spot_instance_id'] == pool_data['dummy-aws-pool']['spot_instance_id']
