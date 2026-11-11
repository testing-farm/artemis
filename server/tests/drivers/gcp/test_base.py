# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock

import _pytest.monkeypatch
import gluetool.log
import pytest
import sqlalchemy
import sqlalchemy.orm.session

import tft.artemis.context
import tft.artemis.db
import tft.artemis.drivers.gcp


@pytest.fixture(name='gcp_pool', scope='function')
def fixture_gcp_pool(logger: gluetool.log.ContextAdapter) -> tft.artemis.drivers.gcp.GCPDriver:
    return tft.artemis.drivers.gcp.GCPDriver(
        logger,
        'dummy-gcp-pool',
        {
            'project': 'dummy-project',
            'zone': 'dummy-zone',
        },
    )


def test_api_call_timeout_default(gcp_pool: tft.artemis.drivers.gcp.GCPDriver) -> None:
    mock_fn = MagicMock()

    gcp_pool._api_call(mock_fn, request='dummy-request')

    mock_fn.assert_called_once_with(request='dummy-request', timeout=60)


def test_api_call_timeout_per_pool(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver, monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    monkeypatch.setenv('ARTEMIS_GCP_API_TIMEOUT_dummy_gcp_pool', '123')

    mock_fn = MagicMock()

    # `_api_timeout` is a cached property, but the fixture creates a fresh driver for each test.
    gcp_pool._api_call(mock_fn, request='dummy-request')

    mock_fn.assert_called_once_with(request='dummy-request', timeout=123)


def test_api_call_timeout_disabled(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver, monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    monkeypatch.setenv('ARTEMIS_GCP_API_TIMEOUT_dummy_gcp_pool', '0')

    mock_fn = MagicMock()

    gcp_pool._api_call(mock_fn, request='dummy-request')

    # With the knob disabled, the `timeout` argument must be left out entirely: passing `timeout=None`
    # explicitly would disable the client library's own default timeout as well.
    mock_fn.assert_called_once_with(request='dummy-request')


def test_api_call_explicit_timeout_not_overridden(gcp_pool: tft.artemis.drivers.gcp.GCPDriver) -> None:
    mock_fn = MagicMock()

    gcp_pool._api_call(mock_fn, request='dummy-request', timeout=5)

    mock_fn.assert_called_once_with(request='dummy-request', timeout=5)


def test_api_call_retry_passed_through(gcp_pool: tft.artemis.drivers.gcp.GCPDriver) -> None:
    mock_fn = MagicMock()

    gcp_pool._api_call(mock_fn, request='dummy-request', retry=None)

    mock_fn.assert_called_once_with(request='dummy-request', timeout=60, retry=None)


def test_api_call_invalid_knob_value(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver, monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    monkeypatch.setenv('ARTEMIS_GCP_API_TIMEOUT_dummy_gcp_pool', 'not-a-number')

    mock_fn = MagicMock()

    gcp_pool._api_call(mock_fn, request='dummy-request')

    # Invalid knob value is reported, and the client library's default timeout is used.
    mock_fn.assert_called_once_with(request='dummy-request')


def test_api_retry_deadline_default(gcp_pool: tft.artemis.drivers.gcp.GCPDriver) -> None:
    retry = gcp_pool._api_retry

    assert retry is not None
    assert retry._deadline == 180


def test_api_retry_deadline_per_pool(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver, monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    monkeypatch.setenv('ARTEMIS_GCP_API_RETRY_DEADLINE_dummy_gcp_pool', '123')

    assert gcp_pool._api_retry is not None
    assert gcp_pool._api_retry._deadline == 123


def test_api_retry_deadline_disabled(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver, monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> None:
    monkeypatch.setenv('ARTEMIS_GCP_API_RETRY_DEADLINE_dummy_gcp_pool', '0')

    assert gcp_pool._api_retry is None


@pytest.mark.usefixtures('schema_actual')
def test_api_timeout_from_db(
    gcp_pool: tft.artemis.drivers.gcp.GCPDriver,
    session: sqlalchemy.orm.session.Session,
) -> None:
    session.execute(sqlalchemy.insert(tft.artemis.db.Knob).values(knobname='gcp.api-timeout:dummy-gcp-pool', value=123))

    session.commit()

    token = tft.artemis.context.SESSION.set(session)

    try:
        assert gcp_pool._api_timeout == 123

    finally:
        tft.artemis.context.SESSION.reset(token)
