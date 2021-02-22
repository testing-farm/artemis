import json

from gluetool.result import Error, Ok
from mock import MagicMock
from pytest import fixture

import tft.artemis.tasks
from tft.artemis import Failure
from tft.artemis.tasks import do_release_pool_resources

from . import assert_failure_log


@fixture(name='mock_pool')
def fixture_mock_pool(monkeypatch):
    mock_pool = MagicMock(
        name='PoolDriver (mock)'
    )

    mock_pool.release_pool_resources = MagicMock(
        name='PoolDriver.release_pool_driver (mock)',
        return_value=Ok(None)
    )

    mock_get_pool = MagicMock(
        name='_get_pool (mock)',
        return_value=Ok(mock_pool)
    )

    monkeypatch.setattr(tft.artemis.tasks, '_get_pool', mock_get_pool)

    return mock_pool, mock_get_pool


def test_release_pool_resources(context, caplog, monkeypatch, mock_pool):
    """
    Test the success path.
    """

    pool, _ = mock_pool

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_ok
    assert r is tft.artemis.tasks.SUCCESS

    pool.release_pool_resources.assert_called_once_with(tft.artemis.LOGGER.get(), mock_resource_ids)


def test_release_pool_resources_broken_json(context, caplog, monkeypatch, mock_pool):
    """
    Test the broken, unserializable resource IDs are handled.
    """

    pool, _ = mock_pool

    r = do_release_pool_resources(
        'dummy-pool',
        '{',
        None
    )

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'failed to unserialize resource IDs'
    assert isinstance(failure.exception, json.decoder.JSONDecodeError)
    assert failure.details['serialized_resource_ids'] == '{'

    pool.release_pool_resources.assert_not_called()

    assert_failure_log(caplog, 'failed to unserialize resource IDs', exception_label='JSONDecodeError:')


def test_release_pool_resources_broken_pool(context, caplog, monkeypatch, mock_pool):
    """
    Test the failure of fetching pool instance is handled.
    """

    pool, get_pool = mock_pool

    get_pool.return_value = Error(Failure('dummy get_pool failure'))

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'dummy get_pool failure'
    assert failure.exception is None

    pool.release_pool_resources.assert_not_called()

    assert_failure_log(caplog, 'pool sanity failed')


def test_release_pool_resources_failed(context, caplog, monkeypatch, mock_pool):
    """
    Test the pool failure is handled.
    """

    pool, _ = mock_pool

    pool.release_pool_resources.return_value = Error(Failure('injected pool failure'))

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'injected pool failure'
    assert failure.exception is None

    pool.release_pool_resources.assert_called_once_with(tft.artemis.LOGGER.get(), mock_resource_ids)

    assert_failure_log(caplog, 'failed to release pool resources')
