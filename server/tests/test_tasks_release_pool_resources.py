import json
import threading
from typing import Callable, Tuple, cast

import _pytest.logging
import _pytest.monkeypatch
import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from mock import MagicMock
from pytest import fixture

import tft.artemis.drivers
import tft.artemis.tasks
from tft.artemis import Failure
from tft.artemis.drivers import PoolDriver
from tft.artemis.tasks import do_release_pool_resources

from . import assert_failure_log


@fixture(name='mock_pool')
def fixture_mock_pool(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
) -> Tuple[
    PoolDriver,
    Callable[
        [gluetool.log.ContextAdapter, sqlalchemy.orm.session.Session, str],
        Result[tft.artemis.drivers.PoolDriver, Failure]
    ]
]:
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


def test_release_pool_resources(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    mock_pool: Tuple[
        PoolDriver,
        Callable[
            [gluetool.log.ContextAdapter, sqlalchemy.orm.session.Session, str],
            Result[tft.artemis.drivers.PoolDriver, Failure]
        ]
    ]
) -> None:
    """
    Test the success path.
    """

    pool, _ = mock_pool

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_ok
    assert r is tft.artemis.tasks.SUCCESS

    cast(
        MagicMock,
        pool.release_pool_resources
    ).assert_called_once_with(logger, json.dumps(mock_resource_ids))


def test_release_pool_resources_broken_pool(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    mock_pool: Tuple[
        PoolDriver,
        Callable[
            [gluetool.log.ContextAdapter, sqlalchemy.orm.session.Session, str],
            Result[tft.artemis.drivers.PoolDriver, Failure]
        ]
    ]
) -> None:
    """
    Test the failure of fetching pool instance is handled.
    """

    pool, get_pool = mock_pool

    cast(MagicMock, get_pool).return_value = Error(Failure('dummy get_pool failure'))

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'dummy get_pool failure'
    assert failure.exception is None

    cast(
        MagicMock,
        pool.release_pool_resources
    ).assert_not_called()

    assert_failure_log(caplog, 'pool sanity failed')


def test_release_pool_resources_failed(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    mock_pool: Tuple[
        PoolDriver,
        Callable[
            [gluetool.log.ContextAdapter, sqlalchemy.orm.session.Session, str],
            Result[tft.artemis.drivers.PoolDriver, Failure]
        ]
    ]
) -> None:
    """
    Test the pool failure is handled.
    """

    pool, _ = mock_pool

    cast(
        MagicMock,
        pool.release_pool_resources
    ).return_value = Error(Failure('injected pool failure'))

    mock_resource_ids = {'instance_id': 79}

    r = do_release_pool_resources(
        logger,
        db,
        session,
        threading.Event(),
        'dummy-pool',
        json.dumps(mock_resource_ids),
        None
    )

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'injected pool failure'
    assert failure.exception is None

    cast(
        MagicMock,
        pool.release_pool_resources
    ).assert_called_once_with(logger, json.dumps(mock_resource_ids))

    assert_failure_log(caplog, 'failed to release pool resources')
