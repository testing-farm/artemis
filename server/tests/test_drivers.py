# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, Pattern, cast

import gluetool
import gluetool.log
import pytest
import sqlalchemy
from gluetool.result import Error, Ok, Result
from mock import MagicMock

import tft.artemis
import tft.artemis.drivers
import tft.artemis.drivers.localhost
from tft.artemis.drivers import vm_info_to_ip

from . import MockPatcher


@pytest.mark.parametrize(
    ('output', 'key', 'regex', 'expected'),
    [
        ({'address': '127.0.0.1'}, 'address', None, Ok('127.0.0.1')),
        ({'address': 'IPv4=127.0.0.1, IPv6=2001:db8::8a2e:370:7334'}, 'address', None, Ok('127.0.0.1')),
        ({'address': None}, 'address', None, Ok(None)),
        ({'address': '127.0.0'}, 'address', None, Error(tft.artemis.Failure('failed to parse an IP address'))),
    ]
)
def test_vm_info_to_ip(
    output: tft.artemis.JSONType,
    key: str,
    regex: Optional[Pattern[str]],
    expected: Result[str, tft.artemis.Failure]
) -> None:
    r_ip = vm_info_to_ip(output, key, regex=regex)

    if expected.is_ok:
        assert r_ip.is_ok
        assert r_ip.unwrap() == expected.unwrap()

    else:
        assert r_ip.is_error
        assert isinstance(r_ip.unwrap_error(), tft.artemis.Failure)


def test_driver_instantiate(logger: gluetool.log.ContextAdapter) -> None:
    r_pool = tft.artemis.drivers.PoolDriver._instantiate(logger, 'localhost', 'dummy-localhost', {})

    assert r_pool.is_ok

    pool = r_pool.unwrap()

    assert isinstance(pool, tft.artemis.drivers.localhost.LocalhostDriver)


def test_driver_instantiate_unknown_driver(logger: gluetool.log.ContextAdapter) -> None:
    r_pool = tft.artemis.drivers.PoolDriver._instantiate(logger, 'unknown-driver', 'dummy-pool', {})

    assert r_pool.is_error

    failure = r_pool.unwrap_error()

    assert failure.message == 'cannot find pool driver'
    assert failure.details['drivername'] == 'unknown-driver'


def test_driver_instantiate_failed_sanity(
    logger: gluetool.log.ContextAdapter,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.drivers.localhost.LocalhostDriver, 'sanity').return_value = Error(
        tft.artemis.Failure('failed sanity')
    )

    r_pool = tft.artemis.drivers.PoolDriver._instantiate(logger, 'localhost', 'dummy-localhost', {})

    assert r_pool.is_error

    failure = r_pool.unwrap_error()

    assert failure.message == 'failed sanity'


def test_driver_load_or_none(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mock_record = MagicMock(
        name='Pool()<M>',
        driver='dummy-driver',
        parameters={}
    )

    mock_pool = MagicMock(name='pool<M>')

    mockpatch(tft.artemis.drivers.SafeQuery, 'one_or_none').return_value = Ok(mock_record)  # type: ignore[attr-defined]
    mockpatch(tft.artemis.drivers.PoolDriver, '_instantiate').return_value = Ok(mock_pool)

    r_pool = tft.artemis.drivers.PoolDriver.load_or_none(logger, session, 'dummy-pool')

    assert r_pool.is_ok

    pool = r_pool.unwrap()

    cast(MagicMock, tft.artemis.drivers.PoolDriver._instantiate).assert_called_once_with(
        logger,
        'dummy-driver',
        'dummy-pool',
        mock_record.parameters
    )

    assert pool is mock_pool


def test_driver_load_or_none_no_such_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.drivers.SafeQuery, 'one_or_none').return_value = Ok(None)  # type: ignore[attr-defined]

    r_pool = tft.artemis.drivers.PoolDriver.load_or_none(logger, session, 'dummy-pool-that-does-not-exist')

    assert r_pool.is_ok

    assert r_pool.unwrap() is None


def test_driver_load_or_none_db_error(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mock_failure = tft.artemis.Failure('dummy failure')
    mockpatch(
        tft.artemis.drivers.SafeQuery,  # type: ignore[attr-defined]
        'one_or_none'
    ).return_value = Error(mock_failure)

    r_pool = tft.artemis.drivers.PoolDriver.load_or_none(logger, session, 'dummy-pool-that-does-not-exist')

    assert r_pool.is_error
    assert r_pool.unwrap_error() is mock_failure


def test_driver_load_or_none_instantiate_error(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mockpatch(
        tft.artemis.drivers.SafeQuery,  # type: ignore[attr-defined]
        'one_or_none'
    ).return_value = Ok(MagicMock(name='Pool<M>'))

    mock_failure = tft.artemis.Failure('dummy failure')
    mockpatch(tft.artemis.drivers.PoolDriver, '_instantiate').return_value = Error(mock_failure)

    r_pool = tft.artemis.drivers.PoolDriver.load_or_none(logger, session, 'dummy-pool')

    assert r_pool.is_error
    assert r_pool.unwrap_error() is mock_failure


def test_driver_load(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mock_pool = MagicMock(name='pool<M>')
    mockpatch(tft.artemis.drivers.PoolDriver, 'load_or_none').return_value = Ok(mock_pool)

    r = tft.artemis.drivers.PoolDriver.load(logger, session, 'dummy-pool')

    assert r.is_ok

    pool = r.unwrap()

    assert pool is mock_pool

    cast(MagicMock, tft.artemis.drivers.PoolDriver.load_or_none).assert_called_once_with(logger, session, 'dummy-pool')


def test_driver_load_no_such_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.drivers.PoolDriver, 'load_or_none').return_value = Ok(None)

    r = tft.artemis.drivers.PoolDriver.load(logger, session, 'dummy-pool')

    assert r.is_error

    failure = r.unwrap_error()

    assert failure.message == 'no such pool'
    assert failure.details['poolname'] == 'dummy-pool'

    _ = """
        if r_pool.is_error:
            return Error(r_pool.unwrap_error())
    """


def test_driver_load_error(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    mockpatch: MockPatcher
) -> None:
    mockpatch(tft.artemis.drivers.PoolDriver, 'load_or_none').return_value = Error(
        tft.artemis.Failure('dummy failure')
    )

    r = tft.artemis.drivers.PoolDriver.load(logger, session, 'dummy-pool')

    assert r.is_error

    failure = r.unwrap_error()

    assert failure.message == 'dummy failure'
