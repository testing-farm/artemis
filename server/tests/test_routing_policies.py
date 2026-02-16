# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Policies are filters, so try to cover possible venues:

* guest request has special trait, and there are matching pools,
* guest request has special trait, and there are no matching pools,
* guest request does not have special trait,

and maybe add others if they make sense for the given policy. But in general, we want to make sure
we pick right pools when needed, we pick no pools when we can't satisfy the request, and that we
pick no (or all - "pass through" policies) pools when guest request doesn't care or apply.

This can be often reduced to using a helper function with the core of the test, parametrized with
just a couple of parameters - together with fixtures, this makes the actual tests much simpler.
"""

import datetime
from typing import Any, NamedTuple, Optional, cast
from unittest.mock import MagicMock

import _pytest.monkeypatch
import gluetool.log
import pytest
import sqlalchemy
import sqlalchemy.orm.session
from gluetool.result import Error, Ok
from returns.pipeline import is_successful
from returns.result import Failure as _Error, Success as _Ok

import tft.artemis
import tft.artemis.context
import tft.artemis.db
import tft.artemis.drivers.localhost
import tft.artemis.routing_policies
from tft.artemis.drivers import PoolDriver
from tft.artemis.metrics import PoolMetrics

from . import MockPatcher


# Routing knobs do have a DB source, therefore we cannot acquire their value right away
# but we have to rather query them when needed.
def timeout_reached_age_too_young(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_REQUEST_MAX_TIME.get_value(session=session).unwrap() // 2


def timeout_reached_age_too_old(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_REQUEST_MAX_TIME.get_value(session=session).unwrap() * 2


def one_attempt_forgiving_too_young(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_FORGIVING_TIME.get_value(session=session).unwrap() // 2


def one_attempt_forgiving_too_old(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_FORGIVING_TIME.get_value(session=session).unwrap() * 2


def enough_resources_excess_multiplier(session: sqlalchemy.orm.session.Session) -> float:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_RESOURCE_THRESHOLD.get_value(session=session).unwrap() + 10


class MockInputs(NamedTuple):
    logger: gluetool.log.ContextAdapter
    session: sqlalchemy.orm.session.Session
    pools: list[PoolDriver[Any]]
    guest_request: MagicMock


@pytest.fixture
def mock_inputs() -> MockInputs:
    inputs = MockInputs(
        logger=MagicMock(name='logger<mock>'),
        session=MagicMock(
            name='session<mock>',
            bind=MagicMock(dialect=MagicMock()),
            # Mocks session.query().filter(...).one_or_none() called by knobs' DB source, to pretend
            # the mock has no record in the database. Yes, it is that ugly.
            query=MagicMock(
                return_value=MagicMock(
                    filter=MagicMock(return_value=MagicMock(one_or_none=MagicMock(return_value=None)))
                )
            ),
        ),
        pools=[
            MagicMock(name='pool_foo<mock>', poolname='dummy-pool'),
            MagicMock(name='pool_bar<mock>', poolname='not-so-dummy-pool'),
            MagicMock(name='pool_baz<mock>', poolname='another-cool-pool'),
        ],
        guest_request=MagicMock(name='guest_request<mock>'),
    )

    # We need `dialect` mock to have attribute `name` but it cannot be done by passing `name=...` to `MagiMock()`,
    # it must be done afterward.
    assert inputs.session.bind is not None  # narrow type
    inputs.session.bind.dialect.name = 'postgresql'

    return inputs


@pytest.fixture
def mock_policies(mock_inputs: MockInputs) -> list[tft.artemis.routing_policies.PolicyType]:
    _, _, mock_pools, _ = mock_inputs

    return [
        MagicMock(
            name='policy_foo<mock>',
            policy_name='policy-foo',
            return_value=Ok(tft.artemis.routing_policies.PolicyRuling.from_pools([mock_pools[0], mock_pools[1]])),
        ),
        MagicMock(
            name='policy_bar<mock>',
            policy_name='policy-bar',
            return_value=Ok(tft.artemis.routing_policies.PolicyRuling.from_pools([mock_pools[0]])),
        ),
    ]


def test_boilerplate(mock_inputs: MockInputs) -> None:
    mock_return_value: tft.artemis.routing_policies.PolicyReturnType = Ok(MagicMock(name='policy_ruling<mock>'))

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pools: list[PoolDriver[Any]],
        guest_request: tft.artemis.db.GuestRequest,
    ) -> tft.artemis.routing_policies.PolicyReturnType:
        assert isinstance(logger, tft.artemis.routing_policies.PolicyLogger)
        assert logger._contexts == {'policy_name': (50, 'dummy-whatever')}

        assert session is mock_session
        assert pools is mock_pools
        assert guest_request is mock_guest_request

        return mock_return_value

    r_ruling = policy_dummy_whatever(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling is mock_return_value
    assert r_ruling.unwrap() is mock_return_value.unwrap()

    # TODO: test logging, it is important for keeping track of decisions


def test_boilerplate_error(mock_inputs: MockInputs) -> None:
    mock_return_value: tft.artemis.routing_policies.PolicyReturnType = Error(MagicMock(name='policy_ruling<mock>'))

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pools: list[PoolDriver[Any]],
        guest_request: tft.artemis.db.GuestRequest,
    ) -> tft.artemis.routing_policies.PolicyReturnType:
        return mock_return_value

    r_ruling = policy_dummy_whatever(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling is mock_return_value
    assert r_ruling.unwrap_error() is mock_return_value.unwrap_error()


def test_boilerplate_crash(mock_inputs: MockInputs) -> None:
    mock_exception = ValueError('dummy error')

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pools: list[PoolDriver[Any]],
        guest_request: tft.artemis.db.GuestRequest,
    ) -> tft.artemis.routing_policies.PolicyReturnType:
        raise mock_exception

    r_ruling = policy_dummy_whatever(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_error

    failure = r_ruling.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.exception is mock_exception


def test_collect_pool_capabilities(mock_inputs: MockInputs, mockpatch: MockPatcher) -> None:
    _, _, mock_pools, _ = mock_inputs

    mock_capabilities = [MagicMock(name=f'{pool.poolname}.capabilities<mock>') for pool in mock_pools]

    for pool, capabilities in zip(mock_pools, mock_capabilities):
        mockpatch(pool, 'capabilities').return_value = _Ok(capabilities)

    r = tft.artemis.routing_policies.collect_pool_capabilities(mock_pools)

    assert is_successful(r)

    collected = r.unwrap()

    for i in range(len(mock_pools)):
        expected_pool = mock_pools[i]
        expected_capabilities = mock_capabilities[i]

        actual_pool, actual_capabilities = collected[i]

        assert actual_pool is expected_pool
        assert actual_capabilities is expected_capabilities


def test_collect_pool_capabilities_error(
    mock_inputs: MockInputs, monkeypatch: _pytest.monkeypatch.MonkeyPatch, mockpatch: MockPatcher
) -> None:
    _, _, mock_pools, _ = mock_inputs

    mockpatch(mock_pools[0], 'capabilities').return_value = _Ok(
        MagicMock(name=f'{mock_pools[0].poolname}.capabilities<mock>')
    )
    mockpatch(mock_pools[1], 'capabilities').return_value = _Error(MagicMock(name='failure<mock>'))
    mockpatch(mock_pools[2], 'capabilities').return_value = _Ok(
        MagicMock(name=f'{mock_pools[2].poolname}.capabilities<mock>')
    )

    r = tft.artemis.routing_policies.collect_pool_capabilities(mock_pools)

    assert not is_successful(r)

    failure = r.failure()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.caused_by == cast(MagicMock, mock_pools[1]).capabilities.return_value.failure()


def test_run_routing_policies(
    mock_inputs: MockInputs, mock_policies: list[tft.artemis.routing_policies.PolicyType]
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger, mock_session, mock_guest_request, mock_pools, mock_policies
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == [mock_pools[0]]

    cast(MagicMock, mock_policies[0]).assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    cast(MagicMock, mock_policies[1]).assert_called_once_with(
        mock_logger, mock_session, [mock_pools[0], mock_pools[1]], mock_guest_request
    )


def test_create_preferrence_filter_by_driver_class_no_trigger(mock_inputs: MockInputs) -> None:
    mock_logger, mock_session, _, mock_guest_request = mock_inputs

    policy = tft.artemis.routing_policies.create_preferrence_filter_by_driver_class(
        'dummy-custom-policy', cast(type[PoolDriver[Any]], dict)
    )

    assert cast(tft.artemis.routing_policies.PolicyWrapperType, policy).policy_name == 'dummy-custom-policy'

    mock_pools: list[PoolDriver[Any]] = [
        PoolDriver(mock_logger, 'pool1', {}),
        PoolDriver(mock_logger, 'pool2', {}),
        PoolDriver(mock_logger, 'pool3', {}),
    ]

    r_ruling = policy(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == mock_pools


def test_create_preferrence_filter_by_driver_class(mock_inputs: MockInputs) -> None:
    mock_logger, mock_session, _, mock_guest_request = mock_inputs

    policy = tft.artemis.routing_policies.create_preferrence_filter_by_driver_class(
        'dummy-custom-policy', tft.artemis.drivers.localhost.LocalhostDriver
    )

    assert cast(tft.artemis.routing_policies.PolicyWrapperType, policy).policy_name == 'dummy-custom-policy'

    mock_pools: list[PoolDriver[Any]] = [
        PoolDriver(mock_logger, 'pool1', {}),
        PoolDriver(mock_logger, 'pool2', {}),
        tft.artemis.drivers.localhost.LocalhostDriver(mock_logger, 'pool3', {}),
        PoolDriver(mock_logger, 'pool4', {}),
    ]

    r_ruling = policy(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == [mock_pools[2]]


def test_run_routing_policies_cancel(
    mock_inputs: MockInputs, mock_policies: list[tft.artemis.routing_policies.PolicyType]
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    cast(MagicMock, mock_policies[0]).return_value = Ok(tft.artemis.routing_policies.PolicyRuling(cancel=True))

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger, mock_session, mock_guest_request, mock_pools, mock_policies
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is True

    cast(MagicMock, mock_policies[0]).assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    cast(MagicMock, mock_policies[1]).assert_not_called()


def test_run_routing_policies_error(
    mock_inputs: MockInputs, mock_policies: list[tft.artemis.routing_policies.PolicyType]
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_failure = MagicMock(name='failure<mock>')

    cast(MagicMock, mock_policies[0]).return_value = Error(mock_failure)

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger, mock_session, mock_guest_request, mock_pools, mock_policies
    )

    assert r_ruling.is_error

    failure = r_ruling.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'failed to route guest request'
    assert failure.caused_by is mock_failure

    cast(MagicMock, mock_policies[0]).assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    cast(MagicMock, mock_policies[1]).assert_not_called()


def do_test_policy_match_pool_name(
    mock_inputs: MockInputs, pool_name: Optional[str], expected_pools: Optional[list[PoolDriver[Any]]]
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_guest_request.environment = tft.artemis.environment.Environment(
        hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
        os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
        kickstart=tft.artemis.environment.Kickstart(),
        pool=pool_name,
    )

    r_ruling = tft.artemis.routing_policies.policy_match_pool_name(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if pool_name == 'dummy-pool':
        assert ruling.allowed_pools == [mock_pools[0]]

    else:
        assert ruling.allowed_pools == (mock_pools if expected_pools is None else expected_pools)


def test_policy_match_pool_name(mock_inputs: MockInputs) -> None:
    do_test_policy_match_pool_name(mock_inputs, 'dummy-pool', None)


def test_policy_match_pool_name_no_match(mock_inputs: MockInputs) -> None:
    do_test_policy_match_pool_name(mock_inputs, 'pool-that-does-not-exist', [])


def test_policy_match_pool_name_no_trigger(mock_inputs: MockInputs) -> None:
    do_test_policy_match_pool_name(mock_inputs, None, None)


def do_test_policy_supports_architecture(
    mock_inputs: MockInputs, monkeypatch: _pytest.monkeypatch.MonkeyPatch, provide_arch: bool
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    for mock_pool in mock_pools:
        monkeypatch.setattr(
            mock_pool,
            'capabilities',
            lambda: Ok(tft.artemis.drivers.PoolCapabilities(supported_architectures=['foo', 'bar'])),
        )

    if provide_arch:
        monkeypatch.setattr(
            mock_pools[1],
            'capabilities',
            lambda: Ok(tft.artemis.drivers.PoolCapabilities(supported_architectures=['foo', 'bar', 'x86_64'])),
        )

    mock_guest_request.environment = tft.artemis.environment.Environment(
        hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
        os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
        kickstart=tft.artemis.environment.Kickstart(),
        snapshots=False,
    )

    r_ruling = tft.artemis.routing_policies.policy_supports_architecture(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if provide_arch:
        assert ruling.allowed_pools == [mock_pools[1]]

    elif not provide_arch:
        assert ruling.allowed_pools == []

    else:
        raise AssertionError('unreachable')


def test_policy_supports_architecture(
    mock_inputs: MockInputs,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    do_test_policy_supports_architecture(mock_inputs, monkeypatch, True)


def test_policy_supports_architecture_no_match(
    mock_inputs: MockInputs,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    do_test_policy_supports_architecture(mock_inputs, monkeypatch, False)


def do_test_policy_least_crowded(
    mockpatch: MockPatcher, mock_inputs: MockInputs, pool_count: Optional[int] = None, one_crowded: bool = True
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_metrics = []

    for mock_pool in mock_pools:
        mock_pool_metrics = PoolMetrics(mock_pool.poolname)
        mock_pool_metrics.current_guest_request_count = 50

        mock_metrics.append(mock_pool_metrics)

    if one_crowded is True:
        mock_metrics[1].current_guest_request_count = 100

    if pool_count is not None:
        mock_pools = mock_pools[:pool_count]
        mock_metrics = mock_metrics[:pool_count]

    mockpatch(tft.artemis.routing_policies, 'collect_pool_metrics').return_value = Ok(
        [(_pool, _metrics) for _pool, _metrics in zip(mock_pools, mock_metrics)]
    )

    r_ruling = tft.artemis.routing_policies.policy_least_crowded(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if pool_count is not None:
        assert ruling.allowed_pools == mock_pools

    elif one_crowded is True:
        assert ruling.allowed_pools == [mock_pools[0], mock_pools[2]]

    else:
        assert ruling.allowed_pools == mock_pools


def test_policy_least_crowded(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_least_crowded(mockpatch, mock_inputs)


def test_policy_least_crowded_one_pool(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_least_crowded(mockpatch, mock_inputs, pool_count=0)
    do_test_policy_least_crowded(mockpatch, mock_inputs, pool_count=1)


def test_policy_least_crowded_one_pool_all_worthy(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_least_crowded(mockpatch, mock_inputs, one_crowded=False)


def do_test_policy_timeout_reached(
    mock_inputs: MockInputs, empty_events: bool = False, age: Optional[int] = None
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    if empty_events:
        mock_guest_request.fetch_events = lambda session, eventname: Ok([])

    else:
        event = tft.artemis.db.GuestEvent('created', 'dummy-guest')
        event.updated = datetime.datetime.utcnow() - datetime.timedelta(seconds=(age or 0))

        mock_guest_request.fetch_events = lambda session, eventname: Ok([event])

    r_ruling = tft.artemis.routing_policies.policy_timeout_reached(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)

    if age == timeout_reached_age_too_old(mock_session):
        assert ruling.cancel is True
        assert ruling.allowed_pools == []

    elif age == timeout_reached_age_too_young(mock_session) or empty_events:
        assert ruling.cancel is False
        assert ruling.allowed_pools == mock_pools


def test_policy_timeout_reached(logger: gluetool.log.ContextAdapter, mock_inputs: MockInputs) -> None:
    do_test_policy_timeout_reached(mock_inputs, age=timeout_reached_age_too_old(mock_inputs.session))


def test_policy_timeout_reached_no_trigger(mock_inputs: MockInputs) -> None:
    do_test_policy_timeout_reached(mock_inputs, age=timeout_reached_age_too_young(mock_inputs.session))


def test_policy_timeout_reached_no_events(mock_inputs: MockInputs) -> None:
    do_test_policy_timeout_reached(mock_inputs, empty_events=True)


def do_policy_one_attempt_forgiving(
    mock_inputs: MockInputs, empty_events: bool = False, age: Optional[int] = None
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    if empty_events:
        mock_guest_request.fetch_events = lambda session, eventname: Ok([])

    else:
        event = tft.artemis.db.GuestEvent('error', 'dummy-guest', failure={'poolname': 'dummy-pool'})
        event.updated = datetime.datetime.utcnow() - datetime.timedelta(seconds=(age or 0))

        mock_guest_request.fetch_events = lambda session, eventname: Ok([event])

    r_ruling = tft.artemis.routing_policies.policy_one_attempt_forgiving(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if age == one_attempt_forgiving_too_old(mock_session):
        assert ruling.allowed_pools == mock_pools

    elif age == one_attempt_forgiving_too_young(mock_session):
        assert ruling.allowed_pools == [mock_pools[1], mock_pools[2]]

    elif empty_events:
        assert ruling.allowed_pools == mock_pools


def test_policy_one_attempt_forgiving(mock_inputs: MockInputs) -> None:
    do_policy_one_attempt_forgiving(mock_inputs, age=one_attempt_forgiving_too_young(mock_inputs.session))


def test_policy_one_attempt_forgiving_no_trigger(mock_inputs: MockInputs) -> None:
    do_policy_one_attempt_forgiving(mock_inputs, age=one_attempt_forgiving_too_old(mock_inputs.session))


def test_policy_one_attempt_forgiving_no_events(mock_inputs: MockInputs) -> None:
    do_policy_one_attempt_forgiving(mock_inputs, empty_events=True)


def do_test_policy_enough_resources(
    mockpatch: MockPatcher, mock_inputs: MockInputs, pool_count: Optional[int] = None, one_crowded: bool = True
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    # TODO: use proper fixture once it lands
    tft.artemis.context.CACHE.set(MagicMock(name='cache<mock>'))
    tft.artemis.context.SESSION.set(mock_session)

    mock_metrics = []

    for mock_pool in mock_pools:
        mock_pool_metrics = PoolMetrics(mock_pool.poolname)

        mock_pool_metrics.resources.limits.cores = 100
        mock_pool_metrics.resources.limits.memory = 100
        mock_pool_metrics.resources.limits.diskspace = 100

        mock_pool_metrics.resources.usage.cores = 50
        mock_pool_metrics.resources.usage.memory = 50
        mock_pool_metrics.resources.usage.diskspace = 50

        mock_metrics.append(mock_pool_metrics)

    if one_crowded is True:
        mock_metrics[1].resources.usage.cores = int(100 * enough_resources_excess_multiplier(mock_session))

    if pool_count is not None:
        mock_pools = mock_pools[:pool_count]
        mock_metrics = mock_metrics[:pool_count]

    mockpatch(tft.artemis.routing_policies, 'collect_pool_metrics').return_value = Ok(
        [(_pool, _metrics) for _pool, _metrics in zip(mock_pools, mock_metrics)]
    )

    r_ruling = tft.artemis.routing_policies.policy_enough_resources(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if pool_count is not None:
        assert ruling.allowed_pools == mock_pools

    elif one_crowded is True:
        assert ruling.allowed_pools == [mock_pools[0], mock_pools[2]]

    else:
        assert ruling.allowed_pools == mock_pools


def test_policy_enough_resources(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_enough_resources(mockpatch, mock_inputs)


def test_policy_enough_resources_one_pool(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_enough_resources(mockpatch, mock_inputs, pool_count=0)
    do_test_policy_enough_resources(mockpatch, mock_inputs, pool_count=1)


def test_policy_enough_resources_all_worthy(mockpatch: MockPatcher, mock_inputs: MockInputs) -> None:
    do_test_policy_enough_resources(mockpatch, mock_inputs, one_crowded=False)


def do_test_policy_use_only_when_addressed(
    mock_inputs: MockInputs, mark_pool: Optional[str], requested_pool: Optional[str], expected_pool_names: list[str]
) -> None:
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    for pool in mock_pools:
        cast(MagicMock, pool).use_only_when_addressed = pool.poolname == mark_pool

    mock_guest_request.environment.pool = requested_pool

    r_ruling = tft.artemis.routing_policies.policy_use_only_when_addressed(
        mock_logger, mock_session, mock_pools, mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    assert [pool_ruling.pool.poolname for pool_ruling in ruling.allowed_rulings] == expected_pool_names


def test_policy_use_only_when_addressed_no_marked_pool(mock_inputs: MockInputs) -> None:
    do_test_policy_use_only_when_addressed(mock_inputs, None, None, [pool.poolname for pool in mock_inputs.pools])


def test_policy_use_only_when_addressed_marked_pool(mock_inputs: MockInputs) -> None:
    do_test_policy_use_only_when_addressed(
        mock_inputs,
        'not-so-dummy-pool',
        None,
        [pool.poolname for pool in mock_inputs.pools if pool.poolname != 'not-so-dummy-pool'],
    )


def test_policy_use_only_when_addressed_marked_pool_with_requested(mock_inputs: MockInputs) -> None:
    do_test_policy_use_only_when_addressed(
        mock_inputs, 'not-so-dummy-pool', 'dummy-pool', [pool.poolname for pool in mock_inputs.pools]
    )
