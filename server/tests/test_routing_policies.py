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

import collections
import datetime
import json

import pytest
import sqlalchemy
from gluetool.result import Error, Ok
from mock import MagicMock

import tft.artemis
import tft.artemis.context
import tft.artemis.db
import tft.artemis.routing_policies
from tft.artemis.metrics import PoolMetrics


# Routing knobs do have a DB source, therefore we cannot acquire their value right away
# but we have to rather query them when needed.
def TIMEOUT_REACHED_AGE_TOO_YOUNG(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_REQUEST_MAX_TIME.get_value(session=session).unwrap() / 2


def TIMEOUT_REACHED_AGE_TOO_OLD(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_REQUEST_MAX_TIME.get_value(session=session).unwrap() * 2


def ONE_ATTEMPT_FORGIVING_TOO_YOUNG(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_FORGIVING_TIME.get_value(session=session).unwrap() / 2


def ONE_ATTEMPT_FORGIVING_TOO_OLD(session: sqlalchemy.orm.session.Session) -> int:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_FORGIVING_TIME.get_value(session=session).unwrap() * 2


def ENOUGH_RESOURCES_EXCESS_MULTIPLIER(session: sqlalchemy.orm.session.Session) -> float:
    return tft.artemis.routing_policies.KNOB_ROUTE_POOL_RESOURCE_THRESHOLD.get_value(session=session).unwrap() + 10


MockInputs = collections.namedtuple(
    'MockInputs', ['logger', 'session', 'pools', 'guest_request']
)


@pytest.fixture
def mock_inputs():
    inputs = MockInputs(
        logger=MagicMock(name='logger<mock>'),
        session=MagicMock(
            name='session<mock>',
            bind=MagicMock(
                dialect=MagicMock()
            ),
            # Mocks session.query().filter(...).one_or_none() called by knobs' DB source, to pretend
            # the mock has no record in the database. Yes, it is that ugly.
            query=MagicMock(
                return_value=MagicMock(
                    filter=MagicMock(
                        return_value=MagicMock(
                            one_or_none=MagicMock(return_value=None)
                        )
                    )
                )
            ),
        ),
        pools=[
            MagicMock(name='pool_foo<mock>', poolname='dummy-pool'),
            MagicMock(name='pool_bar<mock>', poolname='not-so-dummy-pool'),
            MagicMock(name='pool_baz<mock>', poolname='another-cool-pool')
        ],
        guest_request=MagicMock(name='guest_request<mock>')
    )

    # We need `dialect` mock to have attribute `name` but it cannot be done by passing `name=...` to `MagiMock()`,
    # it must be done afterward.
    inputs.session.bind.dialect.name = 'postgresql'

    return inputs


@pytest.fixture
def mock_policies(mock_inputs):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    return [
        MagicMock(name='policy_foo<mock>', return_value=Ok(tft.artemis.routing_policies.PolicyRuling(
            allowed_pools=[mock_pools[0], mock_pools[1]]
        ))),
        MagicMock(name='policy_bar<mock>', return_value=Ok(tft.artemis.routing_policies.PolicyRuling(
            allowed_pools=[mock_pools[0]]
        )))
    ]


def test_boilerplate(mock_inputs):
    mock_return_value = Ok(MagicMock(name='policy_ruling<mock>'))

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(logger, session, pools, guest_request):
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


def test_boilerplate_error(mock_inputs):
    mock_return_value = Error(MagicMock(name='policy_ruling<mock>'))

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(logger, session, pools, guest_request):
        return mock_return_value

    r_ruling = policy_dummy_whatever(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling is mock_return_value
    assert r_ruling.unwrap_error() is mock_return_value.unwrap_error()


def test_boilerplate_crash(mock_inputs):
    mock_exception = ValueError('dummy error')

    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    @tft.artemis.routing_policies.policy_boilerplate
    def policy_dummy_whatever(logger, session, pools, guest_request):
        raise mock_exception

    r_ruling = policy_dummy_whatever(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_error

    failure = r_ruling.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.exception is mock_exception


def test_collect_pool_capabilities(mock_inputs):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_capabilities = [
        MagicMock(name='{}.capabilities<mock>'.format(pool.poolname)) for pool in mock_pools
    ]

    for pool, capabilities in zip(mock_pools, mock_capabilities):
        pool.capabilities = MagicMock(return_value=Ok(capabilities))

    r = tft.artemis.routing_policies.collect_pool_capabilities(mock_pools)

    assert r.is_ok

    collected = r.unwrap()

    for i in range(0, len(mock_pools)):
        expected_pool = mock_pools[i]
        expected_capabilities = mock_capabilities[i]

        actual_pool, actual_capabilities = collected[i]

        assert actual_pool is expected_pool
        assert actual_capabilities is expected_capabilities


def test_collect_pool_capabilities_error(mock_inputs):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_pools[0].capabilities = MagicMock(return_value=Ok(MagicMock(name='{}.capabilities<mock>'.format(mock_pools[0].poolname))))
    mock_pools[1].capabilities = MagicMock(return_value=Error(MagicMock(name='failure<mock>')))
    mock_pools[2].capabilities = MagicMock(return_value=Ok(MagicMock(name='{}.capabilities<mock>'.format(mock_pools[2].poolname))))

    r = tft.artemis.routing_policies.collect_pool_capabilities(mock_pools)

    assert r.is_error

    failure = r.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.caused_by == mock_pools[1].capabilities.return_value.unwrap_error()


def test_run_routing_policies(mock_inputs, mock_policies):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger,
        mock_session,
        mock_guest_request,
        mock_pools,
        mock_policies
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == [mock_pools[0]]

    mock_policies[0].assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    mock_policies[1].assert_called_once_with(mock_logger, mock_session, [mock_pools[0], mock_pools[1]], mock_guest_request)


def test_create_preferrence_filter_by_driver_class_no_trigger(mock_inputs):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    policy = tft.artemis.routing_policies.create_preferrence_filter_by_driver_class(
        'dummy-custom-policy',
        dict
    )

    assert policy.policy_name == 'dummy-custom-policy'

    mock_pools = [list(), list(), list()]

    r_ruling = policy(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == mock_pools


def test_create_preferrence_filter_by_driver_class(mock_inputs):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    policy = tft.artemis.routing_policies.create_preferrence_filter_by_driver_class(
        'dummy-custom-policy',
        list
    )

    assert policy.policy_name == 'dummy-custom-policy'

    mock_pools = [list(), list(), dict(), list()]

    r_ruling = policy(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is False
    assert ruling.allowed_pools == [mock_pools[0], mock_pools[1], mock_pools[3]]


def test_run_routing_policies_cancel(mock_inputs, mock_policies):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_policies[0].return_value = Ok(tft.artemis.routing_policies.PolicyRuling(cancel=True))

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger,
        mock_session,
        mock_guest_request,
        mock_pools,
        mock_policies
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert ruling.cancel is True

    mock_policies[0].assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    mock_policies[1].assert_not_called()


def test_run_routing_policies_error(mock_inputs, mock_policies):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_failure = MagicMock(name='failure<mock>')

    mock_policies[0].return_value = Error(mock_failure)

    r_ruling = tft.artemis.routing_policies.run_routing_policies(
        mock_logger,
        mock_session,
        mock_guest_request,
        mock_pools,
        mock_policies
    )

    assert r_ruling.is_error

    failure = r_ruling.unwrap_error()

    assert isinstance(failure, tft.artemis.Failure)
    assert failure.message == 'failed to route guest request'
    assert failure.caused_by is mock_failure

    mock_policies[0].assert_called_once_with(mock_logger, mock_session, mock_pools, mock_guest_request)
    mock_policies[1].assert_not_called()


def do_test_policy_match_pool_name(mock_inputs, pool_name, expected_pools):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    mock_guest_request.environment = tft.artemis.environment.Environment(
        hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
        os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
        pool=pool_name
    ).serialize_to_str()

    r_ruling = tft.artemis.routing_policies.policy_match_pool_name(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if pool_name == 'dummy-pool':
        assert ruling.allowed_pools == [mock_pools[0]]

    else:
        assert ruling.allowed_pools == (mock_pools if expected_pools is None else expected_pools)


def test_policy_match_pool_name(mock_inputs):
    do_test_policy_match_pool_name(mock_inputs, 'dummy-pool', None)


def test_policy_match_pool_name_no_match(mock_inputs):
    do_test_policy_match_pool_name(mock_inputs, 'pool-that-does-not-exist', [])


def test_policy_match_pool_name_no_trigger(mock_inputs):
    do_test_policy_match_pool_name(mock_inputs, None, None)


def do_test_policy_supports_architecture(mock_inputs, provide_arch):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    for mock_pool in mock_pools:
        mock_pool.capabilities = lambda: Ok(tft.artemis.drivers.PoolCapabilities(supported_architectures=['foo', 'bar']))

    if provide_arch:
        mock_pools[1].capabilities = lambda: Ok(tft.artemis.drivers.PoolCapabilities(supported_architectures=['foo', 'bar', 'x86_64']))

    mock_guest_request.environment = tft.artemis.environment.Environment(
        hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
        os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
        snapshots=False
    ).serialize_to_str()

    r_ruling = tft.artemis.routing_policies.policy_supports_architecture(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if provide_arch:
        assert ruling.allowed_pools == [mock_pools[1]]

    elif not provide_arch:
        assert ruling.allowed_pools == []

    else:
        assert False, 'unreachable'


def test_policy_supports_architecture(mock_inputs):
    do_test_policy_supports_architecture(mock_inputs, True)


def test_policy_supports_architecture_no_match(mock_inputs):
    do_test_policy_supports_architecture(mock_inputs, False)


def do_test_policy_supports_snapshots(mock_inputs, require_snapshots, provide_snapshots):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    for mock_pool in mock_pools:
        mock_pool.capabilities = lambda: Ok(tft.artemis.drivers.PoolCapabilities(supports_snapshots=False))

    if provide_snapshots:
        mock_pools[0].capabilities = lambda: Ok(tft.artemis.drivers.PoolCapabilities(supports_snapshots=True))

    mock_guest_request.environment = json.dumps(
        tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            snapshots=require_snapshots
        ).serialize_to_json()
    )

    r_ruling = tft.artemis.routing_policies.policy_supports_snapshots(mock_logger, mock_session, mock_pools, mock_guest_request)

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if require_snapshots and provide_snapshots:
        assert ruling.allowed_pools == [mock_pools[0]]

    elif require_snapshots and not provide_snapshots:
        assert ruling.allowed_pools == []

    elif not require_snapshots:
        assert ruling.allowed_pools == mock_pools

    else:
        assert False, 'unreachable'


def test_policy_supports_snapshots(mock_inputs):
    do_test_policy_supports_snapshots(mock_inputs, True, True)


def test_policy_supports_snapshots_no_match(mock_inputs):
    do_test_policy_supports_snapshots(mock_inputs, True, False)


def test_policy_supports_snapshots_no_trigger(mock_inputs):
    do_test_policy_supports_snapshots(mock_inputs, False, True)
    do_test_policy_supports_snapshots(mock_inputs, False, False)


def do_test_policy_least_crowded(monkeypatch, mock_inputs, pool_count=None, one_crowded=True):
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

    monkeypatch.setattr(tft.artemis.routing_policies, 'collect_pool_metrics', MagicMock(
        name='collect_pool_metrics<mock>',
        return_value=Ok([
            (_pool, _metrics) for _pool, _metrics in zip(mock_pools, mock_metrics)
        ])
    ))

    r_ruling = tft.artemis.routing_policies.policy_least_crowded(
        mock_logger,
        mock_session,
        mock_pools,
        mock_guest_request
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


def test_policy_least_crowded(monkeypatch, mock_inputs):
    do_test_policy_least_crowded(monkeypatch, mock_inputs)


def test_policy_least_crowded_one_pool(monkeypatch, mock_inputs):
    do_test_policy_least_crowded(monkeypatch, mock_inputs, pool_count=0)
    do_test_policy_least_crowded(monkeypatch, mock_inputs, pool_count=1)


def test_policy_least_crowded_one_pool_all_worthy(monkeypatch, mock_inputs):
    do_test_policy_least_crowded(monkeypatch, mock_inputs, one_crowded=False)


def do_test_policy_timeout_reached(mock_inputs, empty_events=False, age=None):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    if empty_events:
        mock_guest_request.fetch_events = lambda session, eventname: Ok([])

    else:
        event = tft.artemis.db.GuestEvent('created', 'dummy-guest')
        event.updated = datetime.datetime.utcnow() - datetime.timedelta(seconds=age)

        mock_guest_request.fetch_events = lambda session, eventname: Ok([event])

    r_ruling = tft.artemis.routing_policies.policy_timeout_reached(
        mock_logger,
        mock_session,
        mock_pools,
        mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)

    if age == TIMEOUT_REACHED_AGE_TOO_OLD(mock_session):
        assert ruling.cancel is True
        assert ruling.allowed_pools == []

    elif age == TIMEOUT_REACHED_AGE_TOO_YOUNG(mock_session):
        assert ruling.cancel is False
        assert ruling.allowed_pools == mock_pools

    elif empty_events:
        assert ruling.cancel is False
        assert ruling.allowed_pools == mock_pools


def test_policy_timeout_reached(logger, mock_inputs):
    do_test_policy_timeout_reached(
        mock_inputs,
        age=TIMEOUT_REACHED_AGE_TOO_OLD(mock_inputs.session)
    )


def test_policy_timeout_reached_no_trigger(mock_inputs):
    do_test_policy_timeout_reached(
        mock_inputs,
        age=TIMEOUT_REACHED_AGE_TOO_YOUNG(mock_inputs.session)
    )


def test_policy_timeout_reached_no_events(mock_inputs):
    do_test_policy_timeout_reached(
        mock_inputs,
        empty_events=True
    )


def do_policy_one_attempt_forgiving(mock_inputs, empty_events=False, age=None):
    mock_logger, mock_session, mock_pools, mock_guest_request = mock_inputs

    if empty_events:
        mock_guest_request.fetch_events = lambda session, eventname: Ok([])

    else:
        event = tft.artemis.db.GuestEvent('error', 'dummy-guest', failure={'poolname': 'dummy-pool'})
        event.updated = datetime.datetime.utcnow() - datetime.timedelta(seconds=age)

        mock_guest_request.fetch_events = lambda session, eventname: Ok([event])

    r_ruling = tft.artemis.routing_policies.policy_one_attempt_forgiving(
        mock_logger,
        mock_session,
        mock_pools,
        mock_guest_request
    )

    assert r_ruling.is_ok

    ruling = r_ruling.unwrap()

    assert isinstance(ruling, tft.artemis.routing_policies.PolicyRuling)
    assert ruling.cancel is False

    if age == ONE_ATTEMPT_FORGIVING_TOO_OLD:
        assert ruling.allowed_pools == mock_pools

    elif age == ONE_ATTEMPT_FORGIVING_TOO_YOUNG:
        assert ruling.allowed_pools == [mock_pools[1], mock_pools[2]]

    elif empty_events:
        assert ruling.allowed_pools == mock_pools


def test_policy_one_attempt_forgiving(mock_inputs):
    do_policy_one_attempt_forgiving(
        mock_inputs,
        age=ONE_ATTEMPT_FORGIVING_TOO_YOUNG(mock_inputs.session)
    )


def test_policy_one_attempt_forgiving_no_trigger(mock_inputs):
    do_policy_one_attempt_forgiving(
        mock_inputs,
        age=ONE_ATTEMPT_FORGIVING_TOO_OLD(mock_inputs.session)
    )


def test_policy_one_attempt_forgiving_no_events(mock_inputs):
    do_policy_one_attempt_forgiving(
        mock_inputs,
        empty_events=True
    )


def do_test_policy_enough_resources(monkeypatch, mock_inputs, pool_count=None, one_crowded=True):
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
        mock_pool_metrics.resources.limits.snapshots = 100

        mock_pool_metrics.resources.usage.cores = 50
        mock_pool_metrics.resources.usage.memory = 50
        mock_pool_metrics.resources.usage.diskspace = 50
        mock_pool_metrics.resources.usage.snapshots = 50

        mock_metrics.append(mock_pool_metrics)

    if one_crowded is True:
        mock_metrics[1].resources.usage.cores = 100 * ENOUGH_RESOURCES_EXCESS_MULTIPLIER(mock_session)

    if pool_count is not None:
        mock_pools = mock_pools[:pool_count]
        mock_metrics = mock_metrics[:pool_count]

    monkeypatch.setattr(tft.artemis.routing_policies, 'collect_pool_metrics', MagicMock(
        name='collect_pool_metrics<mock>',
        return_value=Ok([
            (_pool, _metrics) for _pool, _metrics in zip(mock_pools, mock_metrics)
        ])
    ))

    r_ruling = tft.artemis.routing_policies.policy_enough_resources(
        mock_logger,
        mock_session,
        mock_pools,
        mock_guest_request
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


def test_policy_enough_resources(monkeypatch, mock_inputs):
    do_test_policy_enough_resources(monkeypatch, mock_inputs)


def test_policy_enough_resources_one_pool(monkeypatch, mock_inputs):
    do_test_policy_enough_resources(monkeypatch, mock_inputs, pool_count=0)
    do_test_policy_enough_resources(monkeypatch, mock_inputs, pool_count=1)


def test_policy_enough_resources_all_worthy(monkeypatch, mock_inputs):
    do_test_policy_enough_resources(monkeypatch, mock_inputs, one_crowded=False)
