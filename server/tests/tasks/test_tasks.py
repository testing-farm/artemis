# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import re
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, call

import _pytest.logging
import _pytest.monkeypatch
import dramatiq
import dramatiq.brokers.stub
import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy.orm.session

import tft.artemis
import tft.artemis.db
import tft.artemis.guest
import tft.artemis.middleware
import tft.artemis.tasks
import tft.artemis.tasks.acquire_guest_request
import tft.artemis.tasks.route_guest_request

from .. import MATCH, SEARCH, MockPatcher, assert_log


@pytest.fixture
def server_config(logger: gluetool.log.ContextAdapter) -> tft.artemis.JSONType:
    return cast(tft.artemis.JSONType, gluetool.utils.load_yaml('artemis-configuration/server.yml', logger=logger))


def test_run_doer(logger: gluetool.log.ContextAdapter, db: tft.artemis.db.DB) -> None:
    def foo(
        _logger: gluetool.log.ContextAdapter, _db: tft.artemis.db.DB, _session: sqlalchemy.orm.session.Session, bar: str
    ) -> tft.artemis.tasks.DoerReturnType:
        assert bar == '79'

        return tft.artemis.tasks.RESCHEDULE

    with db.get_session(logger) as session:
        assert (
            tft.artemis.tasks.run_doer(
                logger, db, session, cast(tft.artemis.tasks.DoerType, foo), 'test_run_doer', '79'
            )
            == tft.artemis.tasks.RESCHEDULE
        )


def test_run_doer_exception(logger: gluetool.log.ContextAdapter, db: tft.artemis.db.DB) -> None:
    def foo(
        _logger: gluetool.log.ContextAdapter, _db: tft.artemis.db.DB, _session: sqlalchemy.orm.session.Session
    ) -> tft.artemis.tasks.DoerReturnType:
        raise Exception('foo')

    with db.get_session(logger) as session, pytest.raises(Exception, match=r'foo'):
        tft.artemis.tasks.run_doer(
            logger, db, session, cast(tft.artemis.tasks.DoerType, foo), 'test_run_doer_exception'
        )


@pytest.fixture(name='actor')
def fixture_actor() -> tft.artemis.tasks.Actor:
    @tft.artemis.tasks.task()
    def dummy_actor(foo: Any) -> None:
        print(foo)

    return dummy_actor


def test_dispatch_task(
    logger: gluetool.log.ContextAdapter, broker: dramatiq.Broker, mockpatch: MockPatcher, actor: tft.artemis.tasks.Actor
) -> None:
    mockpatch(tft.artemis.tasks, 'safe_call').return_value = gluetool.result.Ok(
        dramatiq.Message(queue_name='dummy-queue', actor_name='dummy-actor', args=('79',), kwargs={}, options={})
    )

    r = tft.artemis.tasks.dispatch_task(logger, actor, '79')

    assert r.is_ok

    cast(MagicMock, tft.artemis.tasks.safe_call).assert_called_once_with(  # type: ignore[attr-defined]
        broker.enqueue,
        # TODO: verify it was a message
        unittest.mock.ANY,
        delay=None,
    )


@pytest.mark.usefixtures('broker')
def test_dispatcher_task_exception(
    logger: gluetool.log.ContextAdapter, broker: dramatiq.Broker, mockpatch: MockPatcher, actor: tft.artemis.tasks.Actor
) -> None:
    mockpatch(tft.artemis.tasks, 'safe_call').return_value = gluetool.result.Error(tft.artemis.Failure('dummy failure'))

    r = tft.artemis.tasks.dispatch_task(logger, actor, '79')

    assert r.is_error
    assert isinstance(r.error, tft.artemis.Failure)
    assert r.error.message == 'failed to dispatch task'
    cast(MagicMock, tft.artemis.tasks.safe_call).assert_called_once_with(  # type: ignore[attr-defined]
        broker.enqueue,
        # TODO: verify it was a message
        unittest.mock.ANY,
        delay=None,
    )


TaskCoreArgsType = tuple[tft.artemis.tasks.TaskLogger, MagicMock, MagicMock, tuple[MagicMock, MagicMock]]


@pytest.fixture
def task_core_args(
    logger: gluetool.log.ContextAdapter,
    current_message: dramatiq.MessageProxy,
    broker: dramatiq.broker.Broker,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    mockpatch: MockPatcher,
) -> TaskCoreArgsType:
    task_logger = tft.artemis.tasks.TaskLogger(logger, 'dummy-task')

    run_doer = mockpatch(tft.artemis.tasks, 'run_doer')
    monkeypatch.setattr(tft.artemis.tasks, 'run_doer', run_doer)

    doer = MagicMock(name='mock_doer', actor_name='dummy-actor-name', __name__='mock_doer')
    doer_args = (MagicMock(name='mock_doer_arg1'), MagicMock(name='mock_doer_arg2'))

    monkeypatch.setitem(broker.actors, doer.actor_name, doer)

    return task_logger, run_doer, doer, doer_args


def test_task_core_ok(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    task_core_args: TaskCoreArgsType,
) -> None:
    task_logger, run_doer, doer, doer_args = task_core_args

    tft.artemis.tasks.task_core(doer, task_logger, db=db, session=session, doer_args=doer_args)

    run_doer.assert_has_calls(
        [
            call(task_logger, db, session, doer, doer.actor_name, *doer_args, fallback_actor_name=None),
            call().is_ok.__bool__(),
            call().unwrap(),
        ]
    )

    assert_log(
        caplog,
        message=MATCH(
            r"beginning: \(<MagicMock name='mock_doer_arg1' id='.+'>, <MagicMock name='mock_doer_arg2' id='.+'>\)"
        ),  # noqa: E501
        levelno=logging.INFO,
    )
    assert_log(caplog, message='finished', levelno=logging.INFO)


def test_task_core_failure(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    task_core_args: TaskCoreArgsType,
) -> None:
    task_logger, run_doer, doer, doer_args = task_core_args

    run_doer.return_value = gluetool.result.Error(tft.artemis.Failure('dummy failure'))

    with pytest.raises(Exception, match=r'message processing failed: dummy failure'):
        tft.artemis.tasks.task_core(doer, task_logger, db=db, session=session, doer_args=doer_args)

    assert_log(
        caplog,
        message=MATCH(
            r"beginning: \(<MagicMock name='mock_doer_arg1' id='.+'>, <MagicMock name='mock_doer_arg2' id='.+'>\)"
        ),  # noqa: E501
        levelno=logging.INFO,
    )


def test_task_core_raises(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    task_core_args: TaskCoreArgsType,
) -> None:
    task_logger, run_doer, doer, doer_args = task_core_args

    run_doer.side_effect = ValueError('dummy exception')

    with pytest.raises(Exception, match=r'message processing failed: unhandled doer exception'):
        tft.artemis.tasks.task_core(doer, task_logger, db=db, session=session, doer_args=doer_args)

    assert_log(
        caplog,
        message=MATCH(
            r"beginning: \(<MagicMock name='mock_doer_arg1' id='.+'>, <MagicMock name='mock_doer_arg2' id='.+'>\)"
        ),  # noqa: E501
        levelno=logging.INFO,
    )
    assert_log(
        caplog,
        message=MATCH(r'(?m)failure\n\nmessage: unhandled doer exception\n(?:.*\n)+    ValueError: dummy exception'),
        levelno=logging.ERROR,
    )


def test_task_core_reschedule(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    current_message: dramatiq.MessageProxy,
    task_core_args: TaskCoreArgsType,
) -> None:
    task_logger, run_doer, doer, doer_args = task_core_args

    run_doer.return_value = tft.artemis.tasks.RESCHEDULE

    with pytest.raises(Exception, match=r'message processing requested reschedule'):
        tft.artemis.tasks.task_core(doer, task_logger, db=db, doer_args=doer_args)

    assert_log(
        caplog,
        message=MATCH(
            r"beginning: \(<MagicMock name='mock_doer_arg1' id='.+'>, <MagicMock name='mock_doer_arg2' id='.+'>\)"
        ),  # noqa: E501
        levelno=logging.INFO,
    )


@pytest.fixture(name='workspace')
def fixture_workspace(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    current_message: dramatiq.MessageProxy,
) -> tft.artemis.tasks.Workspace:
    return tft.artemis.tasks.Workspace(logger, session, 'dummy-guest', db=db)


@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool')
def test_mark_note_poolname(mockpatch: MockPatcher, workspace: tft.artemis.tasks.Workspace) -> None:
    assert workspace.gr

    mockpatch(tft.artemis.middleware, 'set_message_note')

    assert workspace.mark_note_poolname() is workspace

    cast(MagicMock, tft.artemis.middleware.set_message_note).assert_called_once_with(
        tft.artemis.middleware.NOTE_POOLNAME, workspace.gr.poolname
    )

    assert workspace.spice_details['poolname'] == workspace.gr.poolname


def test_pools_matching_name_exclude(workspace: tft.artemis.tasks.Workspace) -> None:
    workspace.pools = cast(
        Any,
        [MagicMock(poolname=name) for name in ('ibmcloud-s390x', 'ibmcloud-x86', 'aws-1', 'azure-fast')],
    )

    # A normal group: only the include pattern applies.
    assert sorted(pool.poolname for pool in workspace.pools_matching_name(re.compile('ibmcloud-.*'))) == [
        'ibmcloud-s390x',
        'ibmcloud-x86',
    ]

    # The catch-all: everything, minus the pools every configured group matches.
    assert sorted(
        pool.poolname
        for pool in workspace.pools_matching_name(re.compile('.*'), [re.compile('ibmcloud-.*'), re.compile('aws-.*')])
    ) == ['azure-fast']


@pytest.mark.usefixtures('broker')
def test_register_pool_dispatcher_actors_no_groups() -> None:
    namespace: dict[str, Any] = {}

    tft.artemis.tasks.register_pool_dispatcher_actors(
        namespace,
        base_actor_name='dummy_dispatcher',
        taskname='dummy-dispatcher',
        doer=cast(Any, MagicMock(name='doer', __name__='doer')),
        groups=[],
        default_schedule='*/5 * * * *',
    )

    # No groups configured preserves the original behavior: a single actor under the bare base name, no catch-all.
    assert sorted(namespace) == ['dummy_dispatcher']


@pytest.mark.usefixtures('broker')
def test_register_pool_dispatcher_actors_groups_add_catchall() -> None:
    namespace: dict[str, Any] = {}

    groups = tft.artemis.tasks.parse_dispatcher_groups('ibmcloud-.*:0/27 * * * *;aws-.*:*/5 * * * *')

    tft.artemis.tasks.register_pool_dispatcher_actors(
        namespace,
        base_actor_name='dummy_dispatcher',
        taskname='dummy-dispatcher',
        doer=cast(Any, MagicMock(name='doer', __name__='doer')),
        groups=groups,
        default_schedule='*/5 * * * *',
    )

    # One indexed actor per configured group, plus an implicit catch-all under `_rest` refreshing uncovered pools.
    assert sorted(namespace) == ['dummy_dispatcher_0', 'dummy_dispatcher_1', 'dummy_dispatcher_rest']


@pytest.mark.usefixtures('schema_actual')
def test_get_knobs_serializes_dispatcher_groups_to_json(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    """
    Listing knobs over the API must yield a JSON-serializable response even when a pool-refresh dispatcher-groups
    knob is configured.

    Such a knob holds its value as the parsed, rich form ``list[tuple[re.Pattern, periodiq.CronSpec]]`` (see
    :py:func:`tft.artemis.tasks.parse_dispatcher_groups`). Neither ``re.Pattern`` nor ``periodiq.CronSpec`` is
    JSON-serializable on its own, so without special handling ``get_knobs`` produces a response that Pydantic cannot
    serialize, and ``GET /knobs`` fails with ``PydanticSerializationError``.

    This test drives the real ``get_knobs`` path and asserts the whole response survives JSON serialization. It is
    agnostic to *how* the value is made JSON-safe - it only pins the observable behavior.
    """

    from pydantic import TypeAdapter

    from tft.artemis.api.models import KnobResponse
    from tft.artemis.api.routers import KnobManager
    from tft.artemis.tasks.refresh_pool_flavor_info_dispatcher import KNOB_REFRESH_POOL_FLAVOR_INFO_GROUPS

    # Pretend the knob was configured (via envvar or DB) with a non-empty set of groups, so its value is the parsed,
    # rich form rather than the empty default - this is what triggers the serialization problem.
    configured = tft.artemis.tasks.parse_dispatcher_groups('ibmcloud-.*:0/27 * * * *;aws-.*:*/5 * * * *')
    assert configured  # sanity: the knob value is actually non-empty
    monkeypatch.setattr(KNOB_REFRESH_POOL_FLAVOR_INFO_GROUPS, 'static_value', configured)

    responses = KnobManager(db).get_knobs(logger)

    # Mirror what the API does with the handler's return value: serialize it to JSON. Must not raise.
    TypeAdapter(list[KnobResponse]).dump_json(responses)


@pytest.mark.usefixtures('broker')
@pytest.mark.parametrize(
    ('groups_spec', 'actor_names'),
    [
        # No groups: a single default actor under the bare base name.
        (None, ['dummy_refresh_dispatcher']),
        # Groups: one indexed actor per group, plus the implicit catch-all.
        (
            'aws-.*:*/5 * * * *;ibmcloud-.*:0/27 * * * *',
            [
                'dummy_refresh_dispatcher_0',
                'dummy_refresh_dispatcher_1',
                'dummy_refresh_dispatcher_rest',
            ],
        ),
    ],
    ids=['no-groups', 'groups'],
)
def test_dispatcher_actor_taskcall_from_scheduled_message(
    broker: dramatiq.broker.Broker,
    groups_spec: Any,
    actor_names: list[str],
) -> None:
    # The generated dispatcher actors bind their per-group values as default arguments of `_entry`, so
    # `inspect.signature(actor.fn)` counts those parameters. periodiq, however, schedules these actors with no
    # arguments (`actor.send_with_options(scheduled_at=...)`), so the emitted message carries an empty `args`.
    # `TaskCall` is built from that message in `task_core` and in the metrics/worker-traffic middleware, so it
    # must construct successfully from an argument-less scheduled message - otherwise every dispatcher run raises
    # before reaching the doer.
    namespace: dict[str, Any] = {}

    groups = tft.artemis.tasks.parse_dispatcher_groups(groups_spec) if groups_spec is not None else []

    tft.artemis.tasks.register_pool_dispatcher_actors(
        namespace,
        base_actor_name='dummy_refresh_dispatcher',
        taskname='dummy-refresh-dispatcher',
        doer=cast(Any, MagicMock(name='doer', __name__='doer')),
        groups=groups,
        default_schedule='*/5 * * * *',
    )

    assert sorted(namespace) == sorted(actor_names)

    for actor_name in actor_names:
        actor = namespace[actor_name]

        # Exactly the message periodiq emits for a scheduled actor: the actor name, no arguments.
        message: dramatiq.Message[None] = dramatiq.Message(
            queue_name=actor.queue_name,
            actor_name=actor.actor_name,
            args=(),
            kwargs={},
            options={},
        )

        task_call = tft.artemis.tasks.TaskCall.from_message_proxy(broker, dramatiq.MessageProxy(message))

        assert task_call.actor is actor
        assert task_call.args == ()


def test_actor_control_value_fallback(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> None:
    for var in ('ARTEMIS_ACTOR_DUMMY_DISPATCHER_0_QUEUE', 'ARTEMIS_ACTOR_DUMMY_DISPATCHER_QUEUE'):
        monkeypatch.delenv(var, raising=False)

    # The actor's own var wins over the fallback.
    monkeypatch.setenv('ARTEMIS_ACTOR_DUMMY_DISPATCHER_0_QUEUE', 'own')
    monkeypatch.setenv('ARTEMIS_ACTOR_DUMMY_DISPATCHER_QUEUE', 'base')
    assert (
        tft.artemis.tasks.actor_control_value(
            'dummy_dispatcher_0', 'QUEUE', 'def', fallback_actor_name='dummy_dispatcher'
        )
        == 'own'
    )

    # With the actor's own var unset, the base actor name's var applies - existing overrides keep working.
    monkeypatch.delenv('ARTEMIS_ACTOR_DUMMY_DISPATCHER_0_QUEUE')
    assert (
        tft.artemis.tasks.actor_control_value(
            'dummy_dispatcher_0', 'QUEUE', 'def', fallback_actor_name='dummy_dispatcher'
        )
        == 'base'
    )

    # Without a fallback name the base var is ignored; only the actor's own var or the default apply.
    assert tft.artemis.tasks.actor_control_value('dummy_dispatcher_0', 'QUEUE', 'def') == 'def'

    # Neither var set: the default is used.
    monkeypatch.delenv('ARTEMIS_ACTOR_DUMMY_DISPATCHER_QUEUE')
    assert (
        tft.artemis.tasks.actor_control_value(
            'dummy_dispatcher_0', 'QUEUE', 'def', fallback_actor_name='dummy_dispatcher'
        )
        == 'def'
    )


def test_mark_note_poolname_error_noop(mockpatch: MockPatcher, workspace: tft.artemis.tasks.Workspace) -> None:
    workspace.result = tft.artemis.tasks.RESCHEDULE

    mockpatch(tft.artemis.middleware, 'set_message_note')

    assert workspace.mark_note_poolname() is workspace

    cast(MagicMock, tft.artemis.middleware.set_message_note).assert_not_called()


@pytest.mark.skip
@pytest.mark.usefixtures('dummy_guest_request', 'dummy_pool', '_schema_initialized_actual')
def test_update_guest_state_and_request_task(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    transaction: tft.artemis.db.Transaction,
    workspace: tft.artemis.tasks.Workspace,
    caplog: _pytest.logging.LogCaptureFixture,
    mockpatch: MockPatcher,
) -> None:
    assert (
        workspace.update_guest_state_and_request_task(
            transaction,
            tft.artemis.guest.GuestState.SHELF_LOOKUP,
            tft.artemis.guest.GuestState.ROUTING,
            tft.artemis.tasks.route_guest_request.route_guest_request,
            'dummy-guest',
            delay=79,
        )
        is workspace
    )

    assert workspace.result is None

    assert_log(caplog, message=SEARCH(r'state switch: shelf-lookup => routing'), levelno=logging.INFO)
    assert_log(
        caplog,
        message="""requested task #1:
actor: route_guest_request
args:
    guestname: dummy-guest
delay: 79
message:
    id:
    age:
    queue:
    options: {}
task-request:
    id: 1""",
        levelno=logging.INFO,
    )

    with db.get_session(logger) as new_session:
        r_tasks = tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.TaskRequest).all()

        assert r_tasks.is_ok

        tasks = list(r_tasks.unwrap())

        assert len(tasks) == 1

        task = tasks[0]

        assert task.id == 1
        assert task.taskname == 'route_guest_request'
        assert task.arguments == ['dummy-guest']
        assert task.delay == 79

        r_guests = tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.GuestRequest).all()

        assert r_guests.is_ok

        guests = list(r_guests.unwrap())

        assert len(guests) == 3

        guest = guests[0]

        assert guest.state == tft.artemis.guest.GuestState.ROUTING


@pytest.mark.skip
@pytest.mark.usefixtures('_schema_initialized_actual')
def test_update_guest_state_and_request_task_no_such_guest(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    transaction: tft.artemis.db.Transaction,
    workspace: tft.artemis.tasks.Workspace,
    caplog: _pytest.logging.LogCaptureFixture,
    mockpatch: MockPatcher,
) -> None:
    workspace.guestname = 'not-so-dummy-guest'

    assert (
        workspace.update_guest_state_and_request_task(
            transaction,
            tft.artemis.guest.GuestState.ROUTING,
            tft.artemis.guest.GuestState.PROVISIONING,
            tft.artemis.tasks.acquire_guest_request.acquire_guest_request,
            'not-so-dummy-guest',
            poolname='dummy-pool',
            delay=79,
            set_values={'poolname': 'dummy-pool'},
        )
        is workspace
    )

    assert workspace.result is not None
    assert workspace.result.is_error

    failure = workspace.result.unwrap_error()

    assert failure.message == 'failed to switch guest state'
    assert failure.details['current_state'] == 'routing'
    assert failure.details['new_state'] == 'provisioning'
    assert failure.details['task_name'] == 'acquire_guest_request'
    assert failure.details['task_args'] == ('not-so-dummy-guest', 'dummy-pool')
    assert failure.details['guestname'] == 'not-so-dummy-guest'
    assert failure.recoverable is True

    assert failure.caused_by is not None

    assert failure.caused_by.message == 'unexpected number of affected rows'
    assert failure.caused_by.details['affected_rows'] == 0
    assert failure.caused_by.details['expected_affected_rows'] == 1
    assert failure.caused_by.details['statement'].startswith('UPDATE')

    assert_log(caplog, message=SEARCH(r'state switch: routing => provisioning'), levelno=logging.INFO)

    with db.get_session(logger) as new_session:
        r_tasks = tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.TaskRequest).all()

        assert r_tasks.is_ok

        tasks = list(r_tasks.unwrap())

        assert not tasks

        r_guests = tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.GuestRequest).all()

        assert r_guests.is_ok

        guests = list(r_guests.unwrap())

        assert len(guests) == 3

        guest = guests[0]

        assert guest.poolname is None
        assert guest.state == tft.artemis.guest.GuestState.SHELF_LOOKUP


@pytest.mark.usefixtures('skip_sqlite', '_schema_initialized_actual')
def test_fail_on_tainted_transaction(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    workspace: tft.artemis.tasks.Workspace,
) -> None:
    """
    Test whether the error event survives the rollback of the transaction it would have been written to.
    """

    with tft.artemis.db.Transaction.go(logger, session) as transaction:
        # Taint the transaction, just like a failing DML statement would.
        transaction._handle_failure(tft.artemis.Failure('dummy DB failure'))

        workspace._fail(transaction, tft.artemis.Failure('dummy failure'), 'dummy label')

        # The event cannot be written now - the transaction would refuse the statement, and even if it did
        # not, the following rollback would drop the event.
        assert len(transaction.on_resolve_callbacks) == 1

    assert transaction.complete is False

    with db.get_session(logger) as new_session:
        events = list(
            tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.GuestEvent)
            .filter(tft.artemis.db.GuestEvent.eventname == 'error')
            .all()
            .unwrap()
        )

        assert len(events) == 1
        assert events[0].guestname == 'dummy-guest'
        assert events[0].details['error'] == 'dummy label'
        assert events[0].details['failure']['message'] == 'dummy failure'


@pytest.mark.usefixtures('skip_sqlite', '_schema_initialized_actual')
def test_fail_on_healthy_transaction(
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    workspace: tft.artemis.tasks.Workspace,
) -> None:
    """
    Test whether a healthy transaction still carries the error event itself, without the detour.
    """

    with tft.artemis.db.Transaction.go(logger, session) as transaction:
        workspace._fail(transaction, tft.artemis.Failure('dummy failure'), 'dummy label')

        assert transaction.on_resolve_callbacks == []

    assert transaction.complete is True

    with db.get_session(logger) as new_session:
        events = list(
            tft.artemis.db.SafeQuery.from_session(new_session, tft.artemis.db.GuestEvent)
            .filter(tft.artemis.db.GuestEvent.eventname == 'error')
            .all()
            .unwrap()
        )

        assert len(events) == 1
        assert events[0].guestname == 'dummy-guest'
        assert events[0].details['error'] == 'dummy label'
