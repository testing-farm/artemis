# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
import threading
from typing import Dict
from unittest.mock import MagicMock

import _pytest.logging
import _pytest.monkeypatch
import gluetool.log
import pytest
import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.orm.session
from sqlalchemy import Column, Integer, Text
from sqlalchemy.schema import PrimaryKeyConstraint

import tft.artemis.db
import tft.artemis.tasks
from tft.artemis.db import DB, Base, GuestEvent, GuestRequest, SafeQuery, TransactionResult, transaction, upsert
from tft.artemis.guest import GuestState

from . import MockPatcher, assert_failure_log

# Base = sqlalchemy.ext.declarative.declarative_base()


class Counters(Base):
    """
    Dummy table for exercising inserts and updates.
    """

    __tablename__ = 'counters'

    name = Column(Text(), nullable=False)
    count = Column(Integer, default=0)

    # Used to verify compound keys and multiple values work.
    subname = Column(Text(), default='')
    subcount = Column(Integer, default=0)

    __table_args__ = (PrimaryKeyConstraint('name'),)


@pytest.fixture
def schema_test_db_counters(db: DB, session: sqlalchemy.orm.session.Session) -> None:
    """
    Initialize database: create Counters table.
    """

    Counters.__table__.create(db.engine)  # type: ignore[attr-defined]

    session.commit()


@pytest.fixture
def schema_test_db_counters_1record(session: sqlalchemy.orm.session.Session, schema_test_db_counters: None) -> None:
    """
    Initialize database: add one record to Counters table.
    """

    session.add(Counters(name='foo', count=0))

    session.commit()


@pytest.fixture
def schema_test_db_counters_2records(session: sqlalchemy.orm.session.Session, schema_test_db_counters: None) -> None:
    """
    Initialize database: add two records to Counters table.
    """

    session.add(Counters(name='foo', count=0))
    session.add(Counters(name='bar', count=0))

    session.commit()


@pytest.fixture(name='mock_session')
def fixture_mock_session(db: DB, mockpatch: MockPatcher) -> MagicMock:
    mock_session = MagicMock(name='Session<mock>', transaction=MagicMock(name='Transaction<mock>', is_active=True))

    mockpatch(db, 'sessionmaker_autocommit').return_value = mock_session
    mockpatch(db, 'sessionmaker_transactional').return_value = mock_session

    return mock_session


def test_session(logger: gluetool.log.ContextAdapter, db: DB) -> None:
    with db.get_session(logger) as session:
        assert hasattr(session, 'commit')


# def test_session_autocommit(logger: gluetool.log.ContextAdapter, db: DB, mock_session: MagicMock) -> None:
#    with db.get_session(logger) as session:
#        assert session is mock_session

#    mock_session.commit.assert_called_once()
#    mock_session.close.assert_called_once()


# def test_session_autocommit_active_only(logger: gluetool.log.ContextAdapter, db: DB, mock_session: MagicMock) -> None:
#    mock_session.transaction.is_active = False

#    with db.get_session(logger):
#        pass

#    mock_session.commit.assert_not_called()
#    mock_session.close.assert_called_once()


# def test_session_autorollback(logger: gluetool.log.ContextAdapter, db: DB, mock_session: MagicMock) -> None:
#    mock_exception = ValueError('Exception<mock>')

#    try:
#        with db.get_session(logger):
#            raise mock_exception

#    except Exception as exc:
#        assert exc is mock_exception

#    mock_session.commit.assert_not_called()
#    mock_session.rollback.assert_called_once()
#    mock_session.close.assert_called_once()


def assert_upsert_counter(
    session: sqlalchemy.orm.session.Session, count: int, subname: str = '', subcount: int = 0
) -> Counters:
    records = SafeQuery.from_session(session, Counters).all().unwrap()

    assert len(records) == 1

    record = records[0]

    assert record.name == 'foo'
    assert record.count == count
    assert record.subname == subname
    assert record.subcount == subcount

    return record


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
        session,
        Counters,
        {Counters.name: 'foo'},
        Counters.__table_args__[0],
        insert_data={Counters.count: 1},
        update_data={'count': Counters.count + 1},
    )

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1)


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert_no_update(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger, session, Counters, {Counters.name: 'foo'}, Counters.__table_args__[0], insert_data={Counters.count: 1}
    )

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1)


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert_compound_key(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
        session,
        Counters,
        {Counters.name: 'foo', Counters.subname: 'bar'},
        Counters.__table_args__[0],
        insert_data={Counters.count: 1},
        update_data={'count': Counters.count + 1},
    )

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1, subname='bar')


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert_multiple_values(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
        session,
        Counters,
        {Counters.name: 'foo'},
        Counters.__table_args__[0],
        insert_data={Counters.count: 1, Counters.subcount: 1},
        update_data={
            'count': Counters.count + 1,
            'subcount': Counters.subcount + 1,
        },
    )

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1, subcount=1)


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert_multiple_upserts(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    def do_upsert() -> None:
        r = upsert(
            logger,
            session,
            Counters,
            {Counters.name: 'foo'},
            Counters.__table_args__[0],
            insert_data={Counters.count: 1},
            update_data={'count': Counters.count + 1},
        )

        assert r.is_ok
        assert r.unwrap() is True

    do_upsert()
    do_upsert()
    do_upsert()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_upsert_multiple_commits(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    def do_upsert() -> None:
        r = upsert(
            logger,
            session,
            Counters,
            {Counters.name: 'foo'},
            Counters.__table_args__[0],
            insert_data={Counters.count: 1},
            update_data={'count': Counters.count + 1},
        )

        assert r.is_ok
        assert r.unwrap() is True

    do_upsert()

    assert_upsert_counter(session, 1)

    do_upsert()
    do_upsert()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('schema_actual')
def test_schema_actual_load(session: sqlalchemy.orm.session.Session) -> None:
    """
    Metatest of sorts: doesn't test any unit nor scenario, but a fixture. If everything went well, ``schema_actual``
    was successfull and created the full DB schema in our current DB fixture. We are not interested in testing
    whether the schema is sane or whether it matches models, no, we only want to be sure the schema fixture works,
    and at least something resembling the Artemis DB schema has been created.
    """

    assert SafeQuery.from_session(session, GuestRequest).all().unwrap() == []


@pytest.mark.usefixtures('schema_test_db_counters_1record')
def test_safe_query_query(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    """
    Test regular workflow: construct query, fetch records.
    """

    r = SafeQuery.from_session(session, Counters).all()

    assert r.is_ok is True

    records = r.unwrap()

    assert len(records) == 1
    assert records[0].name == 'foo'
    assert records[0].count == 0


@pytest.mark.usefixtures('schema_test_db_counters_2records')
def test_safe_query_query_filter(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    """
    Test regular workflow: construct query, apply filter and sorting, fetch records.
    """

    r = SafeQuery.from_session(session, Counters).filter(Counters.name == 'bar').order_by(Counters.name).all()

    assert r.is_ok is True

    records = r.unwrap()

    assert len(records) == 1
    assert records[0].name == 'bar'
    assert records[0].count == 0


def test_safe_query_no_change_on_error(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
) -> None:
    """
    If query already encoutered an error, it should not apply any additional methods nor return any valid records.
    """

    mock_failure = MagicMock(name='Failure<mock>')

    query = SafeQuery.from_session(session, Counters)

    # Inject a failure
    query.failure = mock_failure

    # Now these should do nothing, and return an error.
    r = query.filter(Counters.name == 'bar').all()

    assert r.is_ok is False

    failure = r.unwrap_error()

    assert failure is mock_failure


@pytest.mark.usefixtures('skip_postgresql')
def test_safe_query_get_error(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> None:
    """
    Test handling of genuine SQLAlchemy error: without any schema or records, fetch a record.
    """

    r = SafeQuery.from_session(session, Counters).filter(Counters.name == 'bar').all()

    assert r.is_ok is False

    failure = r.unwrap_error()

    assert 'query' in failure.details
    assert failure.exception is not None

    failure.handle(logger)

    assert_failure_log(
        caplog,
        'failed to retrieve query result',
        exception_label=r'OperationalError: \(sqlite3\.OperationalError\) no such table: counters',
    )


@pytest.mark.usefixtures('skip_sqlite', 'schema_test_db_counters')
def test_transaction_no_transactions(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> None:
    """
    Test whether :py:func:`transaction` behaves correctly when facing non-transactional session.
    """

    query1 = sqlalchemy.insert(Counters).values(name='counter1', count=1)

    query2 = sqlalchemy.insert(Counters).values(name='counter2', count=2)

    with transaction(logger, session) as r:
        session.execute(query1)
        session.execute(query2)

    assert r.complete is True

    records = SafeQuery.from_session(session, Counters).order_by(Counters.name).all().unwrap()

    assert len(records) == 2
    assert records[0].name == 'counter1'
    assert records[0].count == 1
    assert records[1].name == 'counter2'
    assert records[1].count == 2


@pytest.mark.usefixtures('skip_sqlite', '_schema_initialized_actual')
def test_transaction(caplog: _pytest.logging.LogCaptureFixture, logger: gluetool.log.ContextAdapter, db: DB) -> None:
    """
    Test whether :py:func:`transaction` behaves correctly when wrapping non-conflicting queries.
    """

    with db.get_session(logger) as session:
        update = tft.artemis.tasks._guest_state_update_query(
            'dummy-guest', GuestState.PROVISIONING, current_state=GuestState.SHELF_LOOKUP
        ).unwrap()

        insert = sqlalchemy.insert(GuestEvent).values(
            updated=datetime.datetime.utcnow(), guestname='dummy-guest', eventname='dummy-event'
        )

        with transaction(logger, session) as r:
            session.execute(update)
            session.execute(insert)

        assert r.complete is True

        requests = (
            SafeQuery.from_session(session, GuestRequest).filter(GuestRequest.guestname == 'dummy-guest').all().unwrap()
        )

        assert len(requests) == 1
        # TODO: cast shouldn't be needed, sqlalchemy should annouce .state as enum - maybe with more recent stubs?
        assert requests[0].state == GuestState.PROVISIONING

        events = SafeQuery.from_session(session, GuestEvent).all().unwrap()

        assert len(events) == 1
        assert events[0].guestname == 'dummy-guest'
        assert events[0].eventname == 'dummy-event'


@pytest.mark.usefixtures('skip_sqlite', '_schema_initialized_actual')
def test_transaction_conflict(
    caplog: _pytest.logging.LogCaptureFixture,
    logger: gluetool.log.ContextAdapter,
    db: DB,
    session: sqlalchemy.orm.session.Session,
) -> None:
    """
    Test whether :py:func:`transaction` intercepts and reports transaction rollback.
    """

    checkpoint_transactions_started = threading.Barrier(2)
    checkpoint_thread1_done = threading.Barrier(2)

    transaction_results: Dict[int, TransactionResult] = {}

    def thread1() -> None:
        with db.get_session(logger) as session:
            update = tft.artemis.tasks._guest_state_update_query(
                'dummy-guest', GuestState.PROVISIONING, current_state=GuestState.SHELF_LOOKUP
            ).unwrap()

            insert = sqlalchemy.insert(GuestEvent).values(
                updated=datetime.datetime.utcnow(), guestname='dummy-guest', eventname='dummy-event'
            )

            with transaction(logger, session) as r:
                SafeQuery.from_session(session, GuestRequest).all()

                checkpoint_transactions_started.wait()

                session.execute(update)
                session.execute(insert)

                checkpoint_thread1_done.wait()

        transaction_results[threading.get_ident()] = r

    def thread2() -> None:
        with db.get_session(logger) as session:
            update = tft.artemis.tasks._guest_state_update_query(
                'dummy-guest', GuestState.PROMISED, current_state=GuestState.SHELF_LOOKUP
            ).unwrap()

            insert = sqlalchemy.insert(GuestEvent).values(
                updated=datetime.datetime.utcnow(), guestname='dummy-guest', eventname='another-dummy-event'
            )

            with transaction(logger, session) as r:
                SafeQuery.from_session(session, GuestRequest).all()

                checkpoint_transactions_started.wait()
                checkpoint_thread1_done.wait()

                session.execute(update)
                session.execute(insert)

        transaction_results[threading.get_ident()] = r

    t1 = threading.Thread(target=thread1)
    t2 = threading.Thread(target=thread2)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    assert len(transaction_results) == 2

    assert t1.ident is not None
    assert t2.ident is not None

    r1 = transaction_results[t1.ident]
    r2 = transaction_results[t2.ident]

    assert r1.complete is True

    assert r2.complete is False
    assert r2.failure is not None
    assert r2.failed_query is not None
    assert 'UPDATE' in r2.failed_query

    with transaction(logger, session):
        requests = SafeQuery.from_session(session, GuestRequest).all().unwrap()

        assert len(requests) == 1
        # TODO: cast shouldn't be needed, sqlalchemy should annouce .state as enum - maybe with more recent stubs?
        assert requests[0].state == GuestState.PROVISIONING

        events = SafeQuery.from_session(session, GuestEvent).all().unwrap()

        assert len(events) == 1
        assert events[0].guestname == 'dummy-guest'
        assert events[0].eventname == 'dummy-event'
