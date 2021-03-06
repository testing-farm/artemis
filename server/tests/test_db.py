import pytest

import sqlalchemy
import sqlalchemy.ext.declarative
from sqlalchemy import Column, Text, Integer

from tft.artemis import safe_db_change
from tft.artemis.db import Query, SafeQuery, upsert, GuestRequest

from mock import MagicMock
from . import assert_failure_log

from mock import MagicMock


Base = sqlalchemy.ext.declarative.declarative_base()


class Counters(Base):
    """
    Dummy table for exercising inserts and updates.
    """

    __tablename__ = 'counters'

    name = Column(Text(), primary_key=True, nullable=False)
    count = Column(Integer, default=0)

    # Used to verify compound keys and multiple values work.
    subname = Column(Text(), default='')
    subcount = Column(Integer, default=0)


@pytest.fixture
def _schema_test_db_Counters(db, session):
    """
    Initialize database: create Counters table.
    """

    Counters.__table__.create(db.engine)

    session.commit()


@pytest.fixture
def _schema_test_db_Counters_1record(session, _schema_test_db_Counters):
    """
    Initialize database: add one record to Counters table.
    """

    session.add(Counters(name='foo', count=0))

    session.commit()


@pytest.fixture
def _schema_test_db_Counters_2records(session, _schema_test_db_Counters):
    """
    Initialize database: add two records to Counters table.
    """

    session.add(Counters(name='foo', count=0))
    session.add(Counters(name='bar', count=0))

    session.commit()


@pytest.fixture(name='mock_session')
def fixture_mock_session(db, monkeypatch):
    mock_session = MagicMock(
        name='Session<mock>',
        transaction=MagicMock(
            name='Transaction<mock>',
            is_active=True
        )
    )

    mock_sessionmaker = MagicMock(
        name='sessionmaker<mock>',
        return_value=mock_session
    )

    monkeypatch.setattr(db, '_sessionmaker', mock_sessionmaker)

    return mock_session


def test_session(db):
    with db.get_session() as session:
        assert hasattr(session, 'commit')


def test_session_autocommit(db, mock_session):
    with db.get_session() as session:
        assert session is mock_session

    mock_session.commit.assert_called_once()
    mock_session.close.assert_called_once()


def test_session_autocommit_active_only(db, mock_session):
    mock_session.transaction.is_active = False

    with db.get_session():
        pass

    mock_session.commit.assert_not_called()
    mock_session.close.assert_called_once()


def test_session_autorollback(db, mock_session):
    mock_exception = ValueError('Exception<mock>')

    try:
        with db.get_session():
            raise mock_exception

    except Exception as exc:
        assert exc is mock_exception

    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def assert_upsert_counter(session, count, subname='', subcount=0):
    records = Query.from_session(session, Counters).all()

    assert len(records) == 1

    record = records[0]

    assert record.name == 'foo'
    assert record.count == count
    assert record.subname == subname
    assert record.subcount == subcount

    return record


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert(session):
    r = upsert(
        session,
        Counters,
        {
            Counters.name: 'foo'
        },
        insert_data={
            Counters.count: 1
        },
        update_data={
            'count': Counters.count + 1
        }
    )

    assert r is None

    session.commit()

    assert_upsert_counter(session, 1)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_compound_key(session):
    r = upsert(
        session,
        Counters,
        {
            Counters.name: 'foo',
            Counters.subname: 'bar'
        },
        insert_data={
            Counters.count: 1
        },
        update_data={
            'count': Counters.count + 1
        }
    )

    assert r is None

    session.commit()

    assert_upsert_counter(session, 1, subname='bar')


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_values(session):
    r = upsert(
        session,
        Counters,
        {
            Counters.name: 'foo'
        },
        insert_data={
            Counters.count: 1,
            Counters.subcount: 1
        },
        update_data={
            'count': Counters.count + 1,
            'subcount': Counters.subcount + 1,
        }
    )

    assert r is None

    session.commit()

    assert_upsert_counter(session, 1, subcount=1)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_upserts(session):
    def do_upsert():
        r = upsert(
            session,
            Counters,
            {
                Counters.name: 'foo'
            },
            insert_data={
                Counters.count: 1
            },
            update_data={
                'count': Counters.count + 1
            }
        )

        assert r is None

    do_upsert()
    do_upsert()
    do_upsert()

    session.commit()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_commits(session):
    def do_upsert():
        r = upsert(
            session,
            Counters,
            {
                Counters.name: 'foo'
            },
            insert_data={
                Counters.count: 1
            },
            update_data={
                'count': Counters.count + 1
            }
        )

        assert r is None

    do_upsert()

    session.commit()

    assert_upsert_counter(session, 1)

    do_upsert()
    do_upsert()

    session.commit()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('_schema_test_db_Counters')
def test_safe_db_change_missed(logger, session):
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).where(Counters.name == 'foo').values(count=1)
    )

    assert r.is_error is False
    assert r.unwrap() is False


@pytest.mark.usefixtures('_schema_test_db_Counters_1record')
def test_safe_db_change(logger, session):
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).where(Counters.name == 'foo').values(count=1)
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = Query.from_session(session, Counters).all()

    assert len(records) == 1
    assert records[0].count == 1


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
def test_safe_db_change_multiple(logger, session):
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).values(count=1),
        expected_records=2
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = Query.from_session(session, Counters).all()

    assert len(records) == 2
    assert all([record.count == 1 for record in records])


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
def test_safe_db_change_single_delete(logger, session):
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.delete(Counters.__table__).where(Counters.name == 'foo')
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = Query.from_session(session, Counters).all()

    assert len(records) == 1

    assert records[0].name == 'bar'
    assert records[0].count == 0


@pytest.mark.usefixtures('_schema_actual')
def test_schema_actual_load(session):
    """
    Metatest of sorts: doesn't test any unit nor scenario, but a fixture. If everything went well, ``_schema_actual``
    was successfull and created the full DB schema in our current DB fixture. We are not interested in testing
    whether the schema is sane or whether it matches models, no, we only want to be sure the schema fixture works,
    and at least something resembling the Artemis DB schema has been created.
    """

    assert Query.from_session(session, GuestRequest).all() == []


@pytest.mark.usefixtures('_schema_test_db_Counters_1record')
def test_safe_query_query(logger, session):
    """
    Test regular workflow: construct query, fetch records.
    """

    r = SafeQuery.from_session(session, Counters).all()

    assert r.is_ok is True

    records = r.unwrap()

    assert len(records) == 1
    assert records[0].name == 'foo'
    assert records[0].count == 0


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
def test_safe_query_query_filter(logger, session):
    """
    Test regular workflow: construct query, apply filter and sorting, fetch records.
    """

    r = SafeQuery.from_session(session, Counters).filter(Counters.name == 'bar').order_by(Counters.name).all()

    assert r.is_ok is True

    records = r.unwrap()

    assert len(records) == 1
    assert records[0].name == 'bar'
    assert records[0].count == 0


def test_safe_query_no_change_on_error(caplog, logger, session, monkeypatch):
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


def test_safe_query_get_error(caplog, logger, session):
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
        exception_label=r'OperationalError: \(sqlite3\.OperationalError\) no such table: counters'
    )
