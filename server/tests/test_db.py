import _pytest.logging
import _pytest.monkeypatch
import gluetool.log
import pytest
import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.orm.session
from mock import MagicMock
from sqlalchemy import Column, Integer, Text

from tft.artemis.db import DB, Base, GuestRequest, SafeQuery, safe_db_change, upsert

from . import assert_failure_log

# Base = sqlalchemy.ext.declarative.declarative_base()


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
def _schema_test_db_Counters(db: DB, session: sqlalchemy.orm.session.Session) -> None:
    """
    Initialize database: create Counters table.
    """

    Counters.__table__.create(db.engine)

    session.commit()  # type: ignore  # TODO: untyped commit()??


@pytest.fixture
def _schema_test_db_Counters_1record(session: sqlalchemy.orm.session.Session, _schema_test_db_Counters: None) -> None:
    """
    Initialize database: add one record to Counters table.
    """

    session.add(Counters(name='foo', count=0))

    session.commit()  # type: ignore  # TODO: untyped commit()??


@pytest.fixture
def _schema_test_db_Counters_2records(session: sqlalchemy.orm.session.Session, _schema_test_db_Counters: None) -> None:
    """
    Initialize database: add two records to Counters table.
    """

    session.add(Counters(name='foo', count=0))
    session.add(Counters(name='bar', count=0))

    session.commit()  # type: ignore  # TODO: untyped commit()??


@pytest.fixture(name='mock_session')
def fixture_mock_session(db: DB, monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> MagicMock:
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


def test_session(db: DB) -> None:
    with db.get_session() as session:
        assert hasattr(session, 'commit')


def test_session_autocommit(db: DB, mock_session: MagicMock) -> None:
    with db.get_session() as session:
        assert session is mock_session

    mock_session.commit.assert_called_once()
    mock_session.close.assert_called_once()


def test_session_autocommit_active_only(db: DB, mock_session: MagicMock) -> None:
    mock_session.transaction.is_active = False

    with db.get_session():
        pass

    mock_session.commit.assert_not_called()
    mock_session.close.assert_called_once()


def test_session_autorollback(db: DB, mock_session: MagicMock) -> None:
    mock_exception = ValueError('Exception<mock>')

    try:
        with db.get_session():
            raise mock_exception

    except Exception as exc:
        assert exc is mock_exception

    mock_session.commit.assert_not_called()
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def assert_upsert_counter(
    session: sqlalchemy.orm.session.Session,
    count: int,
    subname: str = '',
    subcount: int = 0
) -> Counters:
    records = SafeQuery.from_session(session, Counters).all().unwrap()

    assert len(records) == 1

    record = records[0]

    assert record.name == 'foo'
    assert record.count == count
    assert record.subname == subname
    assert record.subcount == subcount

    return record


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
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

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_no_update(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
        session,
        Counters,
        {
            Counters.name: 'foo'
        },
        insert_data={
            Counters.count: 1
        }
    )

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_compound_key(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
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

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1, subname='bar')


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_values(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = upsert(
        logger,
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

    assert r.is_ok
    assert r.unwrap() is True

    assert_upsert_counter(session, 1, subcount=1)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_upserts(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    def do_upsert() -> None:
        r = upsert(
            logger,
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

        assert r.is_ok
        assert r.unwrap() is True

    do_upsert()
    do_upsert()
    do_upsert()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert_multiple_commits(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    def do_upsert() -> None:
        r = upsert(
            logger,
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

        assert r.is_ok
        assert r.unwrap() is True

    do_upsert()

    assert_upsert_counter(session, 1)

    do_upsert()
    do_upsert()

    assert_upsert_counter(session, 3)


@pytest.mark.usefixtures('_schema_test_db_Counters')
def test_safe_db_change_missed(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).where(Counters.name == 'foo').values(count=1)
    )

    assert r.is_error is False
    assert r.unwrap() is False


@pytest.mark.usefixtures('_schema_test_db_Counters_1record')
def test_safe_db_change(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).where(Counters.name == 'foo').values(count=1)
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = SafeQuery.from_session(session, Counters).all().unwrap()

    assert len(records) == 1
    assert records[0].count == 1


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
def test_safe_db_change_multiple(logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).values(count=1),
        expected_records=2
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = SafeQuery.from_session(session, Counters).all().unwrap()

    assert len(records) == 2
    assert all([record.count == 1 for record in records])


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
def test_safe_db_change_single_delete(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> None:
    r = safe_db_change(
        logger,
        session,
        sqlalchemy.delete(Counters.__table__).where(Counters.name == 'foo')
    )

    assert r.is_error is False
    assert r.unwrap() is True

    records = SafeQuery.from_session(session, Counters).all().unwrap()

    assert len(records) == 1

    assert records[0].name == 'bar'
    assert records[0].count == 0


@pytest.mark.usefixtures('_schema_actual')
def test_schema_actual_load(session: sqlalchemy.orm.session.Session) -> None:
    """
    Metatest of sorts: doesn't test any unit nor scenario, but a fixture. If everything went well, ``_schema_actual``
    was successfull and created the full DB schema in our current DB fixture. We are not interested in testing
    whether the schema is sane or whether it matches models, no, we only want to be sure the schema fixture works,
    and at least something resembling the Artemis DB schema has been created.
    """

    assert SafeQuery.from_session(session, GuestRequest).all().unwrap() == []


@pytest.mark.usefixtures('_schema_test_db_Counters_1record')
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


@pytest.mark.usefixtures('_schema_test_db_Counters_2records')
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
    monkeypatch: _pytest.monkeypatch.MonkeyPatch
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
    session: sqlalchemy.orm.session.Session
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
        exception_label=r'OperationalError: \(sqlite3\.OperationalError\) no such table: counters'
    )
