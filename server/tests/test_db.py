import pytest

import sqlalchemy
import sqlalchemy.ext.declarative
from sqlalchemy import Column, Text, Integer

from tft.artemis import safe_db_update
from tft.artemis.db import Query, upsert


Base = sqlalchemy.ext.declarative.declarative_base()


class Counters(Base):
    """
    Dummy table for exercising inserts and updates.
    """

    __tablename__ = 'counters'

    name = Column(Text(), primary_key=True, nullable=False)
    count = Column(Integer, default=0)


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


def assert_upsert_counter(session, count):
    records = Query.from_session(session, Counters).all()

    assert len(records) == 1

    record = records[0]

    assert record.name == 'foo'
    assert record.count == count


@pytest.mark.usefixtures('skip_sqlite', '_schema_test_db_Counters')
def test_upsert(session):
    r = upsert(
        session,
        Counters,
        {
            'name': 'foo'
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
def test_upsert_multiple(session):
    def do_upsert():
        r = upsert(
            session,
            Counters,
            {
                'name': 'foo'
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
                'name': 'foo'
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
def test_safe_db_update_missed(logger, session):
    r = safe_db_update(
        logger,
        session,
        sqlalchemy.update(Counters.__table__).where(Counters.name == 'foo').values(count=1)
    )

    assert r.is_error is False
    assert r.unwrap() is False


@pytest.mark.usefixtures('_schema_test_db_Counters_1record')
def test_safe_db_update(logger, session):
    r = safe_db_update(
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
def test_safe_db_update_multiple(logger, session):
    r = safe_db_update(
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
