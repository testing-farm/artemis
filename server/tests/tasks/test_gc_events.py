# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
import logging
import threading

import _pytest.logging
import pytest
import sqlalchemy
from gluetool.log import ContextAdapter

import tft.artemis.db
import tft.artemis.guest
import tft.artemis.tasks
from tft.artemis.tasks import KNOB_GC_EVENTS_THRESHOLD, do_gc_events

from .. import MATCH, assert_log

# Reset threshold to 24 hours
KNOB_GC_EVENTS_THRESHOLD.value = 86400


@pytest.fixture
def _schema_empty(session: sqlalchemy.orm.session.Session, _schema_actual: None) -> None:
    session.add(tft.artemis.db.User(
        username='dummy-user',
        role=tft.artemis.db.UserRoles.USER.value,
        admin_token='foo',
        provisioning_token='bar'
    ))

    session.add(tft.artemis.db.Pool(
        poolname='dummy-pool',
        driver='dummy-driver',
        _parameters={}
    ))

    session.add(tft.artemis.db.PriorityGroup(
        name='dummy-priority-group'
    ))

    session.add(tft.artemis.db.SSHKey(
        keyname='dummy-key',
        enabled=True,
        ownername='dummy-user',
        file='',
        private='',
        public=''
    ))

    session.add(tft.artemis.db.GuestRequest(
        guestname='dummy-guest',
        _environment={},
        ownername='dummy-user',
        priorityname='dummy-priority-group',
        poolname='dummy-pool',
        ctime=datetime.datetime.utcnow(),
        # TODO: sqlalchemy uses enum member names, not values, and GuestState values are lowercased,
        # therefore they don't match the enum members in DB. upper() is needed, but the correct
        # fix would be to change values of GuestState members to uppercased versions.
        state=tft.artemis.guest.GuestState.READY.value.upper(),
        address=None,
        ssh_keyname='dummy-key',
        ssh_port=22,
        ssh_username='root',
        pool_data='{}',
        _user_data={}
    ))

    session.commit()


@pytest.fixture
def _schema_with_events(session: sqlalchemy.orm.session.Session, _schema_empty: None) -> None:
    # This one is owned by existing guest, but it's too young
    session.add(
        tft.artemis.db.GuestEvent(
            eventname='dummy-event-young',
            guestname='dummy-guest',
            updated=datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value / 2)
        )
    )

    # This one is owned by existing guest, but it's old enough
    session.add(
        tft.artemis.db.GuestEvent(
            eventname='dummy-event-old',
            guestname='dummy-guest',
            updated=datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value * 2)
        )
    )

    # This one is owned by nonexistent guest, but it's young
    session.add(
        tft.artemis.db.GuestEvent(
            eventname='dummy-event-young',
            guestname='dummy-removed-guest',
            updated=datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value / 2)
        )
    )

    # This one is owned by nonexistent guest, but it's old enough
    session.add(
        tft.artemis.db.GuestEvent(
            eventname='dummy-event-old',
            guestname='dummy-removed-guest',
            updated=datetime.datetime.utcnow() - datetime.timedelta(seconds=KNOB_GC_EVENTS_THRESHOLD.value * 2)
        )
    )

    session.commit()


@pytest.mark.usefixtures('skip_sqlite', '_schema_empty')
def test_gc_events_empty(
    logger: ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    """
    Test the success path.
    """

    r = do_gc_events(
        logger, db, session, threading.Event()
    )

    assert r.is_ok
    assert r is tft.artemis.tasks.SUCCESS

    assert_log(
        caplog,
        levelno=logging.INFO,
        message=MATCH(r'removing events older than \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+')  # noqa: FS003
    )
    assert_log(caplog, levelno=logging.INFO, message=MATCH(r'removed 0 events'))


@pytest.mark.usefixtures('skip_sqlite', '_schema_with_events')
def test_gc_events(
    logger: ContextAdapter,
    db: tft.artemis.db.DB,
    session: sqlalchemy.orm.session.Session,
    caplog: _pytest.logging.LogCaptureFixture
) -> None:
    """
    Test the success path.
    """

    r = do_gc_events(
        logger, db, session, threading.Event()
    )

    assert r.is_ok
    assert r is tft.artemis.tasks.SUCCESS

    assert_log(
        caplog,
        levelno=logging.INFO,
        message=MATCH(r'removing events older than \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+')  # noqa: FS003
    )
    assert_log(caplog, levelno=logging.INFO, message=MATCH(r'removed 1 events'))

    query = sqlalchemy.select([
        tft.artemis.db.GuestEvent.guestname,
        tft.artemis.db.GuestEvent.eventname
    ])

    result = session.execute(query)

    records = result.fetchall()

    assert len(records) == 3

    assert ('dummy-guest', 'dummy-event-young') in records
    assert ('dummy-guest', 'dummy-event-old') in records
    assert ('dummy-removed-guest', 'dummy-event-young') in records
    # (dummy-removed-guest, dummy-event-old) should be gone by now
