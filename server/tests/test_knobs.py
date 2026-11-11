# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool.log
import pytest
import sqlalchemy
import sqlalchemy.orm.session

import tft.artemis
import tft.artemis.context
import tft.artemis.db
import tft.artemis.knobs


def test_knob_missing_sources() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        _: tft.artemis.knobs.Knob[str] = tft.artemis.knobs.Knob('foo', 'dummy knob', has_db=False)

    assert excinfo.value.args[0] == 'Badly configured knob: no source specified - no DB, envvar or default value.'  # noqa: E501


def test_knob_missing_default() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        _: tft.artemis.knobs.Knob[str] = tft.artemis.knobs.Knob(
            'foo', 'dummy knob', has_db=False, envvar='DUMMY_ENVVAR', cast_from_str=str
        )

    assert (
        excinfo.value.args[0]
        == 'Badly configured knob: no DB, yet other sources do not provide value! To fix, add an envvar or default value.'  # noqa: E501
    )


def test_knob_missing_cast() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        tft.artemis.knobs.Knob('foo', 'dummy knob', has_db=True)

    assert excinfo.value.args[0] == 'Badly configured knob: has_db requested but no cast_from_str.'

    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        tft.artemis.knobs.Knob('foo', 'dummy knob', has_db=False, envvar='DUMMY_ENVVAR')

    assert excinfo.value.args[0] == 'Badly configured knob: envvar requested but no cast_from_str.'


@pytest.mark.usefixtures('schema_actual')
def test_knob_db_source_session_from_context(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
) -> None:
    knob: tft.artemis.knobs.Knob[int] = tft.artemis.knobs.Knob(
        'knobs-tests.db-session',
        'dummy knob',
        per_entity=True,
        envvar='ARTEMIS_KNOBS_TESTS_DB_SESSION',
        cast_from_str=int,
        default=1,
    )

    # Without a session in the context, the database source provides no value, and the knob falls back
    # to its default.
    r_value = knob.get_value(entityname='dummy-entity')

    assert r_value.is_ok
    assert r_value.unwrap() == 1

    session.execute(
        sqlalchemy.insert(tft.artemis.db.Knob).values(knobname='knobs-tests.db-session:dummy-entity', value=42)
    )

    session.commit()

    # With a session provided by the context, the database record is used.
    token = tft.artemis.context.SESSION.set(session)

    try:
        r_value = knob.get_value(entityname='dummy-entity')

        assert r_value.is_ok
        assert r_value.unwrap() == 42

    finally:
        tft.artemis.context.SESSION.reset(token)

    # An explicitly provided session is used as well.
    r_value = knob.get_value(session=session, entityname='dummy-entity')

    assert r_value.is_ok
    assert r_value.unwrap() == 42
