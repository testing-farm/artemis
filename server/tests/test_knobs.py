import pytest

import tft.artemis


def test_knob_missing_sources():
    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            'dummy knob',
            has_db=False
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no source specified - no DB, envvar, actual nor default value.'


def test_knob_missing_default():
    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            'dummy knob',
            has_db=False,
            envvar='DUMMY_ENVVAR',
            cast_from_str=str
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no DB, yet other sources do not provide value! To fix, add an envvar, actual or default value.'


def test_knob_missing_cast():
    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            'dummy knob',
            has_db=True
        )

    assert excinfo.value.args[0] == 'Badly configured knob: has_db requested but no cast_from_str.'

    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            'dummy knob',
            has_db=False,
            envvar='DUMMY_ENVVAR'
        )

    assert excinfo.value.args[0] == 'Badly configured knob: envvar requested but no cast_from_str.'
