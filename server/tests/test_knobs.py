import pytest

import tft.artemis


def test_knob_missing_sources():
    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            has_db=False
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no source specified - no DB, envvar nor default value.'


def test_knob_missing_default():
    with pytest.raises(tft.artemis.KnobError) as excinfo:
        _: tft.artemis.Knob[str] = tft.artemis.Knob(
            'foo',
            has_db=False,
            envvar='DUMMY_ENVVAR',
            envvar_cast=str
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no DB, yet other sources do not provide value! To fix, add an envvar source, or a default value.'
