import pytest

import tft.artemis
import tft.artemis.knobs


def test_knob_missing_sources() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        _: tft.artemis.knobs.Knob[str] = tft.artemis.knobs.Knob(
            'foo',
            'dummy knob',
            has_db=False
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no source specified - no DB, envvar, actual nor default value.'  # noqa: E501


def test_knob_missing_default() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        _: tft.artemis.knobs.Knob[str] = tft.artemis.knobs.Knob(
            'foo',
            'dummy knob',
            has_db=False,
            envvar='DUMMY_ENVVAR',
            cast_from_str=str
        )

    assert excinfo.value.args[0] == 'Badly configured knob: no DB, yet other sources do not provide value! To fix, add an envvar, actual or default value.'  # noqa: E501


def test_knob_missing_cast() -> None:
    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        tft.artemis.knobs.Knob(
            'foo',
            'dummy knob',
            has_db=True
        )

    assert excinfo.value.args[0] == 'Badly configured knob: has_db requested but no cast_from_str.'

    with pytest.raises(tft.artemis.knobs.KnobError) as excinfo:
        tft.artemis.knobs.Knob(
            'foo',
            'dummy knob',
            has_db=False,
            envvar='DUMMY_ENVVAR'
        )

    assert excinfo.value.args[0] == 'Badly configured knob: envvar requested but no cast_from_str.'
