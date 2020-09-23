import pytest

import tft.artemis.knobs


def test_knob_missing_default():
    with pytest.raises(AssertionError):
        _: tft.artemis.knobs.Knob[str] = tft.artemis.knobs.Knob(
            'foo',
            has_db=False,
            envvar='DUMMY_ENVVAR',
            envvar_cast=str,
        )
