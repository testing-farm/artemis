from mock import MagicMock

import tft.artemis


def test_context():
    mock_logger_old = MagicMock(name='logger-old<mock>')
    mock_logger_new = MagicMock(name='logger-new<mock>')

    tft.artemis.LOGGER.set(mock_logger_old)

    assert tft.artemis.LOGGER.get() is mock_logger_old

    with tft.artemis.context(logger=mock_logger_new):
        assert tft.artemis.LOGGER.get() is mock_logger_new

    assert tft.artemis.LOGGER.get() is mock_logger_old
