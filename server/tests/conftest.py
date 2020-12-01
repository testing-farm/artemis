import pytest
import gluetool.log
import gluetool.utils

import tft.artemis
import tft.artemis.tasks


# List of database URLs we test against. The idea is: this list can be modified via pytest options,
# to add URLs of currently running databases. We could spin a PostgreSQL container, add its URL to
# this list, and get our code tested with it "for free".
DB_URLS = [
    'sqlite://'
]


@pytest.fixture
def logger(caplog) -> gluetool.log.ContextAdapter:
    # Set the most detailed log level possible. It may help when debugging test failures, and we don't
    # keep it for the future, it gets thrown away when tests did not fail.
    tft.artemis.KNOB_LOGGING_LEVEL.value = 'DEBUG'

    # It might be better to avoid JSON when logging, but it might be also easier to test
    # logged messages as they would be JSON, and therefore easier to parse and verify.
    #
    # tft.artemis.KNOB_LOGGING_JSON.value = False

    logger = tft.artemis.get_logger()

    assert gluetool.log.Logging.logger is not None

    # Feed our logs into Pytest's fixture, so we can inspect them later.
    gluetool.log.Logging.logger.addHandler(caplog.handler)

    return logger


@pytest.fixture(params=DB_URLS)
def db(logger, request):
    return tft.artemis.db._DB(logger, request.param)


@pytest.fixture
def session(db):
    with db.get_session() as session:
        yield session


@pytest.fixture
def skip_sqlite(session):
    if session.bind.dialect.name == 'sqlite':
        pytest.skip('Not supported with SQLite')


@pytest.fixture
def skip_postgresql(session):
    if session.bind.dialect.name == 'postgresql':
        pytest.skip('Not supported with PostgreSQL')
