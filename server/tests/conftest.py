import os

import gluetool.log
import gluetool.utils
import pytest
import sqlalchemy.engine.url
import sqlalchemy_utils.functions

import alembic
import alembic.config
import tft.artemis
import tft.artemis.tasks

# The default list of database URLs we test against. Serves as a safe parameter when
# no other URLs were requested via `--against-db-url`.
DEFAULT_DB_URLS = [
    'sqlite://'
]


def pytest_addoption(parser):
    # --against-db-url=sqlite://some.db --against-db-url=postgresql://some:user...
    parser.addoption(
        '--against-db-url',
        action='append',
        # Default list is applied later - should it be applied here, user would have no way to get rid of the defaults.
        default=[],
        help='Database URLs to run tests against. Specify multiple times for more DB dialects.'
    )


# This function is executed automagically by Pytest to support dynamic fixture parametrization (and more).
# We want to parametrize our `db` fixture, but when we apply the `pytest.fixture` decorator, we do not have
# access to command-line option `--against-db-url` and the list of database URLs. The hook below is called
# when collecting tests, and it does have access to configuration, fixtures and allows their parametrization.
#
# So, when we encounter `db_url` fixture - which does not really exists as a function, only as a name - we
# collect its parameters (the list of database URLs, or the default list if none specified), and apply the
# parametrization. The `db` fixture is then given the list of database URL that can be modified on the
# via command-line.
#
# https://docs.pytest.org/en/2.8.7/parametrize.html#pytest-generate-tests
def pytest_generate_tests(metafunc):
    if 'db_url' not in metafunc.fixturenames:
        return

    metafunc.parametrize('db_url', metafunc.config.option.against_db_url or DEFAULT_DB_URLS)


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


@pytest.fixture
def db(logger, db_url):
    parsed_url = sqlalchemy.engine.url.make_url(db_url)

    if parsed_url.get_dialect() != 'sqlalchemy':
        if sqlalchemy_utils.functions.database_exists(db_url):
            sqlalchemy_utils.functions.drop_database(db_url)

        sqlalchemy_utils.functions.create_database(db_url)

    try:
        yield tft.artemis.db._DB(logger, db_url)

    finally:
        if parsed_url.get_dialect() != 'sqlalchemy':
            sqlalchemy_utils.functions.drop_database(db_url)


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


@pytest.fixture(name='_schema_actual')
def fixture_schema_actual(request, logger, db):
    alembic_config = alembic.config.Config()
    alembic_config.set_main_option('script_location', os.path.join(request.config.rootpath, 'alembic'))
    alembic_config.attributes['connectable'] = db.engine

    alembic.command.upgrade(alembic_config, 'head')
