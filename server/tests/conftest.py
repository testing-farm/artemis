# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import contextvars
import logging
import os
from typing import Any, Callable, Generator, Optional, cast
from unittest.mock import MagicMock

import _pytest.config.argparsing
import _pytest.fixtures
import _pytest.logging
import _pytest.monkeypatch
import _pytest.python
import dramatiq
import gluetool.log
import gluetool.utils
import py.path
import pytest
import redis
import redislite
import sqlalchemy.engine.interfaces
import sqlalchemy.engine.url
import sqlalchemy_utils.functions

import alembic
import alembic.config
import tft.artemis
import tft.artemis.context
import tft.artemis.knobs
import tft.artemis.tasks

from . import MockPatcher

# The default list of database URLs we test against. Serves as a safe parameter when
# no other URLs were requested via `--against-db-url`.
DEFAULT_DB_URLS = [
    'sqlite://'
]


def pytest_addoption(parser: _pytest.config.argparsing.Parser) -> None:
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
def pytest_generate_tests(metafunc: _pytest.python.Metafunc) -> None:
    if 'db_url' not in metafunc.fixturenames:
        return

    metafunc.parametrize('db_url', metafunc.config.option.against_db_url or DEFAULT_DB_URLS)


@pytest.fixture
def mockpatch(monkeypatch: _pytest.monkeypatch.MonkeyPatch) -> MockPatcher:
    """
    Returns a helper that patches given object with a :py:class:`MagicMock` instance.

    This instance is then returned to user.

    The following code:

    .. code-block:: python

       mock_baz = MagicMock(return_value=79)
       monkeypatch.setattr(foo.bar, 'baz', mock_baz)

    can be rewritten to use ``mockpatch``:

    .. code-block:: python

       # Patch foo.bar.baz with a mock object, and assign it a return value.
       mockpatch(foo.bar, 'baz').return_value = 79

    It becomes very useful once test does not need to actually label the mock instance with a local variable,
    or when mock's tweaks are as trivial as ``return_value`` changes.
    """

    def _mockpatch(
        obj: Any,
        member_name: str,
        obj_name: Optional[str] = None
    ) -> MagicMock:
        mock = MagicMock(name=f'{member_name}<M>' if obj_name is None else f'{obj_name}.{member_name}<M>')

        monkeypatch.setattr(obj, member_name, mock)

        return mock

    return _mockpatch


@pytest.fixture
def logger(caplog: _pytest.logging.LogCaptureFixture) -> gluetool.log.ContextAdapter:
    # Set the most detailed log level possible. It may help when debugging test failures, and we don't
    # keep it for the future, it gets thrown away when tests did not fail.
    tft.artemis.knobs.KNOB_LOGGING_LEVEL.value = logging.DEBUG

    # When testing logging, we can easily inspect captured log records. Non-JSON log *output* is better
    # for humans when investigating test suite output and failed tests.
    tft.artemis.knobs.KNOB_LOGGING_JSON.value = False

    logger = tft.artemis.get_logger()

    assert gluetool.log.Logging.logger is not None

    # Feed our logs into Pytest's fixture, so we can inspect them later.
    gluetool.log.Logging.logger.addHandler(caplog.handler)

    return logger


@pytest.fixture
def db(logger: gluetool.log.ContextAdapter, db_url: str) -> Generator[tft.artemis.db.DB, None, None]:
    parsed_url = sqlalchemy.engine.url.make_url(db_url)

    dialect_name = cast(
        Callable[[], sqlalchemy.engine.interfaces.Dialect],
        parsed_url.get_dialect
    )().name

    if dialect_name != 'sqlalchemy':
        if sqlalchemy_utils.functions.database_exists(db_url):
            sqlalchemy_utils.functions.drop_database(db_url)

        sqlalchemy_utils.functions.create_database(db_url)

    try:
        tft.artemis.db.DB.instance = None
        tft.artemis.tasks._ROOT_DB = None

        yield tft.artemis.db.DB(logger, db_url)

    finally:
        if dialect_name != 'sqlalchemy':
            sqlalchemy_utils.functions.drop_database(db_url)


@pytest.fixture
def session(db: tft.artemis.db.DB) -> Generator[sqlalchemy.orm.session.Session, None, None]:
    with db.get_session() as session:
        yield session


@pytest.fixture
def skip_sqlite(session: sqlalchemy.orm.session.Session) -> None:
    if session.bind.dialect.name == 'sqlite':
        pytest.skip('Not supported with SQLite')


@pytest.fixture
def skip_postgresql(session: sqlalchemy.orm.session.Session) -> None:
    if session.bind.dialect.name == 'postgresql':
        pytest.skip('Not supported with PostgreSQL')


@pytest.fixture(name='_schema_actual')
def fixture_schema_actual(
    request: _pytest.fixtures.FixtureRequest,
    logger: gluetool.log.ContextAdapter,
    db: tft.artemis.db.DB
) -> None:
    alembic_config = alembic.config.Config()
    alembic_config.set_main_option('script_location', os.path.join(request.config.rootpath, 'alembic'))
    alembic_config.attributes['connectable'] = db.engine

    alembic.command.upgrade(alembic_config, 'head')


@pytest.fixture(name='_schema_initialized_actual')
def fixture_schema_initialized_actual(
    session: sqlalchemy.orm.session.Session,
    # TODO: cannot use `usefixtures` for a fixture - find a pytest issue where this is tracked
    _schema_actual: Any
) -> None:
    import tft.artemis.environment

    session.execute(sqlalchemy.insert(tft.artemis.db.User.__table__).values(username='dummy-user', role='ADMIN'))
    session.execute(sqlalchemy.insert(tft.artemis.db.SSHKey.__table__).values(
        keyname='dummy-ssh-key',
        enabled=True,
        ownername='dummy-user',
        file='',
        private='',
        public=''
    ))

    session.execute(tft.artemis.db.GuestRequest.create_query(
        'dummy-guest',
        tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose')
        ),
        'dummy-user',
        'dummy-ssh-key',
        22,
        'root',
        None,
        None,
        False,
        None,
        []
    ))


@pytest.fixture(name='redis')
def fixture_redis(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    tmpdir: py.path.local,
    logger: gluetool.log.ContextAdapter
) -> Generator[None, None, None]:
    redislite.client.logger.setLevel(logging.DEBUG)

    redis_db_file = tmpdir.join('redis.db')

    def get_cache(logger: gluetool.log.ContextAdapter) -> redislite.Redis:
        return redislite.Redis(dbfilename=str(redis_db_file))

    mock_contextvar = contextvars.ContextVar('CACHE', default=get_cache(logger))

    monkeypatch.setattr(tft.artemis, 'get_cache', get_cache)
    monkeypatch.setattr(tft.artemis.context, 'get_cache', get_cache)

    monkeypatch.setattr(
        tft.artemis.context,
        'CACHE',
        mock_contextvar
    )

    monkeypatch.setitem(
        tft.artemis.context.CONTEXT_PROVIDERS,
        ('cache', redis.Redis),
        mock_contextvar
    )

    yield


@pytest.fixture(name='broker')
def fixture_broker(
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    logger: gluetool.log.ContextAdapter,
    # require redis to make sure middleware has access to cache
    redis: redis.Redis,
) -> dramatiq.broker.Broker:
    def get_broker(
        logger: gluetool.log.ContextAdapter,
        application_name: Optional[str] = None
    ) -> dramatiq.broker.Broker:
        middleware = tft.artemis.get_broker_middleware(logger)
        broker = dramatiq.brokers.stub.StubBroker(middleware=middleware)

        dramatiq.set_broker(broker)

        return broker

    monkeypatch.setattr(tft.artemis, 'get_broker', get_broker)

    return tft.artemis.get_broker(logger)


@pytest.fixture
def worker(
    broker: dramatiq.broker.Broker,
    # require redis to make sure worker middleware has access to cache
    redis: redis.Redis,
) -> Generator[dramatiq.Worker, None, None]:
    worker = dramatiq.Worker(broker, worker_timeout=100)
    worker.start()

    yield worker

    worker.stop()


@pytest.fixture(name='current_message')
def fixture_current_message() -> dramatiq.MessageProxy:
    message = dramatiq.Message(
        queue_name='dummy-queue-name',
        actor_name='dummy-actor-name',
        args=tuple(),
        kwargs=dict(),
        options=dict()
    )

    proxy = dramatiq.MessageProxy(message)

    tft.artemis.context.CURRENT_MESSAGE.set(proxy)

    return proxy
