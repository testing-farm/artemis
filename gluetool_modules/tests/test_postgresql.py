import pytest

import psycopg2

import gluetool
import gluetool_modules.database.postgresql
from mock import MagicMock
from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.database.postgresql.PostgreSQL)


@pytest.fixture(name='configured_module')
def fixture_configured_module(module, monkeypatch):
    ci, module = module

    def options_mock(key):
        return {
            "user": "user1",
            "password": "password1",
            "host": "host1",
            "port": "1234",
            "dbname": "dbname1"
        }[key]
    monkeypatch.setattr(module, "option", options_mock)
    return ci, module


def test_loadable(module):
    glue, _ = module

    check_loadable(glue, "gluetool_modules/database/postgresql.py", "PostgreSQL")


def test_shared(module):
    ci, module = module
    assert ci.has_shared("db_cursor")


def test_shared_postgresql(module):
    ci, _ = module
    assert ci.shared("postgresql") is None


def test_shared_postgresql_cursor_fail(module, monkeypatch):
    ci, _ = module

    monkeypatch.setattr(psycopg2, 'connect', MagicMock(side_effect=Exception('Connection failed!')))

    with pytest.raises(gluetool.GlueError, match=r"Could not connect to PostgreSQL server 'None': Connection failed!"):
        ci.shared("db_cursor")


def test_connect(configured_module, monkeypatch):
    _, module = configured_module
    connection_mock = MagicMock()
    connect_mock = MagicMock(return_value=connection_mock)
    monkeypatch.setattr(psycopg2, "connect", connect_mock)
    assert module._connection is None
    module.connection  # Ignore PyUnusedCodeBear
    connect_mock.assert_called_with(host="host1", port="1234", dbname="dbname1", user="user1", password="password1")
    assert module._connection is connection_mock


def test_connect_fail(module, monkeypatch):
    _, module = module
    monkeypatch.setattr(psycopg2, "connect", MagicMock(side_effect=Exception))
    with pytest.raises(gluetool.GlueError, match=r"Could not connect to PostgreSQL server 'None': "):
        module.connection  # Ignore PyUnusedCodeBear


def test_execute(configured_module, monkeypatch, log):
    _, module = configured_module

    mock_cursor = MagicMock(fetchone=MagicMock(return_value=["TEEID 1.2"]))

    monkeypatch.setattr(module, 'db_cursor', MagicMock(return_value=mock_cursor))

    module.execute()
    assert log.match(message="Connected to a PostgreSQL 'host1', version 'TEEID 1.2'")


def test_execute_fail_server_version(configured_module, monkeypatch):
    _, module = configured_module

    cursor_mock = MagicMock(fetchone=MagicMock(return_value=None))
    monkeypatch.setattr(module, 'db_cursor', MagicMock(return_value=cursor_mock))

    with pytest.raises(gluetool.GlueError, match=r"Could not discover server version"):
        module.execute()
