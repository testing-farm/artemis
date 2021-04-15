# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import psycopg2
from psycopg2.extras import NamedTupleCursor

import gluetool


class PostgreSQL(gluetool.Module):
    """
    This module provides connection to a PostgreSQL database via psycopg2 module:

    http://initd.org/psycopg/

    Connection is compliant with Python Database API Specification v2.0
    Documentation of connection class can be found on:

    http://initd.org/psycopg/docs/connection.html
    """

    name = 'postgresql'
    description = 'Connect to PostgreSQL database'

    options = {
        'user': {
            'help': 'Username (default: %(default)s).',
            'default': None
        },
        'password': {
            'help': 'Password (default: %(default)s).',
            'default': None
        },
        'dbname': {
            'help': 'Database name to connect to.',
        },
        'host': {
            'help': 'Database server host (default: %(default)s).',
            'default': 'localhost',
        },
        'port': {
            'help': 'Database server port number(default: %(default)s).',
            'type': int,
            'default': 5432,
        }
    }

    required_options = ('dbname',)
    shared_functions = ('db_cursor',)

    def __init__(self, *args, **kwargs):
        super(PostgreSQL, self).__init__(*args, **kwargs)

        self._connection = None

    @property
    def connection(self):
        if self._connection is None:
            host, port = self.option('host'), self.option('port')

            self.info('connecting to database {}:{}'.format(host, port))

            try:
                self._connection = psycopg2.connect(host=host, port=port,
                                                    user=self.option('user'), password=self.option('password'),
                                                    dbname=self.option('dbname'))

            except Exception as exc:
                raise gluetool.GlueError("Could not connect to PostgreSQL server '{}': {}".format(host, exc.message))

        return self._connection

    def db_cursor(self, cursor_factory=NamedTupleCursor, **kwargs):
        """
        Return :py:class:`psycopg2.connection.cursor` instance.

        :param cursor_factory: A cursor factory class from :py:mod:`psycopg2.extras`, by default
            :py:class:`psycopg2.extras.NamedTupleCursor` is used.
        :return: A database cursor.
        :rtype: psycopg2.connection.cursor
        :raises gluetool.GlueError: When it is not possible to connect to the database.
        """

        return self.connection.cursor(cursor_factory=cursor_factory)

    def server_version(self):
        cursor = self.db_cursor()

        cursor.execute('SELECT version()')
        row = cursor.fetchone()

        if row is None:
            raise gluetool.GlueError('Could not discover server version')

        return row[0]

    def execute(self):
        version = self.server_version()

        self.info("Connected to a PostgreSQL '{}', version '{}'".format(self.option('host'), version))
