# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import dataclasses
import datetime
import enum
import functools
import hashlib
import json
import logging
import secrets
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Generic, Iterator, List, Optional, Tuple, Type, \
    TypeVar, Union, cast

import gluetool.glue
import gluetool.log
import psycopg2.errors
import sqlalchemy
import sqlalchemy.event
import sqlalchemy.ext.declarative
import sqlalchemy.sql.expression
from gluetool.result import Error, Ok, Result
from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import column_property, relationship
from sqlalchemy.orm.query import Query as _Query
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

from .guest import GuestState
from .knobs import get_vault_password

if TYPE_CHECKING:
    from mypy_extensions import VarArg

    from . import Failure
    from .environment import Environment
    from .tasks import Actor, ActorArgumentType


# Type variables for use in our generic types
T = TypeVar('T')
S = TypeVar('S')


# "A reasonable default" size of tokens. There's no need to tweak it in runtime, but we don't want
# magic numbers spreading through our code. Note that we do't store the token itself, but rather its
# SHA256 hash.
TOKEN_SIZE = 32
TOKEN_HASH_SIZE = 64


Base = sqlalchemy.ext.declarative.declarative_base()


# "Safe" query - a query-like class, adapted to return Result instances instead of the raw data.
# When it comes to issues encountered when working with the database, SafeQuery should be easier
# to use than query, because it aligns better with our codebase, and exceptions raised by underlying
# SQLAlchemy code are translated into Failures. For example, should the database connection go away,
# one_or_none() will raise an exception when called - SafeQuery.one_or_none() would return Error(Failure)
# instead.

# Types of SafeQuery methods, as used by SafeQuery decorators.
#
# Our decorators change the signature of the decorated function: to make the SafeQuery code simpler,
# its methods return raw SQLAlchemy's Query, or the requested records (e.g. List[SomeTableRecord]).
# Decorators then take care of catching exceptions, and either return the SafeQuery instance (e.g. filter()),
# or wrap the "raw" results with Result instances (e.g. one()). Therefore we need one type for the
# original SafeQuery method, and another type for the method as seen by users of SafeQuery:
#
# `one(self) -> T` becomes `one(self) -> Result[T, Failure]`
#
# All types are generic, and depend on at least one type provided by the SafeQuery itself, `T`. This is
# the type of the records query is supposed to work with (e.g. `SafeQuery[db.Knob]`). Types that apply
# to "get records" methods need one more generic type, `S`, which represents the type of the raw value
# returned by the original method: `T` for `one()`, `List[T]` for `all()`, etc. `S` is then used when
# defining what type the decorated method returns, `Result[S, Failure]`, preserving the original return
# value type.
#
# Note: unfortunately, I wasn't able to cover "update" methods - filter(), limit(), ... - with a single
# decorator and preserve the signature enough to keep type checking. I always found out that methods
# accepting 1 integer parameter (limit/offset) collide with signature of filter() which accepts variable
# number of arguments: `[argument: int]` does not fit under [*args: Any]`. Therefore we have a decorator
# for methods accepting anything, and another decorator for methods accepting an integer. On the plus
# side, type checking works, and mypy does see SafeQuery.limit() as accepting one integer and nothing else.
SafeQueryRawUpdateVAType = Callable[['SafeQuery[T]', 'VarArg(Any)'], _Query]  # type: ignore[valid-type]
SafeQueryUpdateVAType = Callable[['SafeQuery[T]', 'VarArg(Any)'], 'SafeQuery[T]']  # type: ignore[valid-type]

SafeQueryRawUpdateIType = Callable[['SafeQuery[T]', int], _Query]
SafeQueryUpdateIType = Callable[['SafeQuery[T]', int], 'SafeQuery[T]']

SafeQueryRawGetType = Callable[['SafeQuery[T]'], S]
SafeQueryGetType = Callable[['SafeQuery[T]'], Result[S, 'Failure']]


# Decorator for methods with variable number of arguments (VA)...
def chain_update_va(fn: 'SafeQueryRawUpdateVAType[T]') -> 'SafeQueryUpdateVAType[T]':
    @functools.wraps(fn)
    def wrapper(self: 'SafeQuery[T]', *args: Any) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = fn(self, *args)

            except Exception as exc:
                from . import Failure

                self.failure = Failure.from_exc(
                    'failed to update query',
                    exc,
                    query=str(self.query)
                )

        return self

    return wrapper


# ... and a decorator for methods with just a single integer argument (I).
def chain_update_i(fn: 'SafeQueryRawUpdateIType[T]') -> 'SafeQueryUpdateIType[T]':
    @functools.wraps(fn)
    def wrapper(self: 'SafeQuery[T]', arg: int) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = fn(self, arg)

            except Exception as exc:
                from . import Failure

                self.failure = Failure.from_exc(
                    'failed to update query',
                    exc,
                    query=str(self.query)
                )

        return self

    return wrapper


def chain_get(fn: 'SafeQueryRawGetType[T, S]') -> 'SafeQueryGetType[T, S]':
    @functools.wraps(fn)
    def wrapper(self: 'SafeQuery[T]') -> 'Result[S, Failure]':
        if self.failure is None:
            try:
                return Ok(fn(self))

            except Exception as exc:
                from . import Failure

                self.failure = Failure.from_exc(
                    'failed to retrieve query result',
                    exc,
                    query=str(self.query)
                )

        return Error(self.failure)

    return wrapper


class SafeQuery(Generic[T]):
    def __init__(self, query: _Query) -> None:
        self.query = query

        self.failure: Optional[Failure] = None

    @staticmethod
    def from_session(session: sqlalchemy.orm.session.Session, klass: Type[T]) -> 'SafeQuery[T]':
        query_proxy: SafeQuery[T] = SafeQuery(
            cast(
                Callable[[Type[T]], _Query],
                session.query
            )(klass)
        )

        return query_proxy

    @chain_update_va
    def filter(self, *args: Any) -> _Query:
        return cast(
            Callable[..., _Query],
            self.query.filter
        )(*args)

    @chain_update_va
    def order_by(self, *args: Any) -> _Query:
        return cast(
            Callable[..., _Query],
            self.query.order_by
        )(*args)

    @chain_update_i
    def limit(self, limit: int) -> _Query:
        return cast(
            Callable[[Optional[int]], _Query],
            self.query.limit
        )(limit)

    @chain_update_i
    def offset(self, offset: int) -> _Query:
        return cast(
            Callable[[Optional[int]], _Query],
            self.query.offset
        )(offset)

    @chain_get
    def one(self) -> T:
        return cast(
            Callable[[], T],
            self.query.one
        )()

    @chain_get
    def one_or_none(self) -> Optional[T]:
        return cast(
            Callable[[], T],
            self.query.one_or_none
        )()

    @chain_get
    def all(self) -> List[T]:
        return cast(
            Callable[[], List[T]],
            self.query.all
        )()


def stringify_query(session: sqlalchemy.orm.session.Session, query: Any) -> str:
    """
    Return string representation of a given DB query.

    This helper wraps one tricky piece of information: since SQLAlchemy supports many SQL dialects,
    and these dialects can add custom operations to queries, it is necessary to be aware of the dialect
    when compiling the query. "Compilation" is what happens when we ask SQLAlchemy to transform the query
    to string.
    """

    return str(query.compile(dialect=session.bind.dialect))


def execute_db_statement(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    statement: Union[sqlalchemy.insert, sqlalchemy.update, sqlalchemy.delete],
    expected_records: Union[int, Tuple[int, int]] = 1,
) -> Result[Optional[Any], 'Failure']:
    """
    Execute a given SQL query, ``INSERT``, ``UPDATE`` or ``DELETE``.

    .. note::

       This routine should replace :py:func:`safe_db_change` one day: we use ``safe_db_change()`` to perform
       changes that must be synchronized with other actions, like dispatching tasks, which is something
       we are moving to different implementation based on transaction outbox.
    """

    from . import Failure

    def to_failure(exc: Exception) -> Failure:
        if isinstance(exc, sqlalchemy.exc.StatementError):
            return Failure.from_exc(
                'failed to execute DB statement',
                exc,
                statement=exc.statement,
                serialization_failure=False
            )

        return Failure.from_exc(
            'failed to execute DB statement',
            exc,
            serialization_failure=False
        )

    try:
        result = cast(
            sqlalchemy.engine.ResultProxy,
            session.execute(statement)
        )

        if result.is_insert:
            # TODO: INSERT sets this correctly, but what about INSERT + ON CONFLICT? If the row exists,
            # TODO: rowcount is set to 0, but the (optional) UPDATE did happen, so... UPSERT should probably
            # TODO: be ready to accept both 0 and 1. We might need to return more than just true/false for
            # TODO: ON CONFLICT to become auditable.
            affected_rows = result.rowcount

        else:
            affected_rows = result.rowcount

        if isinstance(expected_records, tuple) \
           and not (expected_records[0] <= affected_rows <= expected_records[1]):
            return Error(Failure(
                'unexpected number of affected rows',
                statement=stringify_query(session, statement),
                serialization_failure=False,
                affected_rows=affected_rows,
                expected_affected_rows_min=expected_records[0],
                expected_affected_rows_max=expected_records[1]
            ))

        elif affected_rows != expected_records:
            return Error(Failure(
                'unexpected number of affected rows',
                statement=stringify_query(session, statement),
                serialization_failure=False,
                affected_rows=affected_rows,
                expected_affected_rows=expected_records
            ))

        logger.debug(f'found {affected_rows} matching rows, as expected')

    except sqlalchemy.exc.OperationalError as exc:
        if not isinstance(exc.orig, psycopg2.errors.SerializationFailure) \
           or exc.orig.pgerror.strip() != 'ERROR:  could not serialize access due to concurrent update':

            return Error(to_failure(exc))

        return Error(Failure(
            'failed to execute DB statement',
            query=exc.statement,
            serialization_failure=True
        ))

    except Exception as exc:
        return Error(to_failure(exc))

    else:
        if result.is_insert:
            logger.debug(f'created record with primary key {result.inserted_primary_key}')

            return Ok(result.inserted_primary_key)

        return Ok(None)


def safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    expected_records: Union[int, Tuple[int, int]] = 1,
) -> Result[bool, 'Failure']:
    """
    Execute a given SQL query, ``INSERT``, ``UPDATE`` or ``DELETE``, followed by an explicit commit. Verify
    the expected number of records has been changed (or created).

    :returns: a valid boolean result if queries were executed successfully: ``True`` if changes were made, and
        the number of changed records matched the expectation, ``False`` otherwise. If the queries - including the
        commit - were rejected by lower layers or database, an invalid result is returned, wrapping
        a :py:class:`Failure` instance.
    """

    logger.debug(f'safe db change: {stringify_query(session, query)} - expect {expected_records} records')

    from . import Failure, safe_call

    r = safe_call(session.execute, query)

    if r.is_error:
        return Error(
            Failure.from_failure(
                'failed to execute update query',
                r.unwrap_error(),
                query=stringify_query(session, query)
            )
        )

    query_result = cast(
        sqlalchemy.engine.ResultProxy,
        r.value
    )

    if query_result.is_insert:
        # TODO: INSERT sets this correctly, but what about INSERT + ON CONFLICT? If the row exists,
        # TODO: rowcount is set to 0, but the (optional) UPDATE did happen, so... UPSERT should probably
        # TODO: be ready to accept both 0 and 1. We might need to return more than just true/false for
        # TODO: ON CONFLICT to become auditable.
        affected_rows = query_result.rowcount

    else:
        affected_rows = query_result.rowcount

    if isinstance(expected_records, tuple):
        if not (expected_records[0] <= affected_rows <= expected_records[1]):
            logger.warning(
                f'expected {expected_records[0]} - {expected_records[1]} matching rows, found {affected_rows}'
            )

            return Ok(False)

    elif affected_rows != expected_records:
        logger.warning(f'expected {expected_records} matching rows, found {affected_rows}')

        return Ok(False)

    logger.debug(f'found {affected_rows} matching rows, as expected')

    r = safe_call(session.commit)

    if r.is_error:
        failure = r.unwrap_error()

        if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
            logger.warning(f'expected {expected_records} matching rows, found 0')

            return Ok(False)

        return Error(
            Failure.from_failure(
                'failed to commit query',
                failure,
                query=stringify_query(session, query)
            )
        )

    return Ok(True)


def upsert(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    model: Type[Base],
    primary_keys: Dict[Any, Any],
    *,
    update_data: Optional[Dict[Any, Any]] = None,
    insert_data: Optional[Dict[Any, Any]] = None,
    expected_records: Union[int, Tuple[int, int]] = 1
) -> Result[bool, 'Failure']:
    """
    Provide "INSERT ... ON CONFLICT UPDATE ..." primitive, also known as "UPSERT". Using primary key as a constraint,
    if the given row already exists, an UPDATE clause is applied.

    .. note::

       While the UPSERT statement is generated and sent to the DB, it may remain unapplied, staying in the transaction
       buffer, until a commit is performed. Luckily, consecutive UPSERTs should merge nicely into consistent result.

    This helper is designed to update - for example increment - columns without the necessity of first creating
    the records.

    .. note::

       So far, only PostgreSQL support is available. Other dialects may get support later when needed.

    :param session: SQL session to use.
    :param model: a table to work with, in the form of a ORM model class.
    :param primary_keys: mapping of primary keys and their desired values. These are used:
        * when the record does not exist yet - the caller has to specify what values should these columns have;
        * when the record does exist - the values are used to limit the UPDATE clause to just this particular
        record.
    :param update_data: mapping of columns and update actions applied when the record does exist.
    :param insert_data: mapping of columns and initial values applied when the record is created.
    """

    if session.bind.dialect.name != 'postgresql':
        raise gluetool.glue.GlueError(f'UPSERT is not support for dialect "{session.bind.dialect.name}"')

    from sqlalchemy.dialects.postgresql import insert

    # Prepare condition for `WHERE` statement. Basically, we focus on given primary keys and their values. If we
    # were given multiple columns, we need to join them via `AND` so we could present just one value to `where`
    # parameter of the `on_conflict_update` clause.
    if len(primary_keys) > 1:
        where = sqlalchemy.sql.expression.and_(*[
            column == value
            for column, value in primary_keys.items()
        ])

    else:
        column, value = list(primary_keys.items())[0]

        where = (column == value)

    # `values()` accepts only string as argument names, we cant pass a `Column` instance to it.
    # But columns are easier to pass and type-check, which means we need to convert comments
    # to their names. Also, since `values()` applies when inserting new record, we shouldn't
    # forget the primary key columns neither.
    statement = insert(model).values(
        **{
            **{
                column.name: value
                for column, value in primary_keys.items()
            },
            **{
                column.name: value
                for column, value in (insert_data or {}).items()
            }
        }
    )

    if update_data is None:
        statement = statement.on_conflict_do_nothing(
            constraint=model.__table__.primary_key  # type: ignore[attr-defined]
        )

        # INSERT part of the query is still valid, but there's no ON CONFLICT UPDATE... Unfortunatelly,
        # reporting changed rows for UPSERT has gaps :/ Setting to `1` for now, but it may change in the future.
        expected_records = expected_records if expected_records is not None else 1

    else:
        statement = statement.on_conflict_do_update(
            constraint=model.__table__.primary_key,  # type: ignore[attr-defined]
            set_=update_data,
            where=where
        )

        expected_records = expected_records if expected_records is not None else 1

    return safe_db_change(logger, session, statement, expected_records=expected_records)


@dataclasses.dataclass
class TransactionResult:
    success: bool = False

    failure: Optional['Failure'] = None
    failed_query: Optional[str] = None


@contextlib.contextmanager
def transaction() -> Generator[TransactionResult, None, None]:
    """
    Thin context manager for handling possible transation rollback when executing multiple queries.

    .. note::

       Starting a DB session is **not** the responsibility of this context manager - that is left to caller, because
       such a session can and would be used for queries that do not necessarily need to cause transaction rollback.

    .. code-block:: python

       with DB.get_session(transactional=True) as session:
           with transaction() as result:
               session.execute(sqlalchemy.insert(...))
               session.execute(sqlalchemy.insert(...))
               session.execute(sqlalchemy.insert(...))

        if result.success is not True:
            # handle transaction rollback (or DB error)
            ...
    """

    result = TransactionResult()

    def _save_error(exc: Exception) -> None:
        result.success = False

        if isinstance(exc, sqlalchemy.exc.StatementError):
            result.failure = Failure.from_exc(
                'failed to execute in transaction',
                exc=exc,
                query=exc.statement
            )

        else:
            result.failure = Failure.from_exc(
                'failed to execute in transaction',
                exc=exc
            )

    try:
        yield result

    except sqlalchemy.exc.OperationalError as exc:
        if not isinstance(exc.orig, psycopg2.errors.SerializationFailure) \
           or exc.orig.pgerror.strip() != 'ERROR:  could not serialize access due to concurrent update':
            _save_error(exc)
            return

        result.success = False
        result.failed_query = exc.statement

    except Exception as exc:
        _save_error(exc)

    else:
        result.success = True


def execute_in_transaction(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    *queries: Union[sqlalchemy.insert, sqlalchemy.update]
) -> Result[bool, 'Failure']:
    """
    Execute given SQL queries as if they were part of a single transaction, and detect transaction rollback.

    .. note::

       Since the DB session is an input parameter of this function, it is **not** the responsibility of this
       function to start a transaction-aware DB session - that is left to caller, because such a session
       can and would be used for other queries as well.

    :returns: ``True`` when all queries were successfully executed, ``False`` otherwise.
    """

    try:
        for query in queries:
            session.execute(query)

    except sqlalchemy.exc.OperationalError as exc:
        if not isinstance(exc.orig, psycopg2.errors.SerializationFailure) \
           or exc.orig.pgerror.strip() != 'ERROR:  could not serialize access due to concurrent update':
            raise exc

        return Ok(False)

    except Exception as exc:
        return Error(Failure.from_exc(
            'failed to execute in transaction',
            exc=exc,
            query=stringify_query(session, query)
        ))

    return Ok(True)


class UserRoles(enum.Enum):
    """
    Possible user roles.
    """

    USER = 'USER'
    ADMIN = 'ADMIN'


class GuestLogState(enum.Enum):
    #: Given that Artemis may switch to another pool in the future, until the request is in ``READY`` state,
    #: this particular state is transient.
    UNSUPPORTED = 'unsupported'
    PENDING = 'pending'
    IN_PROGRESS = 'in-progress'
    COMPLETE = 'complete'
    # Note: this state does *not* demand a retry - it is a final state
    ERROR = 'error'


class GuestLogContentType(enum.Enum):
    URL = 'url'
    BLOB = 'blob'


class User(Base):
    __tablename__ = 'users'

    username = Column(String(250), primary_key=True, nullable=False)

    role = Column(Enum(UserRoles), nullable=False, server_default=UserRoles.USER.value)
    """
    User role.
    """

    # Tokens are initialized to a short, human-readable string *on purpose*. We don't store the actual tokens
    # in the database, only their SHA256 hashes, and there's no possible token whose hash would be "undefined".
    # This makes newly created users safe from leaking any tokens by accident, user's tokens must be explicitly
    # initialized by ADMIN-level account first.
    admin_token = Column(String(TOKEN_HASH_SIZE), nullable=False, server_default='undefined')
    """
    Token used to authenticate actions not related to guests and provisioning. Stored as a SHA256
    hash of the actual token.
    """

    provisioning_token = Column(String(TOKEN_HASH_SIZE), nullable=False, server_default='undefined')
    """
    Token used to authenticate actions related to guests and provisioning. Stored as a SHA256
    hash of the actual token.
    """

    sshkeys = relationship('SSHKey', back_populates='owner')
    guests = relationship('GuestRequest', back_populates='owner')

    @staticmethod
    def hash_token(token: str) -> str:
        """
        Returns a SHA256 hash of a given token, encoded as string of hexadecimal digits.
        """

        m = hashlib.sha256()
        m.update(token.encode())

        return m.hexdigest()

    @staticmethod
    def generate_token() -> Tuple[str, str]:
        """
        Generate new token. Returns a tuple of two items: the token and its hash.
        """

        token = secrets.token_hex(TOKEN_SIZE)

        return token, User.hash_token(token)

    @classmethod
    def create(cls, username: str, role: UserRoles) -> 'User':
        return cls(
            username=username,
            role=role.value
        )

    @property
    def is_admin(self) -> bool:
        return self.role == UserRoles.ADMIN  # type: ignore[comparison-overlap]


class SSHKey(Base):
    __tablename__ = 'sshkeys'

    keyname = Column(String(250), primary_key=True, nullable=False)
    enabled = Column(Boolean())
    ownername = Column(String(250), ForeignKey('users.username'), nullable=False)

    # DEPRECATED: but kept for easier schema rollback. Once we're sure things work, we will drop the column.
    file = Column(String(250), nullable=False)

    private = Column(EncryptedType(String, get_vault_password(), AesEngine, 'pkcs5'), nullable=False)
    public = Column(EncryptedType(String, get_vault_password(), AesEngine, 'pkcs5'), nullable=False)

    owner = relationship('User', back_populates='sshkeys')
    guests = relationship('GuestRequest', back_populates='ssh_key')


class PriorityGroup(Base):
    __tablename__ = 'priority_groups'

    name = Column(String(250), primary_key=True, nullable=False)

    guests = relationship('GuestRequest', back_populates='priority_group')


class Pool(Base):
    __tablename__ = 'pools'

    poolname = Column(String(250), primary_key=True, nullable=False)
    driver = Column(String(250), nullable=False)
    _parameters = Column(JSON(), nullable=False)

    @property
    def parameters(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._parameters)

    guests = relationship('GuestRequest', back_populates='pool')


class TaskRequest(Base):
    """
    A request to run a task by dispatcher.

    Dispatching a task immediately, e.g. with :py:func:`tft.artemis.tasks.dispatch_task`, might be easier
    but also prone to condition known as "dual write": when task is a follow-up of a DB change, it's impossible
    to guarantee that either both (the DB change and message dispatch) or none of those are performed, with DB
    or broker transactions only.

    A solution most suitable to us is called "transaction outbox": instead of dispatching a task, a DB record
    is created within the same transaction as the original DB change. These "task requests" are then read by
    another service that transforms them into actual broker messages, removing the DB record after successfull
    dispatch.

    Thanks to this split, we can guarantee a both DB change and the need for a follow-up message are safely stored.

    * https://microservices.io/patterns/data/transactional-outbox.html
    """

    __tablename__ = 'task_requests'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    taskname = Column(Text(), nullable=False)
    arguments = Column(JSON(), nullable=False)
    delay = Column(Integer(), nullable=True)

    @classmethod
    def create_query(
        cls,
        task: 'Actor',
        *args: 'ActorArgumentType',
        delay: Optional[int] = None
    ) -> sqlalchemy.insert:
        """
        """

        return sqlalchemy.insert(cls.__table__).values(
            taskname=task.actor_name,
            arguments=list(args),
            delay=delay
        )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        task: 'Actor',
        *args: 'ActorArgumentType',
        delay: Optional[int] = None
    ) -> Result[int, 'Failure']:
        stmt = cls.create_query(task, *args, delay=delay)

        r = execute_db_statement(logger, session, stmt)

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(cast(Tuple[int], r.unwrap())[0])


class GuestEvent(Base):
    __tablename__ = 'guest_events'

    _id = Column(Integer(), primary_key=True)
    updated = Column(DateTime, default=datetime.datetime.utcnow)
    guestname = Column(String(250), nullable=False, index=True)
    eventname = Column(String(250), nullable=False)

    # Details are stored as JSON blob, in a "hidden" column - when accessing event details, we'd like to cast them to
    # proper type, and there will never ever be an event having a list or an integer as a detail, it will always
    # be a mapping. Therefore `_details` column and `details` property to apply proper cast call.
    _details = Column(JSON(), nullable=False, server_default='{}')

    def __init__(
        self,
        eventname: str,
        guestname: str,
        updated: Optional[datetime.datetime] = None,
        **details: Any
    ) -> None:
        self.eventname = eventname
        self.guestname = guestname
        self.updated = updated or datetime.datetime.utcnow()
        self._details = details

    @property
    def details(self) -> Dict[str, Any]:
        return cast(Dict[str, Any], self._details)

    @classmethod
    def fetch(
        cls,
        session: sqlalchemy.orm.session.Session,
        eventname: Optional[str] = None,
        guestname: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        sort_field: str = 'updated',
        sort_order: str = 'desc',
        since: Optional[str] = None,
        until: Optional[str] = None
    ) -> Result[List['GuestEvent'], 'Failure']:
        query = SafeQuery.from_session(session, GuestEvent)

        if guestname is not None:
            query = query.filter(cls.guestname == guestname)

        if eventname:
            query = query.filter(cls.eventname == eventname)

        if since:
            query = query.filter(cls.updated >= since)

        if until:
            query = query.filter(cls.updated <= until)

        try:
            sort_field_column = getattr(cls, sort_field)
            sort_field_direction = getattr(sort_field_column, sort_order)

        except AttributeError:
            return Error(Failure(
                'cannot sort events',
                sort_field=sort_field,
                sort_order=sort_order
            ))

        # E.g. order_by(GuestEvent.updated.desc())
        query = query.order_by(sort_field_direction())

        if page_size is not None:
            query = query.limit(page_size)

            if page is not None:
                query = query.offset((page - 1) * page_size)

        return query.all()


UserDataType = Dict[str, Optional[str]]


class GuestRequest(Base):
    __tablename__ = 'guest_requests'

    guestname = Column(String(250), primary_key=True, nullable=False)
    _environment = Column(JSON(), nullable=False)
    ownername = Column(String(250), ForeignKey('users.username'), nullable=False)
    priorityname = Column(String(250), ForeignKey('priority_groups.name'), nullable=True)
    poolname = Column(String(250), ForeignKey('pools.poolname'), nullable=True)

    @property
    def environment(self) -> 'Environment':
        # avoid circular imports
        from .environment import Environment

        return Environment.unserialize(cast(Dict[str, Any], self._environment))

    # This is tricky:
    # * we want to keep `nullable=False`, because `ctime` cannot ever be set to `NULL`. That way we're not forced
    #   to use `Optional` in our code when talking about `ctime`.
    # * `nullable=False` requires us to specify a default value.
    # * `server_default` is a prefered way, instead of `default`, because then it's the DB that takes care about
    #   the default values. `server_default=sqlalchemy.sql.func.utcnow()` would be the right choice here.
    # * there might be existing guests in `guest_requests` table, and SQLAlchemy and Alembic must be able to update
    #   them as well as alter the table by adding a column - but SQLite will not accept our `server_default` because
    #   it is not a constant!
    #
    # We could relax our requirements and settle for `nullable=False`, but then we would have to pretend `ctime` can
    # be `None`...
    #
    # It all boils down to what to assign to existing guest requests when adding new column. Apparently, we cannot
    # use a dynamic function call, so we may have to keep `default` around, because:
    #
    # * `default` tells SQLAlchemy what default value to use *on Python level* - this means it is not a DB taking
    #   care of the default value after all.
    # * in Alembic script, we use `server_default` set to a value returned by `datetime.datetime.utcnow()`. This
    #   means the default value of the column on the DB level is not dynamic, but set to whatever date and time when
    #   the script was executed, frozen. It applies to existing guest request, because new ones will never land in
    #   db with unknown `ctime`, it will be always set by SQLAlchemy because we used `default`.
    #
    # This needs more attention in general, guest events and some metrics also have these datetime-ish columns,
    # we should use the same approach. Maybe it's possible to limit the static default to SQLite only.
    ctime = Column(DateTime(), nullable=False, default=datetime.datetime.utcnow)

    state = Column(Enum(GuestState), nullable=False)
    state_mtime = Column(DateTime(), nullable=True)

    mtime: datetime.datetime = column_property(  # type: ignore[assignment]
        sqlalchemy  # type: ignore[attr-defined]
        .select(sqlalchemy.func.max(GuestEvent.updated))
        .where(GuestEvent.guestname == guestname)
        .scalar_subquery()
    )

    address = Column(String(250), nullable=True)

    # SSH info
    ssh_keyname = Column(String(250), ForeignKey('sshkeys.keyname'), nullable=False)
    ssh_port = Column(Integer(), nullable=False)
    ssh_username = Column(String(250), nullable=False)

    # Pool-specific data.
    pool_data = Column(Text(), nullable=False)

    # User specified data
    _user_data = Column(JSON(), nullable=False)

    @property
    def user_data(self) -> UserDataType:
        return cast(UserDataType, self._user_data)

    #: If set, the provisioning will skip preparation steps and assume the guest is reachable as soon as it becomes
    #: active.
    skip_prepare_verify_ssh = Column(Boolean(), nullable=False, server_default='false')

    # Contents of a script to be run when the guest becomes active
    post_install_script = Column(Text(), nullable=True)

    # Console url if it was requested by the user
    console_url = Column(String(250), nullable=True)
    console_url_expires = Column(DateTime(), nullable=True)

    # Log types specifically to be supported as requested by the user (colon-separated string of logtype:contenttype)
    _log_types = Column(JSON(), nullable=True)

    owner = relationship('User', back_populates='guests')
    ssh_key = relationship('SSHKey', back_populates='guests')
    priority_group = relationship('PriorityGroup', back_populates='guests')
    pool = relationship('Pool', back_populates='guests')

    @classmethod
    def create_query(
        cls,
        guestname: str,
        environment: 'Environment',
        ownername: str,
        ssh_keyname: str,
        ssh_port: int,
        ssh_username: str,
        priorityname: Optional[str],
        user_data: Optional[UserDataType],
        skip_prepare_verify_ssh: bool,
        post_install_script: Optional[str],
        log_types: List[Tuple[str, GuestLogContentType]]
    ) -> sqlalchemy.insert:
        return sqlalchemy.insert(cls.__table__).values(
            guestname=guestname,
            _environment=environment.serialize(),
            ownername=ownername,
            ssh_keyname=ssh_keyname,
            ssh_port=ssh_port,
            ssh_username=ssh_username,
            priorityname=priorityname,
            _user_data=user_data,
            skip_prepare_verify_ssh=skip_prepare_verify_ssh,
            post_install_script=post_install_script,
            _log_types=[
                {
                    'logtype': log[0],
                    'contenttype': log[1].value
                }
                for log in log_types
            ],
            state=GuestState.ROUTING,
            state_mtime=datetime.datetime.utcnow(),
            poolname=None,
            pool_data=json.dumps({}),
        )

    @classmethod
    def log_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        eventname: str,
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given event.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guestname: guest request name to attach the event to.
        :param eventname: event name.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        from . import log_dict_yaml

        r = safe_db_change(
            logger,
            session,
            sqlalchemy.insert(GuestEvent.__table__).values(  # type: ignore[attr-defined]
                guestname=guestname,
                eventname=eventname,
                _details=details
            )
        )

        if r.is_error:
            failure = r.unwrap_error()

            failure.details.update({
                'guestname': guestname,
                'eventname': eventname
            })

            log_dict_yaml(logger.warning, 'failed to log event', {
                'eventname': eventname,
                'details': details
            })

            # TODO: this handle() call can be removed once we fix callers of log_guest_event and they start consuming
            # its return value. At this moment, they ignore it, therefore we have to keep reporting the failures on
            # our own.
            failure.handle(
                logger,
                label='failed to store guest event',
                guestname=guestname,
                eventname=eventname
            )

            return Error(failure)

        log_dict_yaml(logger.info, 'logged event', {
            'eventname': eventname,
            'details': details
        })

        return Ok(None)

    def log_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        eventname: str,
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given event.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param eventname: event name.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        return self.__class__.log_event_by_guestname(
            logger,
            session,
            self.guestname,
            eventname,
            **details
        )

    @classmethod
    def log_error_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        message: str,
        failure: 'Failure',
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given error.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guestname: guest request name to attach the event to.
        :param message: error message.
        :param failure: failure representing the error.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        details['failure'] = failure.get_event_details()

        return cls.log_event_by_guestname(
            logger,
            session,
            guestname,
            'error',
            error=message,
            **details
        )

    def log_error_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        message: str,
        failure: 'Failure',
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given error.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param message: error message.
        :param failure: failure representing the error.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        return self.__class__.log_error_event_by_guestname(
            logger,
            session,
            self.guestname,
            message,
            failure,
            **details
        )

    @classmethod
    def log_warning_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        message: str,
        failure: Optional['Failure'] = None,
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given warning.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guestname: guest request name to attach the event to.
        :param message: error message.
        :param failure: failure representing the error.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        if failure is not None:
            details['failure'] = failure.get_event_details()

        return cls.log_event_by_guestname(
            logger,
            session,
            guestname,
            'warning',
            error=message,
            **details
        )

    def log_warning_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        message: str,
        failure: Optional['Failure'] = None,
        **details: Any
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given warning.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param message: error message.
        :param failure: failure representing the error.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        return self.__class__.log_warning_event_by_guestname(
            logger,
            session,
            self.guestname,
            message,
            failure=failure,
            **details
        )

    def fetch_events(
        self,
        session: sqlalchemy.orm.session.Session,
        eventname: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        sort_field: str = 'updated',
        sort_order: str = 'desc',
        since: Optional[str] = None,
        until: Optional[str] = None
    ) -> Result[List['GuestEvent'], 'Failure']:
        return GuestEvent.fetch(
            session,
            guestname=self.guestname,
            eventname=eventname,
            page=page,
            page_size=page_size,
            sort_field=sort_field,
            sort_order=sort_order,
            since=since,
            until=until
        )

    @property
    def log_types(self) -> List[Tuple[str, GuestLogContentType]]:
        if not self._log_types:
            return []
        self._log_types = cast(List[Dict[str, str]], self._log_types)
        return [
            (log_type["logtype"], GuestLogContentType(log_type["contenttype"])) for log_type in self._log_types
        ]

    def requests_guest_log(self, logname: str, contenttype: GuestLogContentType) -> bool:
        return (logname, contenttype) in self.log_types


class GuestLog(Base):
    __tablename__ = 'guest_logs'

    guestname = Column(String(), nullable=False, primary_key=True)
    logname = Column(String(), nullable=False, primary_key=True)
    contenttype = Column(Enum(GuestLogContentType), nullable=False, primary_key=True)

    state = Column(Enum(GuestLogState), nullable=False, default=GuestLogState.PENDING)

    url = Column(String(), nullable=True)
    blob = Column(String(), nullable=True)

    updated = Column(DateTime(), nullable=True)
    expires = Column(DateTime(), nullable=True)

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False

        return self.expires < datetime.datetime.utcnow()


class SnapshotRequest(Base):
    __tablename__ = 'snapshot_requests'

    snapshotname = Column(String(250), primary_key=True, nullable=False)
    guestname = Column(String(250), ForeignKey('guest_requests.guestname'), nullable=False)
    poolname = Column(String(250), ForeignKey('pools.poolname'), nullable=True)

    state = Column(Enum(GuestState), nullable=False)

    start_again = Column(Boolean(), nullable=False)


class GuestTag(Base):
    __tablename__ = 'guest_tags'

    #: Used as a poolname to represent system-wide tags.
    SYSTEM_POOL_ALIAS = '__system__'

    poolname = Column(String(), primary_key=True, nullable=False)
    tag = Column(String(), primary_key=True, nullable=False)
    value = Column(String(), nullable=False)

    @classmethod
    def fetch_system_tags(
        cls,
        session: sqlalchemy.orm.session.Session
    ) -> Result[List['GuestTag'], 'Failure']:
        """
        Load all system-wide guest tags.
        """

        return SafeQuery.from_session(session, cls) \
            .filter(cls.poolname == cls.SYSTEM_POOL_ALIAS) \
            .all()

    @classmethod
    def fetch_pool_tags(
        cls,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> Result[List['GuestTag'], 'Failure']:
        """
        Load all pool-wide guest tags for a given pool.
        """

        return SafeQuery.from_session(session, cls) \
            .filter(cls.poolname == poolname) \
            .all()


class Metrics(Base):
    __tablename__ = 'metrics'

    metric = Column(String(250), primary_key=True, nullable=False)
    count = Column(Integer, default=0)
    updated = Column(DateTime, default=datetime.datetime.utcnow)


class Knob(Base):
    __tablename__ = 'knobs'

    knobname = Column(String(), primary_key=True, nullable=False)
    value = Column(JSON(), nullable=False)


# TODO: shuffle a bit with files to avoid local imports and to set this up conditionaly. It's probably not
# critical, but it would also help a bit with DB class, and it would be really nice to not install the event
# hooks when not asked to log slow queries.
@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'before_cursor_execute')  # type: ignore[no-untyped-call,misc]
def before_cursor_execute(
    conn: sqlalchemy.engine.Connection,
    cursor: Any,
    statement: Any,
    parameters: Any,
    context: Any,
    executemany: Any
) -> None:
    conn.info.setdefault('query_start_time', []).append(time.time())


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'after_cursor_execute')  # type: ignore[no-untyped-call,misc]
def after_cursor_execute(
    conn: sqlalchemy.engine.Connection,
    cursor: Any,
    statement: Any,
    parameters: Any,
    context: Any,
    executemany: Any
) -> None:
    from .knobs import KNOB_LOGGING_DB_SLOW_QUERIES, KNOB_LOGGING_DB_SLOW_QUERY_THRESHOLD

    if KNOB_LOGGING_DB_SLOW_QUERIES.value is not True:
        return

    query_time = time.time() - conn.info['query_start_time'].pop(-1)

    if query_time < KNOB_LOGGING_DB_SLOW_QUERY_THRESHOLD.value:
        return

    from . import Failure
    from .context import LOGGER

    Failure(
        'detected a slow query',
        query=str(statement),
        time=query_time
    ).handle(LOGGER.get())


class DB:
    instance: Optional['DB'] = None
    _lock = threading.RLock()

    #: "Root" engine, with the setup dictated by DB configuration.
    engine: sqlalchemy.engine.Engine

    #: Engine derived from :py:attr:`engine`, configured to use no transactions in an auto-commit fashion.
    engine_autocommit: sqlalchemy.engine.Engine
    #: Session factory on top of auto-commit :py:attr:`engine_autocommit` engine: ``AUTOCOMMIT`` isolation level
    #: is applied to each and every query.
    sessionmaker_autocommit: sessionmaker

    #: Engine derived from :py:attr:`engine`, configured to transactions with ``REPEATABLE READ`` isolation level.
    engine_transactional: sqlalchemy.engine.Engine
    #: Session factory on top of auto-commit :py:attr:`engine_treansactional` engine: every session spawns
    #: a transaction with ``REPEATABLE READ`` isolation level.
    sessionmaker_transactional: sessionmaker

    def _setup_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        url: str,
        application_name: Optional[str] = None
    ) -> None:
        from .knobs import KNOB_DB_POOL_MAX_OVERFLOW, KNOB_DB_POOL_SIZE, KNOB_LOGGING_DB_POOL, KNOB_LOGGING_DB_QUERIES

        self.logger = logger

        logger.info(f'connecting to db {url}')

        if KNOB_LOGGING_DB_QUERIES.value:
            gluetool.log.Logging.configure_logger(logging.getLogger('sqlalchemy.engine'))

        self._echo_pool: Union[str, bool] = False

        if KNOB_LOGGING_DB_POOL.value == 'debug':
            self._echo_pool = 'debug'

        else:
            self._echo_pool = gluetool.utils.normalize_bool_option(KNOB_LOGGING_DB_POOL.value)

        # We want a nice way how to change default for pool size and maximum overflow for PostgreSQL
        if url.startswith('postgresql://'):
            connect_args: Dict[str, str] = {}

            if application_name is not None:
                connect_args['application_name'] = application_name

            gluetool.log.log_dict(logger.info, 'sqlalchemy create_engine parameters', {
                'echo_pool': self._echo_pool,
                'pool_size': KNOB_DB_POOL_SIZE.value,
                'max_overflow': KNOB_DB_POOL_MAX_OVERFLOW.value,
                'application_name': application_name
            })

            self.engine = sqlalchemy.create_engine(
                url,
                echo_pool=self._echo_pool,
                pool_size=KNOB_DB_POOL_SIZE.value,
                max_overflow=KNOB_DB_POOL_MAX_OVERFLOW.value,
                connect_args=connect_args
            )

        # SQLite does not support altering pool size nor max overflow
        else:
            self.engine = sqlalchemy.create_engine(url)

        # TODO: hopefully, with better sqlalchemy stubs, cast() wouldn't be needed anymore
        _engine_execution_options = cast(
            Callable[..., sqlalchemy.engine.Engine],
            self.engine.execution_options
        )

        self.engine_autocommit = _engine_execution_options(isolation_level='AUTOCOMMIT')
        self.sessionmaker_autocommit = sqlalchemy.orm.sessionmaker(bind=self.engine_autocommit)

        self.engine_transactional = _engine_execution_options(isolation_level='REPEATABLE READ')
        self.sessionmaker_transactional = sqlalchemy.orm.sessionmaker(bind=self.engine_transactional)

    def __new__(
        cls,
        logger: gluetool.log.ContextAdapter,
        url: str,
        application_name: Optional[str] = None
    ) -> 'DB':
        with cls._lock:
            if cls.instance is None:
                cls.instance = super().__new__(cls)
                cls.instance._setup_instance(logger, url, application_name=application_name)

        return cls.instance

    @contextmanager
    def get_session(self, transactional: bool = False) -> Iterator[sqlalchemy.orm.session.Session]:
        """
        Create new DB session.

        :param transactional: if set, session will support transactions rather than auto-commit isolation level.
        :returns: new DB session.
        """

        if transactional:
            Session = sqlalchemy.orm.scoped_session(self.sessionmaker_transactional)

        else:
            Session = sqlalchemy.orm.scoped_session(self.sessionmaker_autocommit)

        session = Session()

        if self._echo_pool:
            from .metrics import DBPoolMetrics

            gluetool.log.log_dict(
                self.logger.info,
                'pool metrics',
                DBPoolMetrics.load(self.logger, self, session)  # type: ignore[attr-defined]
            )

        try:
            yield session

            # Commit only when the transaction is still active. Our transactions are usually commited here, after
            # being used in read-only workflows, or workflows that do not care about conflicts or concurrency.
            # The workflows that do care about concurrency - switching guest request state, for example - calls
            # commit explicitly. Any SQL query after that starts new transaction.
            #
            # But if this explicit commit fails - because somebody already modified the guest request record - then
            # the transaction is marked as failed, and rolled back. This does not automatically mean we'd encounter
            # an exception, since the situation was probably handled and reported and so on. Which means we have to
            # check session state before issuing `COMMIT`, because committing a failed transaction will just case yet
            # another error.
            #
            # A thing to consider: could we/should we do a rollback instead of a commit? Because we work in read-only
            # mode, then rollback vs commit makes no difference, or we make changes and then we could issue explicit
            # commits, like we do when changing guest request state. We don't make that many changes after all...
            if session.transaction.is_active:
                session.commit()

        except Exception:
            session.rollback()

            raise

        finally:
            cast(Callable[[], None], Session.remove)()


def convert_column_str_to_json(op: Any, tablename: str, columnname: str, rename_to: Optional[str] = None) -> None:
    """
    Generate SQL statements for converting a column from a text type to JSON while preserving data.

    This is a helper for Alembic, easing very common schema transformation.

    :param op: Alembic's ``op`` object, providing access to Alembic's operations.
    :param tablename: name of the table to modify.
    :param columnname: name of the column to modify.
    :param rename_to: if set, the column will be renamed to this name. This may be useful when our model would like
        to apply some additional processing - renaming the column to some "hidden" name, keeping the actual name
        for model-level ``property`` to make the code more readable.
    """

    final_columnname = rename_to or columnname

    # create a temporary JSON column
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.add_column(Column(f'__tmp_{columnname}', JSON(), nullable=False, server_default='{}'))

    # copy data from the existing column to the temporary one, and cast them to JSON type
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}::json')
    else:
        op.get_bind().execute(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}')

    # drop the original column, and create it as JSON
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(columnname)
        batch_op.add_column(Column(final_columnname, JSON(), nullable=False, server_default='{}'))

    # copy data from the temporary column to its final location (no casting needed, they have the very same type)
    op.get_bind().execute(f'UPDATE {tablename} SET {final_columnname} = __tmp_{columnname}')

    # drop the temporary column
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(f'__tmp_{columnname}')


def convert_column_json_to_str(op: Any, tablename: str, columnname: str, rename_to: Optional[str] = None) -> None:
    """
    Generate SQL statements for converting a column from a JSON type to a text type while preserving data.

    This is a helper for Alembic, easing very common schema transformation.

    :param op: Alembic's ``op`` object, providing access to Alembic's operations.
    :param tablename: name of the table to modify.
    :param columnname: name of the column to modify.
    :param rename_to: if set, the column will be renamed to this name. This may be useful when our model would like
        to apply some additional processing - renaming the column to some "hidden" name, keeping the actual name
        for model-level ``property`` to make the code more readable.
    """

    final_columnname = rename_to or columnname

    # create a temporary text column
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.add_column(Column(f'__tmp_{columnname}', Text(), nullable=False, server_default='{}'))

    # copy data from the existing column to the temporary one, and them to text
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}::text')
    else:
        op.get_bind().execute(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}')

    # drop the original column, and create it as text
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(columnname)
        batch_op.add_column(Column(final_columnname, Text(), nullable=False, server_default='{}'))

    # copy data from the temporary column to its final location (no casting needed, they have the very same type)
    op.get_bind().execute(f'UPDATE {tablename} SET {final_columnname} = __tmp_{columnname}')

    # drop the temporary column
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(f'__tmp_{columnname}')
