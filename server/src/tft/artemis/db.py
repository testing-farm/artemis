# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import dataclasses
import datetime
import enum
import functools
import hashlib
import secrets
import threading
import time
from contextlib import contextmanager
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generator,
    Generic,
    Iterator,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import gluetool.glue
import gluetool.log
import psycopg2.errors
import sqlalchemy
import sqlalchemy.engine
import sqlalchemy.event
import sqlalchemy.exc
import sqlalchemy.ext.declarative
import sqlalchemy.inspection
import sqlalchemy.orm.session
import sqlalchemy.pool
import sqlalchemy.sql._typing
import sqlalchemy.sql.base
import sqlalchemy.sql.dml
import sqlalchemy.sql.elements
import sqlalchemy.sql.expression
from gluetool.result import Error, Ok, Result
from sqlalchemy import JSON, Column, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, column_property, mapped_column, relationship
from sqlalchemy.orm.query import Query as _Query
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.schema import ForeignKeyConstraint, Index, PrimaryKeyConstraint
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

from .guest import GuestState
from .knobs import KNOB_GUEST_REQUEST_RESOURCE_DIGEST_TEMPLATE, KNOB_LOGGING_DB_QUERIES, get_vault_password

if TYPE_CHECKING:
    from . import Failure
    from .drivers import PoolData, PoolDriver, ResourceOwnerDigest, SerializedPoolData
    from .environment import Environment
    from .security_group_rules import SecurityGroupRule, SecurityGroupRules
    from .tasks import Actor, ActorArgumentType


# Type variables for use in our generic types
T = TypeVar('T')
S = TypeVar('S')


# "A reasonable default" size of tokens. There's no need to tweak it in runtime, but we don't want
# magic numbers spreading through our code. Note that we do't store the token itself, but rather its
# SHA256 hash.
TOKEN_SIZE = 32
TOKEN_HASH_SIZE = 64


# Base = sqlalchemy.ext.declarative.declarative_base()
class Base(sqlalchemy.orm.DeclarativeBase):
    pass


# "Safe" query - a query-like class, adapted to return Result instances instead of the raw data.
# When it comes to issues encountered when working with the database, SafeQuery should be easier
# to use than query, because it aligns better with our codebase, and exceptions raised by underlying
# SQLAlchemy code are translated into failures. For example, should the database connection go away,
# one_or_none() will raise an exception when called - SafeQuery.one_or_none() would return Error(Failure)
# instead.
#
# Types of SafeQuery methods, as used by SafeQuery decorators.
#
# All types are generic, and depend on at least one type provided by the SafeQuery itself, `T`. This is
# the type of the records query is supposed to work with (e.g. `SafeQuery[db.Knob]`). Types that apply
# to "get records" methods need one more generic type, `S`, which represents the type of the raw value
# returned by the original method: `T` for `one()`, `List[T]` for `all()`, etc. `S` is then used when
# defining what type the decorated method returns, `Result[S, Failure]`, preserving the original return
# value type.


class SafeQuery(Generic[T]):
    def __init__(self, session: sqlalchemy.orm.session.Session, query: '_Query[T]') -> None:
        self._session = session
        self.query = query

        self.failure: Optional[Failure] = None

    @staticmethod
    def from_session(session: sqlalchemy.orm.session.Session, klass: Type[T]) -> 'SafeQuery[T]':
        return SafeQuery(session, session.query(klass))

    def _error(self, message: str, exc: Exception) -> 'Failure':
        from . import Failure

        self.failure = Failure.from_exc(message, exc, query=stringify_query(self._session, self.query.statement))

        return self.failure

    def _update_error(self, exc: Exception) -> 'Failure':
        return self._error('failed to update query', exc)

    def _retrieval_error(self, exc: Exception) -> 'Failure':
        return self._error('failed to retrieve query result', exc)

    def filter(self, *args: sqlalchemy.sql._typing._ColumnExpressionArgument[bool]) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.filter(*args)

            except Exception as exc:
                self._update_error(exc)

        return self

    def with_skip_locked(self) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.with_for_update(skip_locked=True)

            except Exception as exc:
                self._update_error(exc)

        return self

    def options(self, *args: sqlalchemy.sql.base.ExecutableOption) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.options(*args)

            except Exception as exc:
                self._update_error(exc)

        return self

    def order_by(self, *args: sqlalchemy.sql._typing._ColumnExpressionOrStrLabelArgument[Any]) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.order_by(*args)

            except Exception as exc:
                self._update_error(exc)

        return self

    def limit(self, limit: int) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.limit(limit)

            except Exception as exc:
                self._update_error(exc)

        return self

    def offset(self, offset: int) -> 'SafeQuery[T]':
        if self.failure is None:
            try:
                self.query = self.query.offset(offset)

            except Exception as exc:
                self._update_error(exc)

        return self

    def one(self) -> Result[T, 'Failure']:
        if self.failure is None:
            from . import Sentry, TracingOp

            stringified = stringify_query(self._session, self.query.statement)

            with Sentry.start_span(TracingOp.DB_QUERY_ONE, description=stringified):
                try:
                    return Ok(self.query.one())

                except Exception as exc:
                    self._retrieval_error(exc)

        assert self.failure is not None

        return Error(self.failure)

    def one_or_none(self) -> Result[Optional[T], 'Failure']:
        if self.failure is None:
            from . import Sentry, TracingOp

            stringified = stringify_query(self._session, self.query.statement)

            with Sentry.start_span(TracingOp.DB_QUERY_ONE_OR_NONE, description=stringified):
                try:
                    return Ok(self.query.one_or_none())

                except Exception as exc:
                    self._retrieval_error(exc)

        assert self.failure is not None

        return Error(self.failure)

    def all(self) -> Result[List[T], 'Failure']:
        if self.failure is None:
            from . import Sentry, TracingOp

            stringified = stringify_query(self._session, self.query.statement)

            with Sentry.start_span(TracingOp.DB_QUERY_ALL, description=stringified):
                try:
                    return Ok(self.query.all())

                except Exception as exc:
                    self._retrieval_error(exc)

        assert self.failure is not None

        return Error(self.failure)

    def count(self) -> Result[int, 'Failure']:
        if self.failure is None:
            from . import Sentry, TracingOp

            stringified = stringify_query(self._session, self.query.statement)

            with Sentry.start_span(TracingOp.DB_QUERY_COUNT, description=stringified):
                try:
                    return Ok(self.query.count())

                except Exception as exc:
                    self._retrieval_error(exc)

        assert self.failure is not None

        return Error(self.failure)


def stringify_query(session: sqlalchemy.orm.session.Session, query: sqlalchemy.sql.elements.ClauseElement) -> str:
    """
    Return string representation of a given DB query.

    This helper wraps one tricky piece of information: since SQLAlchemy supports many SQL dialects,
    and these dialects can add custom operations to queries, it is necessary to be aware of the dialect
    when compiling the query. "Compilation" is what happens when we ask SQLAlchemy to transform the query
    to string.
    """

    assert session.bind is not None  # narrow type

    return str(query.compile(dialect=session.bind.dialect))


def assert_not_in_transaction(
    logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, rollback: bool = True
) -> bool:
    if session._transaction is None:
        return True

    from . import Failure

    Failure('Unresolved transaction').handle(logger)

    if rollback:
        from . import Sentry, TracingOp

        with Sentry.start_span(TracingOp.DB_TRANSACTION, description='rollback'):
            session.rollback()

    return False


DMLResult = Result[sqlalchemy.engine.cursor.CursorResult[T], 'Failure']


def execute_dml(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    statement: sqlalchemy.sql.dml.UpdateBase,
) -> DMLResult[T]:
    """
    Execute a given DML statement, ``INSERT``, ``UPDATE`` or ``DELETE``.

    :returns: ``None`` if the statement was executed correctly, :py:class:`Failure` otherwise.
    """

    from . import Sentry, TracingOp

    stringified = stringify_query(session, statement)

    logger.debug(f'execute DML: {stringified}')

    with Sentry.start_span(TracingOp.DB_QUERY_DML, description=stringified):
        try:
            result: sqlalchemy.engine.cursor.CursorResult[T] = session.execute(statement)

            return Ok(result)

        except Exception as exc:
            from . import Failure

            return Error(
                Failure.from_exc('failed to execute DML statement', exc, query=stringify_query(session, statement))
            )


def upsert(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    model: Type[Base],
    primary_keys: Dict[Any, Any],
    constraint: PrimaryKeyConstraint,
    *,
    update_data: Optional[Dict[Any, Any]] = None,
    insert_data: Optional[Dict[Any, Any]] = None,
    expected_records: Union[int, Tuple[int, int]] = 1,
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

    assert session.bind is not None  # narrow type

    if session.bind.dialect.name != 'postgresql':
        raise gluetool.glue.GlueError(f'UPSERT is not support for dialect "{session.bind.dialect.name}"')

    from sqlalchemy.dialects.postgresql import insert

    # Prepare condition for `WHERE` statement. Basically, we focus on given primary keys and their values. If we
    # were given multiple columns, we need to join them via `AND` so we could present just one value to `where`
    # parameter of the `on_conflict_update` clause.
    if len(primary_keys) > 1:
        where = sqlalchemy.sql.expression.and_(*[column == value for column, value in primary_keys.items()])

    else:
        column, value = list(primary_keys.items())[0]

        where = column == value

    # `values()` accepts only string as argument names, we cant pass a `Column` instance to it.
    # But columns are easier to pass and type-check, which means we need to convert comments
    # to their names. Also, since `values()` applies when inserting new record, we shouldn't
    # forget the primary key columns neither.
    statement = insert(model).values(
        **{
            **{column.name: value for column, value in primary_keys.items()},
            **{column.name: value for column, value in (insert_data or {}).items()},
        }
    )

    if update_data is None:
        statement = statement.on_conflict_do_nothing(constraint=constraint)

        # INSERT part of the query is still valid, but there's no ON CONFLICT UPDATE... Unfortunatelly,
        # reporting changed rows for UPSERT has gaps :/ Setting to `1` for now, but it may change in the future.
        expected_records = expected_records if expected_records is not None else 1

    else:
        statement = statement.on_conflict_do_update(constraint=constraint, set_=update_data, where=where)

        expected_records = expected_records if expected_records is not None else 1

    logger.debug(f'safe db change: {stringify_query(session, statement)} - expect {expected_records} records')

    from . import Failure

    r: DMLResult[Base] = execute_dml(logger, session, statement)

    if r.is_error:
        return Error(
            Failure.from_failure(
                'failed to execute upsert query', r.unwrap_error(), query=stringify_query(session, statement)
            )
        )

    query_result = r.unwrap()

    # TODO: INSERT sets this correctly, but what about INSERT + ON CONFLICT? If the row exists,
    # TODO: rowcount is set to 0, but the (optional) UPDATE did happen, so... UPSERT should probably
    # TODO: be ready to accept both 0 and 1. We might need to return more than just true/false for
    # TODO: ON CONFLICT to become auditable.
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

    return Ok(True)


@dataclasses.dataclass
class TransactionResult:
    complete: bool = False
    conflict: bool = False

    failure: Optional['Failure'] = None
    failed_query: Optional[str] = None


@contextlib.contextmanager
def transaction(
    logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session
) -> Generator[TransactionResult, None, None]:
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

    from . import Failure, Sentry, TracingOp

    result = TransactionResult()

    def _save_error(exc: Exception) -> None:
        result.complete = False

        if isinstance(exc, sqlalchemy.exc.StatementError):
            result.failure = Failure.from_exc('failed to execute in transaction', exc=exc, query=exc.statement)

        else:
            result.failure = Failure.from_exc('failed to execute in transaction', exc=exc)

    with Sentry.start_span(TracingOp.DB_TRANSACTION):
        try:
            assert_not_in_transaction(logger, session, rollback=False)

            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='begin'):
                session.begin()

            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='body'):
                yield result

            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='commit'):
                session.commit()

            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='expunge'):
                session.expunge_all()

            result.complete = True

        except sqlalchemy.exc.OperationalError as exc:
            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='expunge'):
                session.expunge_all()

            if (
                isinstance(exc, sqlalchemy.exc.OperationalError)
                and isinstance(exc.orig, psycopg2.errors.SerializationFailure)
                and exc.orig.pgerror.strip() == 'ERROR:  could not serialize access due to concurrent update'
            ):
                result.complete = False
                result.conflict = True
                result.failure = Failure.from_exc('could not serialize access due to concurrent update', exc)
                result.failed_query = exc.statement

            else:
                _save_error(exc)

        except Exception as exc:
            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='rollback'):
                session.rollback()

            with Sentry.start_span(TracingOp.DB_TRANSACTION, description='expunge'):
                session.expunge_all()

            _save_error(exc)


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

    username: Mapped[str]

    role: Mapped[UserRoles] = mapped_column(nullable=False, server_default=UserRoles.USER.value)
    """
    User role.
    """

    # Tokens are initialized to a short, human-readable string *on purpose*. We don't store the actual tokens
    # in the database, only their SHA256 hashes, and there's no possible token whose hash would be "undefined".
    # This makes newly created users safe from leaking any tokens by accident, user's tokens must be explicitly
    # initialized by ADMIN-level account first.
    admin_token: Mapped[str] = mapped_column(String(TOKEN_HASH_SIZE), nullable=False, server_default='undefined')
    """
    Token used to authenticate actions not related to guests and provisioning. Stored as a SHA256
    hash of the actual token.
    """

    provisioning_token: Mapped[str] = mapped_column(String(TOKEN_HASH_SIZE), nullable=False, server_default='undefined')
    """
    Token used to authenticate actions related to guests and provisioning. Stored as a SHA256
    hash of the actual token.
    """

    sshkeys = relationship('SSHKey', back_populates='owner')
    guests = relationship('GuestRequest', back_populates='owner')

    __table_args__ = (PrimaryKeyConstraint('username'),)

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
        return cls(username=username, role=role.value)

    @property
    def is_admin(self) -> bool:
        return self.role == UserRoles.ADMIN


class SSHKey(Base):
    __tablename__ = 'sshkeys'

    keyname: Mapped[str]
    enabled: Mapped[bool]
    ownername: Mapped[str] = mapped_column(String(250), ForeignKey('users.username'), nullable=False)

    # DEPRECATED: but kept for easier schema rollback. Once we're sure things work, we will drop the column.
    file: Mapped[str] = mapped_column(String(250), nullable=False)

    private: Mapped[str] = mapped_column(
        EncryptedType(String, get_vault_password(), AesEngine, 'pkcs5'), nullable=False
    )
    public: Mapped[str] = mapped_column(EncryptedType(String, get_vault_password(), AesEngine, 'pkcs5'), nullable=False)

    owner = relationship('User', back_populates='sshkeys')
    guests = relationship('GuestRequest', back_populates='ssh_key')

    __table_args__ = (PrimaryKeyConstraint('keyname'),)


class PriorityGroup(Base):
    __tablename__ = 'priority_groups'

    name: Mapped[str]

    guests = relationship('GuestRequest', back_populates='priority_group')

    __table_args__ = (PrimaryKeyConstraint('name'),)


class Pool(Base):
    __tablename__ = 'pools'

    poolname: Mapped[str]
    driver: Mapped[str] = mapped_column(String(250), nullable=False)
    _parameters: Mapped[Dict[str, Any]] = mapped_column(JSON(), nullable=False)

    __table_args__ = (PrimaryKeyConstraint('poolname'),)

    @property
    def parameters(self) -> Dict[str, Any]:
        return self._parameters

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

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    taskname: Mapped[str]
    arguments: Mapped[Any] = mapped_column(JSON(), nullable=False)
    delay: Mapped[Optional[int]]

    task_sequence_request_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey('task_sequence_requests.id'), nullable=True
    )
    task_sequence_request = relationship('TaskSequenceRequest', back_populates='task_requests')

    @classmethod
    def create_query(
        cls,
        task: 'Actor',
        *args: 'ActorArgumentType',
        delay: Optional[int] = None,
        task_sequence_request_id: Optional[int] = None,
    ) -> sqlalchemy.Insert:
        return sqlalchemy.insert(cls).values(
            taskname=task.actor_name,
            arguments=list(args),
            delay=delay,
            task_sequence_request_id=task_sequence_request_id,
        )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        task: 'Actor',
        *args: 'ActorArgumentType',
        delay: Optional[int] = None,
        task_sequence_request_id: Optional[int] = None,
    ) -> Result[int, 'Failure']:
        stmt = cls.create_query(task, *args, delay=delay, task_sequence_request_id=task_sequence_request_id)

        r: DMLResult[TaskRequest] = execute_dml(logger, session, stmt)

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(r.unwrap().inserted_primary_key[0])


class TaskSequenceRequest(Base):
    __tablename__ = 'task_sequence_requests'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    task_requests = relationship('TaskRequest', back_populates='task_sequence_request')

    @classmethod
    def create(
        cls, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session
    ) -> Result[int, 'Failure']:
        r: DMLResult[TaskSequenceRequest] = execute_dml(logger, session, sqlalchemy.insert(cls))

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(r.unwrap().inserted_primary_key[0])


class GuestShelf(Base):
    __tablename__ = 'guest_shelves'

    shelfname: Mapped[str]
    ownername: Mapped[str] = mapped_column(String(250), ForeignKey('users.username'), nullable=False)
    state: Mapped[GuestState]

    guests = relationship('GuestRequest', back_populates='shelf')

    __table_args__ = (PrimaryKeyConstraint('shelfname'),)

    @classmethod
    def create_query(cls, shelfname: str, ownername: str) -> sqlalchemy.Insert:
        return sqlalchemy.insert(cls).values(shelfname=shelfname, ownername=ownername, state=GuestState.READY)


class GuestEvent(Base):
    __tablename__ = 'guest_events'

    _id: Mapped[int] = mapped_column(primary_key=True)
    updated: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    guestname: Mapped[str] = mapped_column(String(250), nullable=False, index=True)
    eventname: Mapped[str] = mapped_column(String(250), nullable=False)

    # Details are stored as JSON blob, in a "hidden" column - when accessing event details, we'd like to cast them to
    # proper type, and there will never ever be an event having a list or an integer as a detail, it will always
    # be a mapping. Therefore `_details` column and `details` property to apply proper cast call.
    _details: Mapped[Dict[str, Any]] = mapped_column(JSON(), nullable=False, server_default='{}')

    __table_args__ = (Index('ix_guest_events_guestname_updated', guestname, updated.asc()),)

    def __init__(
        self, eventname: str, guestname: str, updated: Optional[datetime.datetime] = None, **details: Any
    ) -> None:
        self.eventname = eventname
        self.guestname = guestname
        self.updated = updated or datetime.datetime.utcnow()
        self._details = details

    @property
    def details(self) -> Dict[str, Any]:
        return self._details

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
        until: Optional[str] = None,
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
            return Error(Failure('cannot sort events', sort_field=sort_field, sort_order=sort_order))

        # E.g. order_by(GuestEvent.updated.desc())
        query = query.order_by(sort_field_direction())

        if page_size is not None:
            query = query.limit(page_size)

            if page is not None:
                query = query.offset((page - 1) * page_size)

        return query.all()


UserDataType = Dict[str, Optional[str]]
PoolDataT = TypeVar('PoolDataT', bound='PoolData')
SerializedPoolDataMapping = Dict[str, 'SerializedPoolData']


class _PoolDataMapping:
    def __init__(self, guest_request: 'GuestRequest') -> None:
        self._guest_request = guest_request

    def one_or_none(self, poolname: str, pool_data_class: Type[PoolDataT]) -> Optional[PoolDataT]:
        pool_data = self._guest_request._pool_data.get(poolname, {})

        if not pool_data:
            return None

        return pool_data_class.unserialize(pool_data)

    def one(self, poolname: str, pool_data_class: Type[PoolDataT]) -> PoolDataT:
        pool_data = self._guest_request._pool_data.get(poolname, {})

        return pool_data_class.unserialize(pool_data)

    def mine_or_none(self, pool: 'PoolDriver', pool_data_class: Type[PoolDataT]) -> Optional[PoolDataT]:
        return self.one_or_none(pool.poolname, pool_data_class)

    def mine(self, pool: 'PoolDriver', pool_data_class: Type[PoolDataT]) -> PoolDataT:
        return self.one(pool.poolname, pool_data_class)

    def update(self, poolname: str, pool_data: PoolDataT) -> SerializedPoolDataMapping:
        return {**self._guest_request._pool_data, poolname: pool_data.serialize()}

    def reset(self, poolname: str, pool_data: PoolDataT) -> SerializedPoolDataMapping:
        """
        Return a copy of pool data mapping with the given pool slot emptied.

        :param poolname: name of the pool whose slot to reset.
        :param pool_data: current pool data of the pool.
        """

        return {**self._guest_request._pool_data, poolname: pool_data.reset().serialize()}


class GuestRequest(Base):
    __tablename__ = 'guest_requests'

    guestname: Mapped[str] = mapped_column(primary_key=True, nullable=False)
    _environment: Mapped[Dict[str, Any]] = mapped_column(JSON(), nullable=False)
    ownername: Mapped[str] = mapped_column(String(250), ForeignKey('users.username'), nullable=False)
    shelfname: Mapped[Optional[str]] = mapped_column(String(250), ForeignKey('guest_shelves.shelfname'), nullable=True)
    priorityname: Mapped[Optional[str]] = mapped_column(String(250), ForeignKey('priority_groups.name'), nullable=True)
    poolname: Mapped[Optional[str]] = mapped_column(String(250), ForeignKey('pools.poolname'), nullable=True)
    last_poolname: Mapped[Optional[str]] = mapped_column(String(250), nullable=True)
    _security_group_rules_ingress: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON(), nullable=True)
    _security_group_rules_egress: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON(), nullable=True)

    @property
    def environment(self) -> 'Environment':
        # avoid circular imports
        from .environment import Environment

        # v0.0.53: added Kickstart specification. For backward compatibility,
        # add `kickstart` key if it's missing.
        if 'kickstart' not in self._environment:
            self._environment['kickstart'] = {}

        return Environment.unserialize(self._environment)

    @property
    def security_group_rules_ingress(self) -> List['SecurityGroupRule']:
        from .security_group_rules import SecurityGroupRule

        return [
            SecurityGroupRule.unserialize(rule)
            for rule in cast(List[Dict[str, Any]], self._security_group_rules_ingress or [])
        ]

    @property
    def security_group_rules_egress(self) -> List['SecurityGroupRule']:
        from .security_group_rules import SecurityGroupRule

        return [
            SecurityGroupRule.unserialize(rule)
            for rule in cast(List[Dict[str, Any]], self._security_group_rules_egress or [])
        ]

    @property
    def security_group_rules(self) -> 'SecurityGroupRules':
        from .security_group_rules import SecurityGroupRules

        return SecurityGroupRules(ingress=self.security_group_rules_ingress, egress=self.security_group_rules_egress)

    def resource_owner_digest(self) -> Result['ResourceOwnerDigest', 'Failure']:
        """
        Generate a mapping describing the given guest request as an owner of pool resources.
        """

        if self.poolname is None:
            return Error(
                Failure('cannot construct guest request resource digest for unknown pool', guestname=self.guestname)
            )

        r_template = KNOB_GUEST_REQUEST_RESOURCE_DIGEST_TEMPLATE.get_value(entityname=self.poolname)

        if r_template.is_error:
            return Error(r_template.unwrap_error())

        from . import get_yaml, render_template, safe_call, template_environment

        r_digest = render_template(r_template.unwrap(), **template_environment(self))

        if r_digest.is_error:
            return Error(r_digest.unwrap_error())

        return safe_call(get_yaml().load, r_digest.unwrap())

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
    ctime: Mapped[datetime.datetime] = mapped_column(nullable=False, default=datetime.datetime.utcnow)

    state: Mapped[GuestState]
    state_mtime: Mapped[Optional[datetime.datetime]]

    mtime: Mapped[datetime.datetime] = column_property(
        sqlalchemy.select(sqlalchemy.func.max(GuestEvent.updated))
        .where(GuestEvent.guestname == guestname)
        .scalar_subquery(),
        deferred=True,
    )

    address: Mapped[Optional[str]] = mapped_column(String(250), nullable=True)

    # SSH info
    ssh_keyname: Mapped[str] = mapped_column(String(250), ForeignKey('sshkeys.keyname'), nullable=False)
    ssh_port: Mapped[int]
    ssh_username: Mapped[str] = mapped_column(String(250), nullable=False)

    # Pool-specific data.
    _pool_data: Mapped[Dict[str, Dict[str, Any]]] = mapped_column(
        JSONB(),  # type: ignore[no-untyped-call]
        nullable=False,
        server_default='{}',
    )

    @functools.cached_property
    def pool_data(self) -> _PoolDataMapping:
        return _PoolDataMapping(self)

    # User specified data
    _user_data: Mapped[UserDataType] = mapped_column(JSON(), nullable=False)

    @property
    def user_data(self) -> UserDataType:
        return self._user_data

    #: If set, the shelf will be bypassed during provisioning ensuring a completely new guest is provisioned.
    bypass_shelf_lookup: Mapped[bool] = mapped_column(nullable=False, server_default='false')

    #: If set, the provisioning will skip preparation steps and assume the guest is reachable as soon as it becomes
    #: active.
    skip_prepare_verify_ssh: Mapped[bool] = mapped_column(nullable=False, server_default='false')

    # Contents of a script to be run when the guest becomes active
    post_install_script: Mapped[Optional[str]]

    # User specified watchdog delay
    watchdog_dispatch_delay: Mapped[Optional[int]]
    watchdog_period_delay: Mapped[Optional[int]]

    # Console url if it was requested by the user
    console_url: Mapped[Optional[str]] = mapped_column(String(250), nullable=True)
    console_url_expires: Mapped[Optional[datetime.datetime]] = mapped_column(nullable=True)

    # Log types specifically to be supported as requested by the user (colon-separated string of logtype:contenttype)
    _log_types: Mapped[Any] = mapped_column(JSON(), nullable=True)

    # Tasks to be dispatched upon guest reaching ready state (list of tuples of taskname, args)
    _on_ready: Mapped[Any] = mapped_column(JSON())

    owner = relationship('User', back_populates='guests')
    shelf = relationship('GuestShelf', back_populates='guests')
    ssh_key = relationship('SSHKey', back_populates='guests')
    priority_group = relationship('PriorityGroup', back_populates='guests')
    pool = relationship('Pool', back_populates='guests')

    __table_args__ = (Index('ix_guestname_poolname', guestname, poolname),)

    @classmethod
    def create_query(
        cls,
        guestname: str,
        environment: 'Environment',
        ownername: str,
        shelfname: Optional[str],
        ssh_keyname: str,
        ssh_port: int,
        ssh_username: str,
        priorityname: Optional[str],
        user_data: Optional[UserDataType],
        bypass_shelf_lookup: bool,
        skip_prepare_verify_ssh: bool,
        post_install_script: Optional[str],
        log_types: List[Tuple[str, GuestLogContentType]],
        watchdog_dispatch_delay: Optional[int],
        watchdog_period_delay: Optional[int],
        on_ready: Optional[List[Tuple['Actor', List['ActorArgumentType']]]],
        security_group_rules_ingress: Optional[List['SecurityGroupRule']],
        security_group_rules_egress: Optional[List['SecurityGroupRule']],
    ) -> sqlalchemy.Insert:
        return sqlalchemy.insert(cls).values(
            guestname=guestname,
            _environment=environment.serialize(),
            ownername=ownername,
            shelfname=shelfname,
            ssh_keyname=ssh_keyname,
            ssh_port=ssh_port,
            ssh_username=ssh_username,
            priorityname=priorityname,
            _user_data=user_data,
            bypass_shelf_lookup=bypass_shelf_lookup,
            skip_prepare_verify_ssh=skip_prepare_verify_ssh,
            post_install_script=post_install_script,
            watchdog_dispatch_delay=watchdog_dispatch_delay,
            watchdog_period_delay=watchdog_period_delay,
            _log_types=[{'logtype': log[0], 'contenttype': log[1].value} for log in log_types],
            state=GuestState.SHELF_LOOKUP,
            state_mtime=datetime.datetime.utcnow(),
            poolname=None,
            last_poolname=None,
            _pool_data={},
            _on_ready=[(actor.actor_name, args) for actor, args in on_ready] if on_ready is not None else on_ready,
            _security_group_rules_ingress=(
                [rule.serialize() for rule in security_group_rules_ingress] if security_group_rules_ingress else None
            ),
            _security_group_rules_egress=(
                [rule.serialize() for rule in security_group_rules_egress] if security_group_rules_egress else None
            ),
        )

    @classmethod
    def log_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        eventname: str,
        **details: Any,
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

        r: DMLResult['GuestEvent'] = execute_dml(
            logger,
            session,
            sqlalchemy.insert(GuestEvent).values(guestname=guestname, eventname=eventname, _details=details),
        )

        if r.is_error:
            failure = r.unwrap_error()

            failure.details.update({'guestname': guestname, 'eventname': eventname})

            log_dict_yaml(logger.warning, 'failed to log event', {'eventname': eventname, 'details': details})

            # TODO: this handle() call can be removed once we fix callers of log_guest_event and they start consuming
            # its return value. At this moment, they ignore it, therefore we have to keep reporting the failures on
            # our own.
            failure.handle(logger, label='failed to store guest event', guestname=guestname, eventname=eventname)

            return Error(failure)

        log_dict_yaml(logger.info, 'logged event', {'eventname': eventname, 'details': details})

        return Ok(None)

    def log_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        eventname: str,
        **details: Any,
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given event.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param eventname: event name.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        return self.__class__.log_event_by_guestname(logger, session, self.guestname, eventname, **details)

    @classmethod
    def log_error_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        message: str,
        failure: 'Failure',
        **details: Any,
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

        return cls.log_event_by_guestname(logger, session, guestname, 'error', error=message, **details)

    def log_error_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        message: str,
        failure: 'Failure',
        **details: Any,
    ) -> Result[None, 'Failure']:
        """
        Store new event record representing a given error.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param message: error message.
        :param failure: failure representing the error.
        :param details: additional event details. The mapping will be stored as a JSON blob.
        """

        return self.__class__.log_error_event_by_guestname(logger, session, self.guestname, message, failure, **details)

    @classmethod
    def log_warning_event_by_guestname(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        message: str,
        failure: Optional['Failure'] = None,
        **details: Any,
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

        return cls.log_event_by_guestname(logger, session, guestname, 'warning', error=message, **details)

    def log_warning_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        message: str,
        failure: Optional['Failure'] = None,
        **details: Any,
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
            logger, session, self.guestname, message, failure=failure, **details
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
        until: Optional[str] = None,
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
            until=until,
        )

    @property
    def log_types(self) -> List[Tuple[str, GuestLogContentType]]:
        if not self._log_types:
            return []
        self._log_types = cast(List[Dict[str, str]], self._log_types)
        return [(log_type['logtype'], GuestLogContentType(log_type['contenttype'])) for log_type in self._log_types]

    def requests_guest_log(self, logname: str, contenttype: GuestLogContentType) -> bool:
        return (logname, contenttype) in self.log_types

    @property
    def on_ready(self) -> List[Tuple[str, List['ActorArgumentType']]]:
        if not self._on_ready:
            return []

        on_ready = cast(List[List[Any]], self._on_ready)

        return [(cast(str, actorname), cast(List['ActorArgumentType'], args)) for actorname, args in on_ready]


class GuestLogBlob(Base):
    __tablename__ = 'guest_log_blobs'

    guestname: Mapped[str]
    logname: Mapped[str]
    contenttype: Mapped[GuestLogContentType]

    ctime: Mapped[datetime.datetime] = mapped_column(nullable=False, default=datetime.datetime.utcnow)
    content: Mapped[str] = mapped_column(nullable=False, server_default='', deferred=True)
    content_hash: Mapped[str] = mapped_column(nullable=False, server_default='')

    guest_log = relationship('GuestLog', back_populates='blobs')

    __table_args__ = (
        PrimaryKeyConstraint('guestname', 'logname', 'contenttype', 'ctime'),
        ForeignKeyConstraint(
            ['guestname', 'logname', 'contenttype'],
            ['guest_logs.guestname', 'guest_logs.logname', 'guest_logs.contenttype'],
        ),
    )

    def update(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        content: str,
        content_hash: str,
    ) -> Result[None, 'Failure']:
        """
        Update the log content.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param content: the log content.
        :param content_hash: the hash of the log content.
        """

        r: DMLResult['GuestLogBlob'] = execute_dml(
            logger,
            session,
            sqlalchemy.update(GuestLogBlob)
            .where(GuestLogBlob.guestname == self.guestname)
            .where(GuestLogBlob.logname == self.logname)
            .where(GuestLogBlob.contenttype == self.contenttype)
            .where(GuestLogBlob.ctime == self.ctime)
            .values(content=content, content_hash=content_hash),
        )

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(None)

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        logname: str,
        contenttype: GuestLogContentType,
        ctime: datetime.datetime,
        content: str,
        content_hash: str,
    ) -> Result[None, 'Failure']:
        """
        Create a new log blob entry.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guestname: guest request name to attach the event to.
        :param logname: name of the log to create.
        :param contenttype: the content type of the log to create.
        :param ctime: the log creation time.
        :param content: the log content.
        :param content_hash: the hash of the log content.
        """

        r: DMLResult['GuestLogBlob'] = execute_dml(
            logger,
            session,
            sqlalchemy.insert(GuestLogBlob).values(
                guestname=guestname,
                logname=logname,
                contenttype=contenttype,
                ctime=ctime,
                content=content,
                content_hash=content_hash,
            ),
        )

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(None)


class GuestLog(Base):
    __tablename__ = 'guest_logs'

    guestname: Mapped[str]
    logname: Mapped[str]
    contenttype: Mapped[GuestLogContentType]

    __table_args__ = (PrimaryKeyConstraint('guestname', 'logname', 'contenttype'),)

    state: Mapped[GuestLogState] = mapped_column(nullable=False, default=GuestLogState.PENDING.value)

    url: Mapped[Optional[str]]
    blobs: Mapped[List[GuestLogBlob]] = relationship('GuestLogBlob', back_populates='guest_log')

    updated: Mapped[Optional[datetime.datetime]]
    expires: Mapped[Optional[datetime.datetime]]

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False

        return self.expires < datetime.datetime.utcnow()

    @property
    def blob_timestamps(self) -> List[datetime.datetime]:
        return [blob.ctime for blob in self.blobs]

    @property
    def blob_contents(self) -> List[str]:
        return [blob.content for blob in self.blobs]

    @property
    def blob_content_hashes(self) -> List[str]:
        return [blob.content_hash for blob in self.blobs]

    def update(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        state: GuestLogState,
        expires: Optional[datetime.datetime] = None,
        *,
        url: Optional[str] = None,
    ) -> Result[None, 'Failure']:
        """
        Update an existing log entry.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param state: current state of the log.
        :param expires: optional datetime object marking the expiration time of a log.
        :param url: optional URL of the log if contenttype is URL.
        """

        r: DMLResult['GuestLog'] = execute_dml(
            logger,
            session,
            sqlalchemy.update(GuestLog)
            .where(
                GuestLog.guestname == self.guestname,
                GuestLog.logname == self.logname,
                GuestLog.contenttype == self.contenttype,
                GuestLog.state == self.state,
                GuestLog.updated == self.updated,
                GuestLog.url == self.url,
            )
            .values(url=url, updated=datetime.datetime.utcnow(), state=state, expires=expires),
        )

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(None)

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guestname: str,
        logname: str,
        contenttype: GuestLogContentType,
        state: GuestLogState,
        expires: Optional[datetime.datetime] = None,
        *,
        url: Optional[str] = None,
    ) -> Result['GuestLog', 'Failure']:
        """
        Create a new log entry.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param guestname: guest request name to attach the event to.
        :param logname: name of the log to create.
        :param contenttype: the content type of the log to create.
        :param state: current state of the log.
        :param expires: optional datetime object marking the expiration time of a log.
        :param url: optional URL of the log if contenttype is URL.
        """

        r: DMLResult['GuestLog'] = execute_dml(
            logger,
            session,
            sqlalchemy.insert(GuestLog)
            .values(
                guestname=guestname,
                logname=logname,
                contenttype=contenttype,
                state=state,
                updated=datetime.datetime.utcnow(),
                expires=expires,
                url=url,
            )
            .returning(GuestLog),
        )

        if r.is_error:
            return Error(r.unwrap_error())

        try:
            guest_log = r.unwrap().one()[0]
        except Exception as exc:
            from . import Failure

            return Error(Failure.from_exc('failed to unwrap the inserted guest log', exc))

        return Ok(guest_log)


class SnapshotRequest(Base):
    __tablename__ = 'snapshot_requests'

    snapshotname: Mapped[str] = mapped_column(String(250), primary_key=True, nullable=False)
    guestname: Mapped[str] = mapped_column(String(250), ForeignKey('guest_requests.guestname'), nullable=False)
    poolname: Mapped[Optional[str]] = mapped_column(String(250), ForeignKey('pools.poolname'), nullable=True)

    state: Mapped[GuestState]

    start_again: Mapped[bool]


class GuestTag(Base):
    __tablename__ = 'guest_tags'

    #: Used as a poolname to represent system-wide tags.
    SYSTEM_POOL_ALIAS = '__system__'

    poolname: Mapped[str]
    tag: Mapped[str]
    value: Mapped[str]

    __table_args__ = (PrimaryKeyConstraint('poolname', 'tag'),)

    @classmethod
    def fetch_system_tags(cls, session: sqlalchemy.orm.session.Session) -> Result[List['GuestTag'], 'Failure']:
        """
        Load all system-wide guest tags.
        """

        return SafeQuery.from_session(session, cls).filter(cls.poolname == cls.SYSTEM_POOL_ALIAS).all()

    @classmethod
    def fetch_pool_tags(
        cls, session: sqlalchemy.orm.session.Session, poolname: str
    ) -> Result[List['GuestTag'], 'Failure']:
        """
        Load all pool-wide guest tags for a given pool.
        """

        return SafeQuery.from_session(session, cls).filter(cls.poolname == poolname).all()


class Metrics(Base):
    __tablename__ = 'metrics'

    metric: Mapped[str] = mapped_column(String(250), primary_key=True, nullable=False)
    count: Mapped[int] = mapped_column(default=0)
    updated: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)


class Knob(Base):
    __tablename__ = 'knobs'

    knobname: Mapped[str]
    value: Mapped[Any] = mapped_column(JSON(), nullable=False)

    __table_args__ = (PrimaryKeyConstraint('knobname'),)


# TODO: shuffle a bit with files to avoid local imports and to set this up conditionaly. It's probably not
# critical, but it would also help a bit with DB class, and it would be really nice to not install the event
# hooks when not asked to log slow queries.
def _log_db_statement(statement: str) -> None:
    if not KNOB_LOGGING_DB_QUERIES.value:
        return

    from .context import CURRENT_MESSAGE, CURRENT_TASK, LOGGER

    logger = LOGGER.get(None)

    if not logger:
        from .tasks import _ROOT_LOGGER

        logger = _ROOT_LOGGER

    current_task = CURRENT_TASK.get(None)
    current_message = CURRENT_MESSAGE.get(None)

    if current_task:
        logger = current_task.logger(logger)

    elif current_message:
        from .tasks import MessageLogger

        logger = MessageLogger(logger, current_message)

    logger.info(statement)


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'before_cursor_execute')
def before_cursor_execute(
    conn: sqlalchemy.engine.Connection, cursor: Any, statement: Any, parameters: Any, context: Any, executemany: Any
) -> None:
    _log_db_statement(statement)

    conn.info.setdefault('query_start_time', []).append(time.time())


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'after_cursor_execute')
def after_cursor_execute(
    conn: sqlalchemy.engine.Connection, cursor: Any, statement: Any, parameters: Any, context: Any, executemany: Any
) -> None:
    from .knobs import KNOB_LOGGING_DB_SLOW_QUERIES, KNOB_LOGGING_DB_SLOW_QUERY_THRESHOLD

    if KNOB_LOGGING_DB_SLOW_QUERIES.value is not True:
        return

    query_time = time.time() - conn.info['query_start_time'].pop(-1)

    if query_time < KNOB_LOGGING_DB_SLOW_QUERY_THRESHOLD.value:
        return

    from . import Failure
    from .context import LOGGER

    Failure('detected a slow query', query=str(statement), time=query_time).handle(LOGGER.get())


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'begin')
def before_begin(
    conn: sqlalchemy.engine.Connection,
) -> None:
    _log_db_statement('BEGIN')


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'commit')
def before_commit(
    conn: sqlalchemy.engine.Connection,
) -> None:
    _log_db_statement('COMMIT')


@sqlalchemy.event.listens_for(sqlalchemy.engine.Engine, 'rollback')
def before_rollback(
    conn: sqlalchemy.engine.Connection,
) -> None:
    _log_db_statement('ROLLBACK')


class DB:
    instance: Optional['DB'] = None
    _lock = threading.RLock()

    #: "Root" engine, with the setup dictated by DB configuration.
    engine: sqlalchemy.engine.Engine

    #: Engine derived from :py:attr:`engine`, configured to use no transactions in an auto-commit fashion.
    engine_autocommit: sqlalchemy.engine.Engine
    #: Session factory on top of auto-commit :py:attr:`engine_autocommit` engine: ``AUTOCOMMIT`` isolation level
    #: is applied to each and every query.
    sessionmaker_autocommit: sessionmaker[sqlalchemy.orm.session.Session]

    #: Engine derived from :py:attr:`engine`, configured to transactions with ``REPEATABLE READ`` isolation level.
    engine_transactional: sqlalchemy.engine.Engine
    #: Session factory on top of auto-commit :py:attr:`engine_treansactional` engine: every session spawns
    #: a transaction with ``REPEATABLE READ`` isolation level.
    sessionmaker_transactional: sessionmaker[sqlalchemy.orm.session.Session]

    #: Engine derived from :py:attr:`engine`, configured to transactions with ``REPEATABLE READ`` isolation level
    #: in read-only mode.
    engine_transactional_read_only: sqlalchemy.engine.Engine
    #: Session factory on top of auto-commit :py:attr:`engine_treansactional_read_only` engine: every session spawns
    #: a read-only transaction with ``REPEATABLE READ`` isolation level.
    sessionmaker_transactional_read_only: sessionmaker[sqlalchemy.orm.session.Session]

    def _setup_instance(
        self, logger: gluetool.log.ContextAdapter, url: str, application_name: Optional[str] = None
    ) -> None:
        from .knobs import KNOB_DB_POOL_MAX_OVERFLOW, KNOB_DB_POOL_SIZE, KNOB_LOGGING_DB_POOL

        self.logger = logger

        logger.info(f'connecting to db {url}')

        # if KNOB_LOGGING_DB_QUERIES.value:
        #    gluetool.log.Logging.configure_logger(logging.getLogger('sqlalchemy.engine'))

        self._echo_pool: Union[str, bool] = False

        if KNOB_LOGGING_DB_POOL.value == 'debug':
            self._echo_pool = 'debug'

        else:
            self._echo_pool = gluetool.utils.normalize_bool_option(KNOB_LOGGING_DB_POOL.value)

        connect_args: Dict[str, Any] = {}

        # We want a nice way how to change default for pool size and maximum overflow for PostgreSQL
        if url.startswith('postgresql://'):
            if application_name is not None:
                connect_args['application_name'] = application_name

            gluetool.log.log_dict(
                logger.info,
                'postgresql create_engine parameters',
                {
                    'echo_pool': self._echo_pool,
                    'pool_size': KNOB_DB_POOL_SIZE.value,
                    'max_overflow': KNOB_DB_POOL_MAX_OVERFLOW.value,
                    'application_name': application_name,
                    'connect_args': connect_args,
                },
            )

            self.engine = sqlalchemy.create_engine(
                url,
                echo_pool=self._echo_pool,
                pool_size=KNOB_DB_POOL_SIZE.value,
                max_overflow=KNOB_DB_POOL_MAX_OVERFLOW.value,
                connect_args=connect_args,
            )

        # SQLite does not support altering pool size nor max overflow, and must be told to share DB between
        # thread.
        else:
            connect_args['check_same_thread'] = False

            if application_name is not None:
                connect_args['application_name'] = application_name

            gluetool.log.log_dict(
                logger.info,
                'sqlite create_engine parameters',
                {
                    'echo_pool': self._echo_pool,
                    'pool_size': KNOB_DB_POOL_SIZE.value,
                    'max_overflow': KNOB_DB_POOL_MAX_OVERFLOW.value,
                    'application_name': application_name,
                    'connect_args': connect_args,
                },
            )

            self.engine = sqlalchemy.create_engine(url, connect_args=connect_args, poolclass=sqlalchemy.pool.StaticPool)

        # TODO: hopefully, with better sqlalchemy stubs, cast() wouldn't be needed anymore
        _engine_execution_options = cast(Callable[..., sqlalchemy.engine.Engine], self.engine.execution_options)

        self.engine_autocommit = _engine_execution_options(isolation_level='AUTOCOMMIT')
        self.sessionmaker_autocommit = sqlalchemy.orm.sessionmaker(bind=self.engine_autocommit)

        if url.startswith('postgresql://'):
            self.engine_transactional = _engine_execution_options(
                isolation_level='REPEATABLE READ', autobegin=False, autocommit=False
            )

            self.engine_transactional_read_only = _engine_execution_options(
                isolation_level='REPEATABLE READ', autobegin=False, autocommit=False, postgresql_readonly=True
            )

        else:
            self.engine_transactional = _engine_execution_options(
                isolation_level='SERIALIZABLE', autobegin=False, autocommit=False
            )

            # No read-only support for SQLite at this point.
            self.engine_transactional_read_only = _engine_execution_options(
                isolation_level='SERIALIZABLE', autobegin=False, autocommit=False
            )

        self.sessionmaker_transactional = sqlalchemy.orm.sessionmaker(bind=self.engine_transactional)
        self.sessionmaker_transactional_read_only = sqlalchemy.orm.sessionmaker(
            bind=self.engine_transactional_read_only
        )

    def __new__(cls, logger: gluetool.log.ContextAdapter, url: str, application_name: Optional[str] = None) -> 'DB':
        with cls._lock:
            if cls.instance is None:
                cls.instance = super().__new__(cls)
                cls.instance._setup_instance(logger, url, application_name=application_name)

        return cls.instance

    @contextmanager
    def get_session(
        self, logger: gluetool.log.ContextAdapter, read_only: bool = False
    ) -> Iterator[sqlalchemy.orm.session.Session]:
        """
        Create new DB session.

        :param transactional: if set, session will support transactions rather than auto-commit isolation level.
        :returns: new DB session.
        """

        from . import Sentry, TracingOp

        if read_only:
            session_factory = sqlalchemy.orm.scoped_session(self.sessionmaker_transactional_read_only)

            _log_db_statement('BEGIN SESSION READ ONLY')

        else:
            session_factory = sqlalchemy.orm.scoped_session(self.sessionmaker_transactional)

            _log_db_statement('BEGIN SESSION')

        with Sentry.start_span(TracingOp.DB_SESSION):
            session = session_factory(
                autoflush=True,
                # autobegin=False,
                expire_on_commit=True,
                twophase=False,
            )

            if self._echo_pool:
                from .metrics import DBPoolMetrics

                gluetool.log.log_dict(
                    logger.info,
                    'pool metrics',
                    DBPoolMetrics.load(self.logger, self, session),  # type: ignore[attr-defined]
                )

            try:
                yield session

                assert_not_in_transaction(logger, session)

            except Exception:
                with Sentry.start_span(TracingOp.DB_SESSION, description='rollback'):
                    session.rollback()

                with Sentry.start_span(TracingOp.DB_SESSION, description='expunge'):
                    session.expunge_all()

                raise

            finally:
                _log_db_statement('END SESSION')

                session_factory.remove()

    @contextmanager
    def transaction(
        self, logger: gluetool.log.ContextAdapter, read_only: bool = False
    ) -> Iterator[tuple[sqlalchemy.orm.session.Session, TransactionResult]]:
        """
        Create new DB session & transaction.

        :returns: new DB session & transaction result tracker.
        """

        with self.get_session(logger, read_only=read_only) as session, transaction(logger, session) as t:
            yield (session, t)

    @classmethod
    def set_application_name(
        cls, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, name: str
    ) -> None:
        with transaction(logger, session):
            session.execute(sqlalchemy.text(f"SET application_name TO '{name}'"))


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
        op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}::json'))
    else:
        op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}'))

    # drop the original column, and create it as JSON
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(columnname)
        batch_op.add_column(Column(final_columnname, JSON(), nullable=False, server_default='{}'))

    # copy data from the temporary column to its final location (no casting needed, they have the very same type)
    op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET {final_columnname} = __tmp_{columnname}'))

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
        op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}::text'))
    else:
        op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET __tmp_{columnname} = {columnname}'))

    # drop the original column, and create it as text
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(columnname)
        batch_op.add_column(Column(final_columnname, Text(), nullable=False, server_default='{}'))

    # copy data from the temporary column to its final location (no casting needed, they have the very same type)
    op.get_bind().execute(sqlalchemy.text(f'UPDATE {tablename} SET {final_columnname} = __tmp_{columnname}'))

    # drop the temporary column
    with op.batch_alter_table(tablename, schema=None) as batch_op:
        batch_op.drop_column(f'__tmp_{columnname}')
