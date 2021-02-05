import collections
import datetime
import enum
import functools
import hashlib
import json
import logging
import os
import secrets
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Dict, Generic, Iterator, List, Optional, Tuple, Type, TypeVar, Union, \
    cast

import gluetool.glue
import gluetool.log
import sqlalchemy
import sqlalchemy.ext.declarative
import sqlalchemy.sql.expression
from gluetool.result import Error, Ok, Result
from sqlalchemy import BigInteger, Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.orm.query import Query as _Query

if TYPE_CHECKING:  # noqa
    from mypy_extensions import VarArg

    from . import Failure


# Type variables for use in our generic types
T = TypeVar('T')
S = TypeVar('S')


# "A reasonable default" size of tokens. There's no need to tweak it in runtime, but we don't want
# magic numbers spreading through our code. Note that we do't store the token itself, but rather its
# SHA256 hash.
TOKEN_SIZE = 32
TOKEN_HASH_SIZE = 64


Base = sqlalchemy.ext.declarative.declarative_base()


# SQLalchemy stubs are missing types for Query methods, and allowing untyped calls globally
# is not a good practice. Therefore, we wrap original Query instances with our wrapper which
# provides all methods we need but applies cast() as needed.
#
# https://github.com/dropbox/sqlalchemy-stubs/pull/81
class Query(Generic[T]):
    def __init__(self, query: _Query) -> None:
        self.query = query

    @staticmethod
    def from_session(session: sqlalchemy.orm.session.Session, klass: Type[T]) -> 'Query[T]':
        query_proxy: Query[T] = Query(
            cast(
                Callable[[Type[T]], _Query],
                session.query
            )(klass)
        )

        return query_proxy

    def filter(self, *args: Any) -> 'Query[T]':
        self.query = cast(
            Callable[..., _Query],
            self.query.filter
        )(*args)

        return self

    def order_by(self, *args: Any) -> 'Query[T]':
        self.query = cast(
            Callable[..., _Query],
            self.query.order_by
        )(*args)

        return self

    def limit(self, limit: Optional[int] = None) -> 'Query[T]':
        self.query = cast(
            Callable[[Optional[int]], _Query],
            self.query.limit
        )(limit)

        return self

    def offset(self, offset: Optional[int] = None) -> 'Query[T]':
        self.query = cast(
            Callable[[Optional[int]], _Query],
            self.query.offset
        )(offset)

        return self

    def one(self) -> T:
        return cast(
            Callable[[], T],
            self.query.one
        )()

    def one_or_none(self) -> Optional[T]:
        return cast(
            Callable[[], T],
            self.query.one_or_none
        )()

    def all(self) -> List[T]:
        return cast(
            Callable[[], List[T]],
            self.query.all
        )()


# "Safe" query - a Query-like class, adapted to return Result instances instead of the raw data.
# When it comes to issues encountered when working with the database, SafeQuery should be easier
# to use than Query, because it aligns better with our codebase, and exceptions raised by underlying
# SQLAlchemy code are translated into Failures. For example, should the database connection go away,
# Query.one_or_none() will raise an exception when called - SafeQuery.one_or_none() would return
# Error(Failure) instead.
#
# TODO: when SafeQuery replaces the use of Query, we will drop Query, rename SafeQuery and that's it.

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
# type/decorator and preserve the signature enough to keep type checking. I always foud out that methods
# accepting 1 integer parameter (limit/offset) collide with signature of filter() which accepts variable
# number of arguments: `[argument: int]` does not fit under [*args: Any]`. Therefore we have a decorator
# for methods accepting anything, and another decorator for methods accepting an integer. On the plus
# side, type checking works, and mypy does see SafeQuery.limit() as accepting one integer and nothing else.
SafeQueryRawUpdateVAType = Callable[['SafeQuery[T]', 'VarArg(Any)'], _Query]  # type: ignore
SafeQueryUpdateVAType = Callable[['SafeQuery[T]', 'VarArg(Any)'], 'SafeQuery[T]']  # type: ignore

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


def upsert(
    session: sqlalchemy.orm.session.Session,
    model: Type[Base],
    primary_keys: Dict[Any, Any],
    *,
    update_data: Dict[Any, Any],
    insert_data: Optional[Dict[Any, Any]] = None
) -> None:
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
        raise gluetool.glue.GlueError('UPSERT is not support for dialect "{}"'.format(session.bind.dialect.name))

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
    ).on_conflict_do_update(
        constraint=model.__table__.primary_key,  # type: ignore
        set_=update_data,
        where=where
    )

    session.execute(statement)


class UserRoles(enum.Enum):
    """
    Possible user roles.
    """

    USER = 'USER'
    ADMIN = 'ADMIN'


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

    @classmethod
    def fetch_by_username(cls, session: sqlalchemy.orm.session.Session, username: str) -> Optional['User']:
        return Query.from_session(session, User) \
            .filter(User.username == username) \
            .one_or_none()


class SSHKey(Base):
    __tablename__ = 'sshkeys'

    keyname = Column(String(250), primary_key=True, nullable=False)
    enabled = Column(Boolean())
    ownername = Column(String(250), ForeignKey('users.username'), nullable=False)
    file = Column(String(250), nullable=False)

    owner = relationship('User', back_populates='sshkeys')
    guests = relationship('GuestRequest', back_populates='ssh_key')

    @property
    def _data(self) -> Dict[str, str]:

        assert self.file

        from . import get_vault

        return cast(
            Dict[str, str],
            get_vault().load(self.file)
        )

    @property
    def private(self) -> str:
        return self._data['private']

    @property
    def public(self) -> str:
        return self._data['public']


class PriorityGroup(Base):
    __tablename__ = 'priority_groups'

    name = Column(String(250), primary_key=True, nullable=False)

    guests = relationship('GuestRequest', back_populates='priority_group')


class Pool(Base):
    __tablename__ = 'pools'

    poolname = Column(String(250), primary_key=True, nullable=False)
    driver = Column(String(250), nullable=False)
    parameters = Column(Text(), nullable=False)

    guests = relationship('GuestRequest', back_populates='pool')


class GuestRequest(Base):
    __tablename__ = 'guest_requests'

    guestname = Column(String(250), primary_key=True, nullable=False)
    environment = Column(Text(), nullable=False)
    ownername = Column(String(250), ForeignKey('users.username'), nullable=False)
    priorityname = Column(String(250), ForeignKey('priority_groups.name'), nullable=True)
    poolname = Column(String(250), ForeignKey('pools.poolname'), nullable=True)

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

    state = Column(String(250), nullable=False)

    address = Column(String(250), nullable=True)

    # SSH info
    ssh_keyname = Column(String(250), ForeignKey('sshkeys.keyname'), nullable=False)
    ssh_port = Column(Integer(), nullable=False)
    ssh_username = Column(String(250), nullable=False)

    # Pool-specific data.
    pool_data = Column(Text(), nullable=False)

    # User specified data
    user_data = Column(Text(), nullable=False)

    # Contents of a script to be run when the guest becomes active
    post_install_script = Column(Text(), nullable=True)

    owner = relationship('User', back_populates='guests')
    ssh_key = relationship('SSHKey', back_populates='guests')
    priority_group = relationship('PriorityGroup', back_populates='guests')
    pool = relationship('Pool', back_populates='guests')

    def log_event(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        eventname: str,
        **details: Optional[Dict[Any, Any]]
    ) -> None:
        """ Create event log record for guest """

        from . import log_guest_event

        log_guest_event(logger, session, self.guestname, eventname, **details)

    @property
    def is_promised(self) -> bool:
        return self.address is None

    def fetch_events(
        self,
        session: sqlalchemy.orm.session.Session,
        eventname: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        sort_field: str = 'updated',
        sort_direction: str = 'desc',
        since: Optional[str] = None,
        until: Optional[str] = None
    ) -> List['GuestEvent']:
        return GuestEvent.fetch(
            session,
            guestname=self.guestname,
            eventname=eventname,
            page=page,
            page_size=page_size,
            sort_field=sort_field,
            sort_direction=sort_direction,
            since=since,
            until=until
        )


class GuestEvent(Base):
    __tablename__ = 'guest_events'

    _id = Column(Integer(), primary_key=True)
    updated = Column(DateTime, default=datetime.datetime.utcnow)
    guestname = Column(String(250), nullable=False)
    eventname = Column(String(250), nullable=False)
    details = Column(Text())

    def __init__(
        self,
        eventname: str,
        guestname: str,
        **details: Any
    ) -> None:
        self.eventname = eventname
        self.guestname = guestname
        self.details = json.dumps(details)

    # This is not very friendly... In our code, when we access event details, we want to get the unserialized form.
    # And we want a nice name, like `details`: `event.details` should be Python-friendly, unserialized details. They
    # are read-only anyway, and we do `details = ...` just once, when we initialize the event just before inserting
    # it to the database.
    #
    # But `details` is already used for the column, and therefore it is `str`. The best solution would be to rename
    # the column (e.g. `_details` or `details_serialized`), and add `details` property for transparent unserialize.
    # TODO: another patch...
    @property
    def details_unserialized(self) -> Dict[str, Any]:
        if not self.details:
            return {}

        return cast(
            Dict[str, Any],
            json.loads(self.details)
        )

    @classmethod
    def fetch(
        cls,
        session: sqlalchemy.orm.session.Session,
        eventname: Optional[str] = None,
        guestname: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        sort_field: str = 'updated',
        sort_direction: str = 'desc',
        since: Optional[str] = None,
        until: Optional[str] = None
    ) -> List['GuestEvent']:
        query = Query.from_session(session, GuestEvent)

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
            sort_field_direction = getattr(sort_field_column, sort_direction)

        except AttributeError:
            raise gluetool.glue.GlueError('Cannot sort by {}/{}'.format(sort_field, sort_direction))

        # E.g. order_by(GuestEvent.updated.desc())
        query = query.order_by(sort_field_direction())

        if page_size is not None:
            query = query.limit(page_size)

            if page is not None:
                query = query.offset((page - 1) * page_size)

        return query.all()


class SnapshotRequest(Base):
    __tablename__ = 'snapshot_requests'

    snapshotname = Column(String(250), primary_key=True, nullable=False)
    guestname = Column(String(250), ForeignKey('guest_requests.guestname'), nullable=False)
    poolname = Column(String(250), ForeignKey('pools.poolname'), nullable=True)

    state = Column(String(250), nullable=False)

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


class MetricsProvisioningSuccess(Base):
    __tablename__ = 'metrics_provisioning_success'

    pool = Column(String(), primary_key=True)
    count = Column(Integer, nullable=False, default=0)


class MetricsFailover(Base):
    __tablename__ = 'metrics_failover'

    from_pool = Column(String(250), ForeignKey('pools.poolname'), primary_key=True)
    to_pool = Column(String(250), ForeignKey('pools.poolname'), primary_key=True)
    count = Column(Integer, default=0)
    updated = Column(DateTime, default=datetime.datetime.utcnow)


class MetricsFailoverSuccess(Base):
    __tablename__ = 'metrics_failover_success'

    from_pool = Column(String(250), ForeignKey('pools.poolname'), primary_key=True)
    to_pool = Column(String(250), ForeignKey('pools.poolname'), primary_key=True)
    count = Column(Integer, default=0)
    updated = Column(DateTime, default=datetime.datetime.utcnow)


class MetricsPolicyCalls(Base):
    __tablename__ = 'metrics_policy_calls'

    policy_name = Column(String(), primary_key=True)
    count = Column(Integer, default=0)


class MetricsPolicyCancellations(Base):
    __tablename__ = 'metrics_policy_cancellations'

    policy_name = Column(String(), primary_key=True)
    count = Column(Integer, default=0)


class MetricsPolicyRulings(Base):
    __tablename__ = 'metrics_policy_rulings'

    policy_name = Column(String(), primary_key=True)
    pool_name = Column(String(), primary_key=True)
    allowed = Column(Boolean(), primary_key=True)
    count = Column(Integer, default=0)


class PoolResourcesMetricsDimensions(enum.Enum):
    LIMITS = 'LIMITS'
    USAGE = 'USAGE'


class PoolResourcesMetrics(Base):
    """
    Metrics tracking pool resources. For each pool, two records exist, tracking two "dimensions",
    :py:attr:`PoolResourcesMetricsDimensions.LIMITS` and :py:attr:`PoolResourcesMetricsDimensions.USAGE`.
    """

    __tablename__ = 'metrics_pool_resources'

    poolname = Column(String(250), primary_key=True, nullable=False)
    dimension = Column(Enum(PoolResourcesMetricsDimensions), primary_key=True, nullable=False)

    instances = Column(BigInteger, nullable=True)
    cores = Column(BigInteger, nullable=True)
    memory = Column(BigInteger, nullable=True)
    diskspace = Column(BigInteger, nullable=True)
    snapshots = Column(BigInteger, nullable=True)

    @classmethod
    def get_by_pool(
        cls,
        session: sqlalchemy.orm.session.Session,
        poolname: str,
        dimension: PoolResourcesMetricsDimensions
    ) -> Optional['PoolResourcesMetrics']:
        """
        Retrieve a record for given ``poolname`` and ``dimension``.
        """

        return Query.from_session(session, PoolResourcesMetrics) \
            .filter(PoolResourcesMetrics.poolname == poolname) \
            .filter(PoolResourcesMetrics.dimension == dimension) \
            .one_or_none()

    @classmethod
    def get_limits_by_pool(
        cls,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> Optional['PoolResourcesMetrics']:
        """
        Retrieve a record tracking resources limits for a given ``poolname``.
        """

        return cls.get_by_pool(session, poolname, PoolResourcesMetricsDimensions.LIMITS)

    @classmethod
    def get_usage_by_pool(
        cls,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> Optional['PoolResourcesMetrics']:
        """
        Retrieve a record tracking resources usage for a given ``poolname``.
        """

        return cls.get_by_pool(session, poolname, PoolResourcesMetricsDimensions.USAGE)


class Knob(Base):
    __tablename__ = 'knobs'

    knobname = Column(String(), primary_key=True, nullable=False)
    value = Column(String(), nullable=False)


class _DB:
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        url: str,
        application_name: Optional[str] = None
    ) -> None:
        from . import KNOB_DB_POOL_MAX_OVERFLOW, KNOB_DB_POOL_SIZE, KNOB_LOGGING_DB_POOL, KNOB_LOGGING_DB_QUERIES

        self.logger = logger

        logger.info('connecting to db {}'.format(url))

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

        self._sessionmaker = sqlalchemy.orm.sessionmaker(bind=self.engine)

    @contextmanager
    def get_session(self) -> Iterator[sqlalchemy.orm.session.Session]:
        with DB._lock:
            session = self._sessionmaker()

            if self._echo_pool:
                from .metrics import DBPoolMetrics

                gluetool.log.log_dict(
                    self.logger.info,
                    'pool metrics',
                    DBPoolMetrics.load(self.logger, self, session)  # type: ignore
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
            session.close()


class DB:
    instance: Optional[_DB] = None
    _lock = threading.RLock()

    def __new__(
        cls,
        logger: gluetool.log.ContextAdapter,
        url: str,
        application_name: Optional[str] = None
    ) -> _DB:
        with DB._lock:
            if DB.instance is None:
                DB.instance = _DB(logger, url, application_name=application_name)

                # declared as class attributes only to avoid typing errors ("DB has no attribute" ...)
                # those attributes should never be used, use instance attributes only
                cls.get_session = DB.instance.get_session  # type: Callable[[], Any]
                cls.engine = DB.instance.engine  # type: sqlalchemy.engine.Engine

            return DB.instance


def _init_schema(logger: gluetool.log.ContextAdapter, db: DB, server_config: Dict[str, Any]) -> None:
    from .drivers import GuestTagsType

    # Note: the current approach of "init schema" is crappy, it basically either succeeds or fails at
    # the first conflict, skipping the rest. To avoid collisions, it must be refactored, and sooner
    # or later CLI will take over once we get full support for user accounts.
    #
    # When adding new bits, let's use a safer approach and test before adding possibly already existing
    # records.
    # Adding system and pool tags. We do not want to overwrite the existing value, only add those
    # that are missing. Artemis' default example of configuration tries to add as little as possible,
    # which means we probably don't return any tag user might have removed.
    with db.get_session() as session:
        all_tags = Query.from_session(session, GuestTag).all()

        current_tags: Dict[str, GuestTagsType] = collections.defaultdict(dict)

        for r in all_tags:
            current_tags[r.poolname][r.tag] = r.value

        def _add_tags(poolname: str, input_tags: GuestTagsType) -> None:
            for tag, value in input_tags.items():
                logger.info('  Adding {}={}'.format(tag, value))

                if tag in current_tags[poolname]:
                    logger.info('    Already exists, skipping')
                    continue

                session.add(GuestTag(
                    poolname=poolname,
                    tag=tag,
                    value=value
                ))

        # Add system-level tags
        logger.info('Adding system-level guest tags')

        _add_tags(GuestTag.SYSTEM_POOL_ALIAS, cast(GuestTagsType, server_config.get('guest_tags', {})))

        # Add pool-level tags
        for pool_config in server_config.get('pools', []):
            poolname = pool_config['name']

            logger.info('Adding pool-level guest tag for pool {}'.format(poolname))

            _add_tags(poolname, cast(GuestTagsType, pool_config.get('guest_tags', {})))

    with db.get_session() as session:
        # Insert our bootstrap users.
        def _add_user(username: str, role: UserRoles) -> None:
            logger.info('Adding user "{}" with role "{}"'.format(username, role.name))

            user = User.create(username, role)
            session.add(user)

            admin_token, user.admin_token = User.generate_token()
            provisioning_token, user.provisioning_token = User.generate_token()

            logger.info('Default admin token for user "{}" is "{}"'.format(username, admin_token))
            logger.info('Default provisioning token for user "{}" is "{}"'.format(username, provisioning_token))

        # In one of the future patches, this will get few changes:
        #
        # * create just the admin user - artemis-cli should be used to create other users
        # * accept username and token from env variables, instead of the config file
        for user_config in server_config.get('users', []):
            username = user_config['name']

            if 'role' in user_config:
                try:
                    role = UserRoles[user_config['role'].upper()]

                except KeyError:
                    raise Exception('Unknown role "{}" of user "{}"'.format(user_config['role'], username))

            else:
                role = UserRoles.USER

            _add_user(username, role)

        for key_config in server_config.get('ssh-keys', []):
            logger.info('Adding SSH key "{}", owner by {}'.format(
                key_config['name'],
                key_config['owner']
            ))

            session.add(
                SSHKey(
                    keyname=key_config['name'],
                    enabled=True,
                    ownername=key_config['owner'],
                    file=key_config['file']
                )
            )

        for priority_group_config in server_config.get('priority-groups', []):
            logger.info('Adding priority group "{}"'.format(
                priority_group_config['name']
            ))

            session.add(
                PriorityGroup(
                    name=priority_group_config['name']
                )
            )

        for pool_config in server_config.get('pools', []):
            logger.info('Adding pool "{}"'.format(pool_config['name']))

            pool_parameters = pool_config.get('parameters', {})

            if pool_config['driver'] == 'openstack':
                if 'project-domain-name' in pool_parameters and 'project-domain-id' in pool_parameters:
                    from . import Failure

                    Failure('Pool "{}" uses both project-domain-name and project-domain-id, name will be used'.format(
                        pool_config['name']
                    )).handle(logger)

            session.add(
                Pool(
                    poolname=pool_config['name'],
                    driver=pool_config['driver'],
                    parameters=json.dumps(pool_parameters)
                )
            )


def init_postgres() -> None:
    # `artemis` imports `artemis.db`, therefore `artemis.db` cannot import artemis on module-level.
    from . import KNOB_DB_URL, get_config, get_db, get_logger

    logger = get_logger()
    server_config = get_config()

    assert KNOB_DB_URL.value.startswith('postgresql://')

    db = get_db(logger)

    _init_schema(logger, db, server_config)


def init_sqlite() -> None:
    # `artemis` imports `artemis.db`, therefore `artemis.db` cannot import artemis on module-level.
    from . import KNOB_DB_URL, get_config, get_db, get_logger

    logger = get_logger()
    server_config = get_config()

    assert KNOB_DB_URL.value.startswith('sqlite:///')

    db_filepath = KNOB_DB_URL.value[10:]

    try:
        os.unlink(db_filepath)

    except OSError:
        pass

    db = get_db(logger)

    _init_schema(logger, db, server_config)
