import dataclasses
import datetime
import enum
import hashlib
import json
import logging
import os
import secrets
import threading

from contextlib import contextmanager

import gluetool.glue
import sqlalchemy
import sqlalchemy.ext.declarative
from sqlalchemy import BigInteger, Column, ForeignKey, String, Boolean, Enum, Text, Integer, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.orm.query import Query as _Query

from typing import cast, Any, Callable, Dict, Generic, Iterator, List, Optional, Tuple, Type, TypeVar, Union
import gluetool.log


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
T = TypeVar('T')


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


@dataclasses.dataclass
class DBPoolMetrics:
    ''' Class for storing DB pool metrics '''
    size: int = 0
    checked_in_connections: int = 0
    checked_out_connections: int = 0
    current_overflow: int = 0


# SQLAlchemy defaults
DEFAULT_SQLALCHEMY_POOL_SIZE = 20
DEFAULT_SQLALCHEMY_MAX_OVERFLOW = 10


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

    @classmethod
    def fetch(
        cls,
        session: sqlalchemy.orm.session.Session,
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


class Metrics(Base):
    __tablename__ = 'metrics'

    _id = Column(Integer, primary_key=True)
    count = Column(Integer, default=0)
    updated = Column(DateTime, default=datetime.datetime.utcnow)


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


class DB:
    instance: 'Optional[__DB]' = None
    _lock = threading.RLock()

    class __DB:
        def __init__(
            self,
            logger: gluetool.log.ContextAdapter,
            url: str
        ) -> None:
            self.logger = logger

            logger.info('connecting to db {}'.format(url))

            if os.getenv('ARTEMIS_LOG_DB_QUERIES', None) == 'yes':
                gluetool.log.Logging.configure_logger(logging.getLogger('sqlalchemy.engine'))

            self._echo_pool: Union[str, bool] = False
            if 'ARTEMIS_LOG_DB_POOL' in os.environ:
                if os.environ['ARTEMIS_LOG_DB_POOL'].lower() == 'debug':
                    self._echo_pool = 'debug'

                elif os.environ['ARTEMIS_LOG_DB_POOL'].lower() == 'yes':
                    self._echo_pool = gluetool.utils.normalize_bool_option(os.environ['ARTEMIS_LOG_DB_POOL'])

            # We want a nice way how to change default for pool size and maximum overflow for PostgreSQL
            if url.startswith('postgresql://'):
                pool_size = os.getenv('ARTEMIS_SQLALCHEMY_POOL_SIZE', DEFAULT_SQLALCHEMY_POOL_SIZE)
                max_overflow = os.getenv('ARTEMIS_SQLALCHEMY_MAX_OVERFLOW', DEFAULT_SQLALCHEMY_MAX_OVERFLOW)

                gluetool.log.log_dict(logger.info, 'sqlalchemy create_engine parameters', {
                    'echo_pool': self._echo_pool,
                    'pool_size': pool_size,
                    'max_overflow': max_overflow
                })

                self._engine = sqlalchemy.create_engine(
                    url,
                    echo_pool=self._echo_pool,
                    pool_size=pool_size,
                    max_overflow=max_overflow
                )

            # SQLite does not support altering pool size nor max overflow
            else:
                self._engine = sqlalchemy.create_engine(url)

            self._sessionmaker = sqlalchemy.orm.sessionmaker(bind=self._engine)

        def pool_metrics(self) -> DBPoolMetrics:
            with DB._lock:
                # Some pools, like NullPool, don't really pool connections, therefore they have no concept
                # of these metrics.
                if hasattr(self._engine.pool, 'size'):
                    return DBPoolMetrics(
                        size=self._engine.pool.size(),
                        checked_in_connections=self._engine.pool.checkedin(),
                        checked_out_connections=self._engine.pool.checkedout(),
                        current_overflow=self._engine.pool.overflow()
                    )

                else:
                    return DBPoolMetrics(
                        size=-1,
                        checked_in_connections=-1,
                        checked_out_connections=-1,
                        current_overflow=-1
                    )

        @contextmanager
        def get_session(self) -> Iterator[sqlalchemy.orm.session.Session]:
            with DB._lock:
                if self._echo_pool:
                    gluetool.log.log_dict(
                        self.logger.info,
                        'pool metrics',
                        self.pool_metrics()
                    )

                session = self._sessionmaker()

            try:
                yield session

                session.commit()

            except Exception:
                session.rollback()

                raise

            finally:
                session.close()

    def __new__(
        cls,
        logger: gluetool.log.ContextAdapter,
        url: str
    ) -> '__DB':
        with DB._lock:
            if DB.instance is None:
                DB.instance = DB.__DB(logger, url)

                # declared as class attributes only to avoid typing errors ("DB has no attribute" ...)
                # those attributes should never be used, use instance attributes only
                cls.get_session = DB.instance.get_session  # type: Callable[[], Any]
                cls.pool_metrics = DB.instance.pool_metrics  # type: Callable[[], DBPoolMetrics]
                cls._engine = DB.instance._engine  # type: sqlalchemy.engine.Engine

            return DB.instance


def _init_schema(logger: gluetool.log.ContextAdapter, db: DB, server_config: Dict[str, Any]) -> None:
    with db.get_session() as session:
        for user_config in server_config.get('users', []):
            logger.info('Adding user "{}"'.format(user_config['name']))

            session.add(
                User(username=user_config['name'])
            )

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

        logger.info('Adding metrics counter')
        session.add(Metrics())


def init_postgres() -> None:
    # `artemis` imports `artemis.db`, therefore `artemis.db` cannot import artemis on module-level.
    from . import get_logger, get_config, get_db_url, get_db

    logger = get_logger()
    server_config = get_config()

    db_url = get_db_url()

    assert db_url.startswith('postgresql://')

    db = get_db(logger)

    _init_schema(logger, db, server_config)


def init_sqlite() -> None:
    # `artemis` imports `artemis.db`, therefore `artemis.db` cannot import artemis on module-level.
    from . import get_logger, get_config, get_db_url, get_db

    logger = get_logger()
    server_config = get_config()

    db_url = get_db_url()

    assert db_url.startswith('sqlite:///')

    db_filepath = db_url[10:]

    try:
        os.unlink(db_filepath)

    except OSError:
        pass

    db = get_db(logger)

    _init_schema(logger, db, server_config)
