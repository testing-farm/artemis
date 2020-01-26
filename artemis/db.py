import json
import logging
import os

from contextlib import contextmanager

import sqlalchemy
import sqlalchemy.ext.declarative
from sqlalchemy import Column, ForeignKey, String, Boolean, Text, Integer
from sqlalchemy.orm import relationship

from typing import cast, Any, Dict, Iterator
import gluetool.log

# SQLAlchemy defaults
DEFAULT_SQLALCHEMY_POOL_SIZE = 20
DEFAULT_SQLALCHEMY_MAX_OVERFLOW = 10

Base = sqlalchemy.ext.declarative.declarative_base()


class User(Base):
    __tablename__ = 'users'

    username = Column(String(250), primary_key=True, nullable=False)

    sshkeys = relationship('SSHKey', back_populates='owner')
    guests = relationship('GuestRequest', back_populates='owner')


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

        import artemis

        return cast(
            Dict[str, str],
            artemis.get_vault().load(self.file)
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

    owner = relationship('User', back_populates='guests')
    ssh_key = relationship('SSHKey', back_populates='guests')
    priority_group = relationship('PriorityGroup', back_populates='guests')
    pool = relationship('Pool', back_populates='guests')


class DB:
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        url: str
    ) -> None:
        logger.info('connecting to db {}'.format(url))

        if os.getenv('ARTEMIS_LOG_DB_QUERIES', None):
            gluetool.log.Logging.configure_logger(logging.getLogger('sqlalchemy.engine'))

        # We want a nice way how to change default for pool size and maximum overflow for PostgreSQL
        if url.startswith('postgresql://'):
            pool_size = os.getenv('ARTEMIS_SQLALCHEMY_POOL_SIZE', DEFAULT_SQLALCHEMY_POOL_SIZE)
            max_overflow = os.getenv('ARTEMIS_SQLALCHEMY_MAX_OVERFLOW', DEFAULT_SQLALCHEMY_MAX_OVERFLOW)

            gluetool.log.log_dict(logger.info, 'sqlalchemy create_engine parameters', {
                'pool_size': pool_size,
                'max_overflow': max_overflow
            })

            self._engine = sqlalchemy.create_engine(url, pool_size=pool_size, max_overflow=max_overflow)

        # SQLite does not support altering pool size nor max overflow
        else:
            self._engine = sqlalchemy.create_engine(url)

        self._sessionmaker = sqlalchemy.orm.sessionmaker(bind=self._engine)

    @contextmanager
    def get_session(self) -> Iterator[sqlalchemy.orm.session.Session]:
        session = self._sessionmaker()

        try:
            yield session

            session.commit()

        except Exception:
            session.rollback()

            raise


def _init_schema(logger: gluetool.log.ContextAdapter, db: DB, server_config: Dict[str, Any]) -> None:
    Base.metadata.create_all(db._engine)

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

            session.add(
                Pool(
                    poolname=pool_config['name'],
                    driver=pool_config['driver'],
                    parameters=json.dumps(pool_config.get('parameters', {}))
                )
            )


def init_postgres() -> None:
    # artemis imports artemis.db, therefore artemis.db cannot import artemis on module-level.
    import artemis

    logger = artemis.get_logger()
    server_config = artemis.get_config()

    db_url = artemis.get_db_url()

    assert db_url.startswith('postgresql://')

    db = artemis.get_db(logger)

    _init_schema(logger, db, server_config)


def init_sqlite() -> None:
    # artemis imports artemis.db, therefore artemis.db cannot import artemis on module-level.
    import artemis

    logger = artemis.get_logger()
    server_config = artemis.get_config()

    db_url = artemis.get_db_url()

    assert db_url.startswith('sqlite:///')

    db_filepath = db_url[10:]

    try:
        os.unlink(db_filepath)

    except OSError:
        pass

    db = artemis.get_db(logger)

    _init_schema(logger, db, server_config)
