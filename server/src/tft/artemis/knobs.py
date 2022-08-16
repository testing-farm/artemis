# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import inspect
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Callable, Dict, Generic, List, Optional, Pattern, Tuple, TypeVar, cast

import gluetool.log
import gluetool.utils
from gluetool.result import Error, Ok, Result
from sqlalchemy.orm.session import Session

if TYPE_CHECKING:
    from . import Failure
    from .drivers import PoolDriver


T = TypeVar('T')


class KnobSource(Generic[T]):
    """
    Represents one of the possible sources of a knob value. Child classes implement the actual
    "get the value" process.

    :param knob: parent knob instance.
    """

    def __init__(self, knob: 'Knob[T]') -> None:
        self.knob = knob

    def get_value(self, **kwargs: Any) -> Result[Optional[T], 'Failure']:
        """
        Acquires and returns the knob value, or ``None`` if the value does not exist. If it may exist but the process
        failed with an error, returns a :py:class:`Failure` describing the error.
        """

        raise NotImplementedError()

    def to_repr(self) -> List[str]:
        """
        Return list of string that shall be added to knob's ``repr()`` representation.
        """

        raise NotImplementedError()


class KnobSourceEnv(KnobSource[T]):
    """
    Read knob value from an environment variable.

    This is a base class for sources that read the values from the environment and provides necessary primitives.

    :param envvar: name of the environment variable.
    :param type_cast: a callback used to cast the raw string to the correct type.
    """

    def __init__(self, knob: 'Knob[T]', envvar: str) -> None:
        super().__init__(knob)

        self.envvar = envvar

    def _fetch_from_env(self, envvar: str) -> Result[Optional[T], 'Failure']:
        if envvar not in os.environ:
            return Ok(None)

        assert self.knob.cast_from_str is not None

        return Ok(
            self.knob.cast_from_str(os.environ[envvar])
        )

    def to_repr(self) -> List[str]:
        return [
            f'envvar="{self.envvar}"'
        ]


class KnobSourceEnvGlobal(KnobSourceEnv[T]):
    """
    Read knob value from an environment variable.

    :param envvar: name of the environment variable.
    :param type_cast: a callback used to cast the raw string to the correct type.
    """

    def get_value(self, **kwargs: Any) -> Result[Optional[T], 'Failure']:
        return self._fetch_from_env(self.envvar)


class KnobSourceEnvPerPool(KnobSourceEnv[T]):
    """
    Read knob value from an environment variable.

    When the parent knob is enabled to provide pool-specific values (via ``per_pool=True``),
    then the environment variable is tweaked to allow per-pool setup:

    * ``${original envvar}_${poolname}``
    * ``${original envvar}``

    :param envvar: name of the environment variable.
    :param type_cast: a callback used to cast the raw string to the correct type.
    """

    def get_value(
        self,
        *,
        poolname: Optional[str] = None,
        pool: Optional['PoolDriver'] = None,
        **kwargs: Any
    ) -> Result[Optional[T], 'Failure']:
        if poolname is not None:
            pass

        elif pool is not None:
            poolname = pool.poolname

        else:
            return Error(Failure('either pool or poolname must be specified'))

        r_value = self._fetch_from_env(f'{self.envvar}_{poolname.replace("-", "_")}')

        if r_value.is_error:
            return r_value

        value = r_value.unwrap()

        if value is not None:
            return r_value

        return self._fetch_from_env(self.envvar)


class KnobSourceDefault(KnobSource[T]):
    """
    Use the given default value as the actual value of the knob.

    :param default: the value to be presented as the knob value.
    :param default_label: if provided, it is used in documentation instead of the actual default value.
        Since the default value expression is evaluated during import, the actual value may be pointless
        from the documentation point of view.
    """

    def __init__(self, knob: 'Knob[T]', default: T, default_label: Optional[str] = None) -> None:
        super().__init__(knob)

        self.default = default
        self.default_label = default_label

    def get_value(self, **kwargs: Any) -> Result[Optional[T], 'Failure']:
        return Ok(self.default)

    def to_repr(self) -> List[str]:
        if self.default_label is None:
            return [
                f'default="{self.default}"'
            ]

        return [
            f'default="{self.default_label}" ({self.default})'
        ]


class KnobSourceDB(KnobSource[T]):
    """
    Read knob value from a database.

    Values are stored as JSON blobs, to preserve their types.

    This is a base class for sources that read the values from the database and provides necessary primitives.
    """

    def _fetch_from_db(self, session: Session, knobname: str) -> Result[Optional[T], 'Failure']:
        from . import Failure
        from .db import Knob as KnobRecord
        from .db import SafeQuery

        r = SafeQuery.from_session(session, KnobRecord) \
            .filter(KnobRecord.knobname == knobname) \
            .one_or_none()

        if r.is_error:
            return Error(Failure.from_failure(
                'Cannot fetch knob value from db',
                r.unwrap_error()
            ))

        record = r.unwrap()

        if not record:
            return Ok(None)

        return Ok(cast(T, record.value))

    def to_repr(self) -> List[str]:
        return [
            'has-db=yes'
        ]


class KnobSourceDBGlobal(KnobSourceDB[T]):
    """
    Read knob value from a database.
    """

    def get_value(  # type: ignore[override]  # match parent
        self,
        *,
        session: Session,
        **kwargs: Any
    ) -> Result[Optional[T], 'Failure']:
        return self._fetch_from_db(session, self.knob.knobname)


class KnobSourceDBPerPool(KnobSourceDB[T]):
    """
    Read knob value from a database.

    When the parent knob is enabled to provide pool-specific values (via ``per_pool=True``),
    then a special knob names are searched in the database instead of the original one:

    * ``${original knob name}:${poolname}``
    * ``${original knob name}``
    """

    def get_value(  # type: ignore[override]  # match parent
        self,
        *,
        session: Session,
        poolname: Optional[str] = None,
        pool: Optional['PoolDriver'] = None,
        **kwargs: Any
    ) -> Result[Optional[T], 'Failure']:
        if poolname is not None:
            pass

        elif pool is not None:
            poolname = pool.poolname

        else:
            return Error(Failure('either pool or poolname must be specified'))

        r_value = self._fetch_from_db(session, f'{self.knob.knobname}:{poolname}')

        if r_value.is_error:
            return r_value

        value = r_value.unwrap()

        if value is not None:
            return r_value

        return self._fetch_from_db(session, self.knob.knobname)


class KnobSourceActual(KnobSource[T]):
    """
    Use value as-is.
    """

    def __init__(self, knob: 'Knob[T]', value: T) -> None:
        super().__init__(knob)

        self.value = value

    def get_value(self, **kwargs: Any) -> Result[Optional[T], 'Failure']:
        return Ok(self.value)

    def to_repr(self) -> List[str]:
        return [
            f'actual="{self.value}"'
        ]


class KnobError(ValueError):
    def __init__(self, knob: 'Knob[T]', message: str, failure: Optional['Failure'] = None) -> None:
        super().__init__(f'Badly configured knob: {message}')

        self.knobname = knob.knobname
        self.failure = failure


class Knob(Generic[T]):
    """
    A "knob" represents a - possibly tweakable - parameter of Artemis or one of its parts. Knobs:

    * are typed values,
    * may have a default value,
    * may be given via environment variable,
    * may be stored in a database.

    Some of the knobs are not backed by a database, especially knobs needed by code establishing the database
    connections.

    The resolution order in which possible sources are checked when knob value is needed:

    1. the database, if the knob declaration specifies the database may be used.
    2. the environment variable.
    3. the given "actual" value, prossibly originating from a config file.
    4. the default value.

    A typical knob may look like this:

    .. code-block:: python3

       # As a two-state knob, `bool` is the best choice here.
       KNOB_LOGGING_JSON: Knob[bool] = Knob(
           # A knob name.
           'logging.json',

           # This knob is not backed by a database.
           has_db=False,

           # This knob does not support pool-specific values.
           per_pool=False,

           # This knob gets its value from the following environment variable.
           envvar='ARTEMIS_LOG_JSON',

           # This knob gets its value when created. Note that this is *very* similar to the default value,
           # but the default value should stand out as the default, while this parameter represents e.g.
           # value read from a configuration file, and as such may be left unspecified - then the default
           # would be used.
           actual=a_yaml_config_file['logging']['json'],

           # The default value - note that it is properly typed.
           default=True,

           # If the knob is backed by the database or environment variable, it is necessary to provide a callback
           # that casts the raw string value to the proper type.
           cast_from_str=gluetool.utils.normalize_bool_option
       )

    The knob can be used in a following way:

    .. code-block:: python3

       >>> print(KNOB_LOGGING_JSON.get_value())
       True
       >>>

    In the case of knobs not backed by the database, the value can be deduced when the knob is declared, and it is then
    possible to use a shorter form:

    .. code-block:: python3

       >>> print(KNOB_LOGGING_JSON.value)
       True
       >>>

    :param knobname: name of the knob. It is used for presentation and as a key when the database is involved.
    :param has_db: if set, the value may also be stored in the database.
    :param per_pool: if set, the knob may provide pool-specific values.
    :param envvar: if set, it is the name of the environment variable providing the value.
    :param actual: if set, it is the currently known value, e.g. provided by a config file.
    :param default: if set, it is used as a default value.
    :param default_label: if provided, it is used in documentation instead of the actual default value.
        Since the default value expression is evaluated during import, the actual value may be pointless
        from the documentation point of view.
    :param cast_from_str: a callback used to cast the raw string value to the correct type. Required when ``envvar``
        or ``has_db`` is set.
    """

    #: All known knobs.
    ALL_KNOBS: Dict[str, 'Knob[Any]'] = {}

    #: Collect all known ``Knob`` instances that are backed by the DB.
    DB_BACKED_KNOBS: Dict[str, 'Knob[Any]'] = {}

    #: List of patterns matching knob names that belong to knobs with per-pool capability. These names cannot be
    #: used for normal knobs.
    RESERVED_PATTERNS: List[Pattern[str]] = [
        re.compile(r'^([a-z\-.]+):.+$')
    ]

    def __init__(
        self,
        knobname: str,
        help: str,
        has_db: bool = True,
        per_pool: bool = False,
        envvar: Optional[str] = None,
        actual: Optional[T] = None,
        default: Optional[T] = None,
        default_label: Optional[str] = None,
        cast_from_str: Optional[Callable[[str], T]] = None
    ) -> None:
        self.knobname = knobname
        self.help = inspect.cleandoc(help)

        self._sources: List[KnobSource[T]] = []

        self.per_pool = per_pool

        self.cast_from_str = cast_from_str

        Knob.ALL_KNOBS[knobname] = self

        if has_db:
            # has_db means it's possible to change the knob via API, which means artemis-cli will need
            # to convert user input to proper type.
            if not cast_from_str:
                raise KnobError(self, 'has_db requested but no cast_from_str.')

            if per_pool:
                self._sources.append(KnobSourceDBPerPool(self))

                Knob.ALL_KNOBS[f'{knobname}:$poolname'] = self

                Knob.DB_BACKED_KNOBS[knobname] = self
                Knob.DB_BACKED_KNOBS[f'{knobname}:$poolname'] = self

            else:
                self._sources.append(KnobSourceDBGlobal(self))

                Knob.DB_BACKED_KNOBS[knobname] = self

        if envvar is not None:
            if not cast_from_str:
                raise KnobError(self, 'envvar requested but no cast_from_str.')

            if per_pool:
                self._sources.append(KnobSourceEnvPerPool(self, envvar))

            else:
                self._sources.append(KnobSourceEnvGlobal(self, envvar))

        if actual is not None:
            self._sources.append(KnobSourceActual(self, actual))

        if default is not None:
            self._sources.append(KnobSourceDefault(self, default, default_label=default_label))

        if not self._sources:
            raise KnobError(
                self,
                'no source specified - no DB, envvar, actual nor default value.'
            )

        # If the knob isn't backed by a database, it should be possible to deduce its value *now*,
        # as it depends on envvar, actual or default value. For such knobs, we provide a shortcut,
        # easy-to-use `value` attribute - no `Result`, no `unwrap()` - given the possible sources,
        # it should never fail to get a value from such sources.
        #
        # If the knob *is* backed by a database, it may still have other sources - if that's the case,
        # we can deduce so called "static" value. This would be a value used when there's no record
        # in DB for this knob, and we can use it when listing knobs as its current value, until overwritten
        # by a DB record. We must skip sources that deal with DB or per-pool-capable sources - these
        # are dynamic, their output depends on inputs (like pool name...).

        def _get_static_value(skip_db: bool = False, skip_per_pool: bool = False) -> T:
            value, failure = self._get_value(skip_db=skip_db, skip_per_pool=skip_per_pool)

            # If we fail to get value from envvar/default sources, then something is wrong. Maybe there's
            # just the envvar source, no default one, and environment variable is not set? In any case,
            # this sounds like a serious bug.
            if value is None:
                raise KnobError(
                    self,
                    'no DB, yet other sources do not provide value! To fix, add an envvar, actual or default value.',
                    failure=failure
                )

            return value

        if len(self._sources) > 1:
            self.static_value: T = _get_static_value(skip_db=True, skip_per_pool=True)

        if not has_db and not per_pool:
            self.value: T = _get_static_value()
            self.static_value = self.value

    def __repr__(self) -> str:
        traits: List[str] = []

        if self.per_pool:
            traits += ['per-pool=yes']

        if self.cast_from_str:
            traits += [f'cast-from-str={self.cast_from_str.__name__}']

        traits += sum((source.to_repr() for source in self._sources), [])

        return f'<Knob: {self.knobname}: {" ".join(traits)}>'

    def _get_value(
        self,
        skip_db: bool = False,
        skip_per_pool: bool = False,
        **kwargs: Any
    ) -> Tuple[Optional[T], Optional['Failure']]:
        """
        The core method for getting the knob value. Returns two items:

        * the value, or ``None`` if the value was not found.
        * optional :py:class:`Failure` instance if the process failed because of an error.
        """

        for source in self._sources:
            if skip_db and isinstance(source, KnobSourceDB):
                continue

            if skip_per_pool and isinstance(source, (KnobSourceEnvPerPool, KnobSourceDBPerPool)):
                continue

            r = source.get_value(**kwargs)

            if r.is_error:
                return None, r.unwrap_error()

            value = r.unwrap()

            if value is None:
                continue

            return value, None

        return None, None

    def get_value(self, **kwargs: Any) -> Result[T, 'Failure']:
        """
        Returns either the knob value, of :py:class:`Failure` instance describing the error encountered, including
        the "value does not exist" state.

        All keyword arguments are passed down to code handling each different sources.
        """

        value, failure = self._get_value(**kwargs)

        if value is not None:
            return Ok(value)

        if failure:
            return Error(failure)

        from . import Failure

        return Error(Failure('Cannot fetch knob value'))

    @property
    def cast_name(self) -> Optional[str]:
        """
        Return a name representing the casting function of a this knob.

        Handles some corner cases and errors transparently.
        """

        # A knob that can be modified over API *must* have a casting function...
        if self.cast_from_str is None:
            return None

        if self.cast_from_str is gluetool.utils.normalize_bool_option:
            return 'bool'

        return self.cast_from_str.__name__

    @staticmethod
    def get_per_pool_parent(logger: gluetool.log.ContextAdapter, knobname: str) -> Optional['Knob[Any]']:
        """
        For a given knobname - which belongs to a knob with per-pool capability - find its "parent" knob.

        Per-pool knobs don't have 1:1 mapping between a Python :py:class:`Knob` instance and its DB record.
        But the "parent" knob, the one actually declared somewhere in the source, can be found by name
        after stripping the pool name from the given knob name.
        """

        for pattern in Knob.RESERVED_PATTERNS:
            match = pattern.match(knobname)

            if match is None:
                continue

            parent_knobname = match.group(1)

            if parent_knobname not in Knob.DB_BACKED_KNOBS:
                return None

            return Knob.DB_BACKED_KNOBS[parent_knobname]

        return None


KNOB_LOGGING_LEVEL: Knob[int] = Knob(
    'logging.level',
    """
    Level of logging. Accepted values are Python logging levels as defined by Python's
    https://docs.python.org/3.7/library/logging.html#levels[logging subsystem].
    """,
    has_db=False,
    envvar='ARTEMIS_LOG_LEVEL',
    cast_from_str=lambda s: logging._nameToLevel.get(s.strip().upper(), logging.INFO),
    default=logging.INFO)

KNOB_LOGGING_JSON: Knob[bool] = Knob(
    'logging.json',
    'If enabled, Artemis would emit log messages as JSON mappings.',
    has_db=False,
    envvar='ARTEMIS_LOG_JSON',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_CONFIG_DIRPATH: Knob[str] = Knob(
    'config.dirpath',
    'Path to a directory with configuration.',
    has_db=False,
    envvar='ARTEMIS_CONFIG_DIR',
    cast_from_str=lambda s: os.path.expanduser(s.strip()),
    default=os.getcwd(),
    default_label='$CWD'
)

KNOB_BROKER_URL: Knob[str] = Knob(
    'broker.url',
    """
    Broker URL. See https://pika.readthedocs.io/en/1.2.0/modules/parameters.html#pika.connection.URLParameters
    for full list of connection parameters that can be specified via URL.
    """,
    has_db=False,
    envvar='ARTEMIS_BROKER_URL',
    cast_from_str=str,
    default='amqp://guest:guest@127.0.0.1:5672'
)

KNOB_CACHE_URL: Knob[str] = Knob(
    'cache.url',
    'Cache URL.',
    has_db=False,
    envvar='ARTEMIS_CACHE_URL',
    cast_from_str=str,
    default='redis://127.0.0.1:6379'
)

KNOB_BROKER_CONFIRM_DELIVERY: Knob[bool] = Knob(
    'broker.confirm-delivery',
    """
    If set, every attempt to enqueue a messages will require a confirmation from the broker.
    """,
    has_db=False,
    envvar='ARTEMIS_BROKER_CONFIRM_DELIVERY',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_DB_URL: Knob[str] = Knob(
    'db.url',
    'Database URL.',
    has_db=False,
    envvar='ARTEMIS_DB_URL',
    cast_from_str=str
)

KNOB_VAULT_PASSWORD: Knob[Optional[str]] = Knob(
    'vault.password',
    'A password for decrypting files protected by Ansible Vault. Takes precedence over ARTEMIS_VAULT_PASSWORD_FILE.',
    has_db=False,
    envvar='ARTEMIS_VAULT_PASSWORD',
    cast_from_str=str,
    default=''  # "empty" password, not set
)

KNOB_VAULT_PASSWORD_FILEPATH: Knob[str] = Knob(
    'vault.password.filepath',
    'Path to a file with a password for decrypting files protected by Ansible Vault.',
    has_db=False,
    envvar='ARTEMIS_VAULT_PASSWORD_FILE',
    cast_from_str=lambda s: os.path.expanduser(s.strip()),
    default=os.path.expanduser('~/.vault_password'),
    default_label='$HOME/.vault_password'
)

KNOB_LOGGING_DB_QUERIES: Knob[bool] = Knob(
    'logging.db.queries',
    'When enabled, Artemis would log SQL queries.',
    has_db=False,
    envvar='ARTEMIS_LOG_DB_QUERIES',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_DB_SLOW_QUERIES: Knob[bool] = Knob(
    'logging.db.slow-queries',
    """
    When enabled, Artemis would log "slow" queries - queries whose execution took longer than
    ARTEMIS_LOG_DB_SLOW_QUERY_THRESHOLD seconds.
    """,
    # Never change it to `True`: querying DB while logging another DB query sounds too much like "endless recursion".
    has_db=False,
    envvar='ARTEMIS_LOG_DB_SLOW_QUERIES',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_DB_SLOW_QUERY_THRESHOLD: Knob[float] = Knob(
    'logging.db.slow-query-threshold',
    'Minimal time, in seconds, spent executing a query for it to be reported as "slow".',
    # Never change it to `True`: querying DB while logging another DB query sounds too much like "endless recursion".
    has_db=False,
    envvar='ARTEMIS_LOG_DB_SLOW_QUERY_THRESHOLD',
    cast_from_str=float,
    default=10.0
)


KNOB_LOGGING_DB_POOL: Knob[str] = Knob(
    'logging.db.pool',
    'When enabled, Artemis would log events related to database connection pool.',
    has_db=False,
    envvar='ARTEMIS_LOG_DB_POOL',
    cast_from_str=str,
    default='no'
)

KNOB_DB_POOL_SIZE: Knob[int] = Knob(
    'db.pool.size',
    'Size of the DB connection pool.',
    has_db=False,
    envvar='ARTEMIS_DB_POOL_SIZE',
    cast_from_str=int,
    default=20
)

KNOB_DB_POOL_MAX_OVERFLOW: Knob[int] = Knob(
    'db.pool.max-overflow',
    'Maximum size of connection pool overflow.',
    has_db=False,
    envvar='ARTEMIS_DB_POOL_MAX_OVERFLOW',
    cast_from_str=int,
    default=10
)

KNOB_POOL_ENABLED: Knob[bool] = Knob(
    'pool.enabled',
    'If unset for a pool, the given pool is ignored by Artemis in general.',
    has_db=True,
    per_pool=True,
    envvar='ARTEMIS_POOL_ENABLED',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_WORKER_PROCESS_METRICS_ENABLED: Knob[bool] = Knob(
    'worker.metrics.process.enabled',
    'If enabled, various metrics related to worker processes would be collected.',
    has_db=False,
    per_pool=False,
    envvar='ARTEMIS_WORKER_PROCESS_METRICS_ENABLED',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK: Knob[int] = Knob(
    'worker.metrics.process.update-tick',
    'How often, in seconds, should workers update their process metrics cache.',
    has_db=False,
    per_pool=False,
    envvar='ARTEMIS_WORKER_PROCESS_METRICS_UPDATE_TICK',
    cast_from_str=int,
    default=60
)

KNOB_WORKER_PROCESS_METRICS_TTL: Knob[int] = Knob(
    'worker.metrics.process.ttl',
    'How long, in seconds, should worker process metrics remain in cache.',
    has_db=False,
    per_pool=False,
    envvar='ARTEMIS_WORKER_PROCESS_METRICS_TTL',
    cast_from_str=int,
    default=120
)

KNOB_WORKER_TRAFFIC_METRICS_ENABLED: Knob[bool] = Knob(
    'worker.metrics.traffic.enabled',
    'If enabled, various metrics related to tasks and requests would be collected.',
    has_db=False,
    per_pool=False,
    envvar='ARTEMIS_WORKER_TRAFFIC_METRICS_ENABLED',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=True
)

KNOB_WORKER_TRAFFIC_METRICS_TTL: Knob[int] = Knob(
    'worker.metrics.traffic.ttl',
    'How long, in seconds, should worker traffic metrics remain in cache.',
    has_db=False,
    per_pool=False,
    envvar='ARTEMIS_WORKER_TRAFFIC_METRICS_TTL',
    cast_from_str=int,
    # The value should be comparable to how long tasks can take, which depends on resources available to workers.
    default=600
)

KNOB_DEPLOYMENT: Knob[str] = Knob(
    'deployment.name',
    'Optional name of the Artemis deployment (e.g. "production-01" or "development").',
    has_db=False,
    envvar='ARTEMIS_DEPLOYMENT',
    cast_from_str=str,
    default='undefined-deployment'
)

KNOB_COMPONENT: Knob[str] = Knob(
    'deployment.component',
    'Optional name of the Artemis component (e.g. "worker", "api", etc.).',
    has_db=False,
    envvar='ARTEMIS_COMPONENT',
    cast_from_str=str,
    default='undefined-component'
)

KNOB_DEPLOYMENT_ENVIRONMENT: Knob[str] = Knob(
    'deployment.environment',
    'Optional environment of the Artemis deployment (e.g. "production" or "staging").',
    has_db=False,
    envvar='ARTEMIS_DEPLOYMENT_ENVIRONMENT',
    cast_from_str=str,
    default='undefined-deployment-environment'
)

KNOB_SENTRY_DSN: Knob[Optional[str]] = Knob(
    'sentry.dsn',
    'Sentry DSN.',
    has_db=False,
    envvar='ARTEMIS_SENTRY_DSN',
    cast_from_str=str,
    # TODO: Knob cannot use None as actual default value. Needs a fix.
    default='undefined'
)

KNOB_SENTRY_BASE_URL: Knob[Optional[str]] = Knob(
    'sentry.base-url',
    'Sentry base URL, for nice event URLs in logs.',
    has_db=False,
    envvar='ARTEMIS_SENTRY_BASE_URL',
    cast_from_str=str,
    # TODO: Knob cannot use None as actual default value. Needs a fix.
    default='undefined'
)

KNOB_SENTRY_DISABLE_CERT_VERIFICATION: Knob[bool] = Knob(
    'sentry.disable-cert-verification',
    'When enabled, Artemis would disable HTTPS certificate verification when submitting to Sentry.',
    has_db=False,
    envvar='ARTEMIS_SENTRY_DISABLE_CERT_VERIFICATION',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_SENTRY: Knob[bool] = Knob(
    'logging.sentry',
    'When enabled, Artemis would log more Sentry-related debug info.',
    has_db=False,
    envvar='ARTEMIS_LOG_SENTRY',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_LOGGING_SINGLETON_LOCKS: Knob[bool] = Knob(
    'logging.singleton-locks',
    'When enabled, Artemis would log more debuginfo related to singleton task locking.',
    has_db=False,
    envvar='ARTEMIS_LOG_SINGLETON_LOCKS',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_TEMPLATE_VARIABLE_DELIMITERS: Knob[str] = Knob(
    'template.delimiters.variable',
    """
    Variable delimiters for various Jinja2 templates.
    Useful when Artemis deployment renders templates that Artemis itself is supposed to render.
    The value shall be comma-separated list of two strings, the start and end delimiter
    of a variable to render in a template.
    """,
    has_db=False,
    envvar='ARTEMIS_TEMPLATE_VARIABLE_DELIMITERS',
    cast_from_str=str,
    default='{{,}}'
)


def get_vault_password() -> str:
    password = KNOB_VAULT_PASSWORD.value

    if password:
        return password

    with open(KNOB_VAULT_PASSWORD_FILEPATH.value) as f:
        return f.read()
