import contextvars
import functools
import json
import logging
import os
import traceback as _traceback
import urllib.parse
from types import FrameType, TracebackType
from typing import Any, Callable, Dict, Generator, Generic, List, NoReturn, Optional, Tuple, TypeVar, Union, cast

import dramatiq
import dramatiq.brokers.rabbitmq
import dramatiq.brokers.stub
import dramatiq.middleware.age_limit
import dramatiq.middleware.callbacks
import dramatiq.middleware.shutdown
import dramatiq.middleware.time_limit
import dramatiq.rate_limits.backends
import dramatiq.rate_limits.concurrent
import gluetool.log
import gluetool.sentry
import gluetool.utils
import jinja2.defaults
import jinja2_ansible_filters.core_filters
import periodiq
import pkg_resources
import redis
import ruamel.yaml
import ruamel.yaml.compat
import sqlalchemy.orm.session
import stackprinter
from gluetool.result import Error, Ok, Result
from mypy_extensions import VarArg
from sqlalchemy.orm.session import Session

__VERSION__ = pkg_resources.get_distribution('tft-artemis').version


# Install additional Jinja2 filters. This must be done before we call `render_template` for the first
# time, because Jinja2 reuses anonymous environments.

jinja2.defaults.DEFAULT_FILTERS.update(
    jinja2_ansible_filters.core_filters.FilterModule().filters()
)

# Now we can import our stuff without any fear we'd miss DEFAULT_FILTERS update
from . import db as artemis_db  # noqa: E402
from . import middleware as artemis_middleware  # noqa: E402
from . import vault as artemis_vault  # noqa: E402
from .environment import Environment  # noqa: E402

stackprinter.set_excepthook(
    style='darkbg2',
    source_lines=7,
    show_signature=True,
    show_vals='all',
    reverse=False,
    add_summary=False
)


ExceptionInfoType = Union[
    # returned by sys.exc_info()
    Tuple[
        Optional[type],
        Optional[BaseException],
        Optional[TracebackType]
    ],

    # this is way of saying "nothing happened, everything's fine"
    Tuple[
        None,
        None,
        None
    ]
]

# Type variable used in generic types
T = TypeVar('T')

FailureDetailsType = Dict[str, Any]


# Gluetool Sentry instance
gluetool_sentry = gluetool.sentry.Sentry()


def format_struct_as_yaml(data: Any) -> str:
    stream = ruamel.yaml.compat.StringIO()

    YAML = gluetool.utils.YAML()

    ruamel.yaml.scalarstring.walk_tree(data)

    YAML.dump(data, stream)

    return stream.getvalue()


def process_output_to_str(output: gluetool.utils.ProcessOutput, stream: str = 'stdout') -> Optional[str]:
    """
    A helper working around Gluetool issue: it still supports Python 2, which makes its
    :py:class:`gluetool.utils.ProcessOutput` a bit weird when it comes to types: type of
    both ``stdout`` and ``stderr`` is supposedly ``str``, but the actual value **may** be
    ``bytes`` too.
    """

    assert stream in ('stdout', 'stderr')

    stream_content = getattr(output, stream)

    if stream_content is None:
        return None

    if isinstance(stream_content, str):
        return stream_content

    return cast(str, stream_content.decode('utf-8'))


class Failure:
    """
    Bundles exception related info.

    :param tuple exc_info: Exception information as returned by :py:func:`sys.exc_info`.

    :ivar Exception exception: Shortcut to ``exc_info[1]``, if available, or ``None``.
    :ivar tuple exc_info: Exception information as returned by :py:func:`sys.exc_info`.
    :ivar str sentry_event_id: If set, the failure was reported to the Sentry under this ID.
    :ivar dict details: Additional details about the exception.
    """

    def __init__(
        self,
        message: str,
        exc_info: Optional[ExceptionInfoType] = None,
        traceback: Optional[_traceback.StackSummary] = None,
        caused_by: Optional['Failure'] = None,
        sentry: Optional[bool] = True,
        recoverable: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional[Environment] = None,
        **details: Any
    ):
        self.message = message
        self.exc_info = exc_info
        self.details = details

        self.sentry = sentry
        self.submited_to_sentry: bool = False
        self.sentry_event_id: Optional[str] = None
        self.sentry_event_url: Optional[str] = None

        self.exception: Optional[BaseException] = None
        self.traceback: Optional[_traceback.StackSummary] = None

        self.caused_by = caused_by

        self.recoverable = recoverable

        if scrubbed_command:
            self.details['scrubbed_command'] = scrubbed_command

        if command_output:
            self.details['command_output'] = command_output

        if environment:
            self.details['environment'] = environment

        if exc_info:
            self.exception = exc_info[1]

            # This is what `traceback.extract_tb` does, but `extract_tb` does not let us save frame locals,
            # and we would like to see them, at least in Sentry.
            self.traceback = _traceback.StackSummary.extract(
                cast(
                    Generator[Tuple[FrameType, int], None, None],
                    _traceback.walk_tb(exc_info[2])
                ),
                capture_locals=True
            )

        if traceback:
            self.traceback = traceback

        if self.traceback is None:
            self.traceback = _traceback.extract_stack()

    @classmethod
    def from_exc(
        self,
        message: str,
        exc: Exception,
        caused_by: Optional['Failure'] = None,
        recoverable: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional[Environment] = None,
        **details: Any
    ):
        # type: (...) -> Failure

        return Failure(
            message,
            exc_info=(
                exc.__class__,
                exc,
                exc.__traceback__
            ),
            caused_by=caused_by,
            recoverable=recoverable,
            scrubbed_command=scrubbed_command,
            command_output=command_output,
            environment=environment,
            **details
        )

    def update(
        self,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional[Environment] = None,
        **details: Any
    ) -> None:
        self.details.update(details)

        if scrubbed_command:
            self.details['scrubbed_command'] = scrubbed_command

        if command_output:
            self.details['command_output'] = command_output

        if environment:
            self.details['environment'] = environment

    @classmethod
    def _exception_details(
        cls,
        exc: BaseException,
        scrubbed_command: Optional[List[str]]
    ) -> Dict[str, str]:
        # Special handling of GlueCommandError - when logged, it reports the full command,
        # possibly revealing credentials and other sensitive details.
        #
        # So, we can either use a scrubbed command we already have, or, if this information
        # was not provided when creating this failure, we construct our own, very dummy, by
        # logging just the command and dropping the rest.
        #
        # It would be nice to test this *before* logging, e.g. when running static analysis
        # of Artemis sources.
        if isinstance(exc, gluetool.glue.GlueCommandError):
            if scrubbed_command is None:
                scrubbed_command = [exc.cmd[0], '<scrubbed...>']

            return {
                'instance': 'Command "{}" failed with exit code {}'.format(
                    ' '.join(scrubbed_command),
                    exc.output.exit_code
                ),
                'type': 'GlueCommandError'
            }

        return {
            'instance': str(exc),
            'type': str(type(exc))
        }

    def get_event_details(self) -> Dict[str, Any]:
        """
        Returns a mapping of failure details, suitable for storing in DB as a guest event details.
        """

        event_details = self.details.copy()

        event_details['message'] = self.message
        event_details['recoverable'] = self.recoverable

        # We don't want command or its output in the event details - hard to serialize, full of secrets, etc.
        event_details.pop('command_output', None)
        event_details.pop('scrubbed_command', None)

        # Guestname will be provided by event instance itself, no need to parse it as event details
        event_details.pop('guestname', None)

        if 'environment' in event_details:
            event_details['environment'] = event_details['environment'].serialize_to_json()

        if self.caused_by:
            event_details['caused_by'] = self.caused_by.get_event_details()

        return event_details

    @classmethod
    def _get_sentry_stack_info(cls, frames: _traceback.StackSummary) -> Dict[str, Any]:
        """
        Based on Raven's ``get_stack_info``. Because Raven is quite outdated, we need to convert
        the traceback to a format Sentry accepts. The original method cannot deal with ``FrameSummary``
        objects used by Python 3.5+, it understands only the old frame objects, witg ``f_*`` attributes.
        """

        from raven.utils.stacks import get_lines_from_file, slim_frame_data

        result = []
        for frame in frames:
            lineno = frame.lineno
            filename = frame.filename
            function = frame.name
            line = frame.line

            frame_result: Dict[str, Union[int, str, Dict[str, str], None]] = {
                'abs_path': filename,
                'filename': os.path.relpath(filename, os.getcwd()),
                'module': None,
                'function': function or '<unknown>',
                'lineno': lineno,
            }

            if line is not None:
                # Lines are indexed from 0, but human representation starts with 1: "1st line".
                # Hence the decrement.
                pre_context, context_line, post_context = get_lines_from_file(filename, lineno - 1, 5)

                frame_result.update({
                    'pre_context': pre_context,
                    'context_line': context_line,
                    'post_context': post_context,
                })

            if frame.locals:
                frame_result['vars'] = frame.locals

            result.append(frame_result)

        stackinfo = {
            'frames': slim_frame_data(result),
        }

        return stackinfo

    def get_sentry_details(self) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """
        Returns three mappings, data, tags and extra, accepted by Sentry as issue details.
        """

        data: Dict[str, Any] = {}
        tags: Dict[str, str] = {}
        extra: Dict[str, Any] = {}

        extra['message'] = self.message
        extra['recoverable'] = self.recoverable

        if 'scrubbed_command' in self.details:
            extra['scrubbed_command'] = gluetool.utils.format_command_line([self.details['scrubbed_command']])

        if 'command_output' in self.details:
            extra['stderr'] = self.details['command_output'].stderr

        if 'guestname' in self.details:
            tags['guestname'] = self.details['guestname']

        if 'snapshotname' in self.details:
            tags['snapshotname'] = self.details['snapshotname']

        if 'poolname' in self.details:
            tags['poolname'] = self.details['poolname']

        if self.traceback:
            # Convert our traceback to format understood by Sentry, and store it in `data['stacktrace']` where Sentry
            # expects it to find when generating the message for submission.
            data['stacktrace'] = Failure._get_sentry_stack_info(self.traceback)

        if 'environment' in self.details:
            extra['environment'] = self.details['environment'].serialize_to_json()

        tags.update({
            key: value
            for key, value in self.details.items()
            if key.startswith('api_request_') or key.startswith('api_response_')
        })

        if self.caused_by:
            caused_by_data, caused_by_tags, caused_by_extra = self.caused_by.get_sentry_details()

            extra['caused_by'] = {
                'data': caused_by_data,
                'tags': caused_by_tags,
                'extra': caused_by_extra
            }

        return data, tags, extra

    def get_log_details(self) -> Dict[str, Any]:
        """
        Returns a mapping of failure details, suitable for logging subsystem.
        """

        details = self.details.copy()

        details['message'] = self.message
        details['recoverable'] = self.recoverable

        if self.exception:
            details['exception'] = self._exception_details(self.exception, self.details.get('scrubbed_command'))

        if self.exc_info:
            details['traceback'] = stackprinter.format(self.exc_info)

        if 'scrubbed_command' in details:
            details['scrubbed_command'] = gluetool.utils.format_command_line([details['scrubbed_command']])

        if 'command_output' in details:
            command_output = details['command_output']

            details['command_output'] = {
                'stdout': process_output_to_str(command_output, stream='stdout'),
                'stderr': process_output_to_str(command_output, stream='stderr')
            }

        if 'environment' in details:
            details['environment'] = details['environment'].serialize_to_json()

        if self.caused_by:
            details['caused-by'] = self.caused_by.get_log_details()

        return details

    def log(
        self,
        log_fn: gluetool.log.LoggingFunctionType,
        label: Optional[str] = None
    ) -> None:
        exc_info = self.exc_info if self.exc_info else (None, None, None)

        details = self.get_log_details()

        if label:
            text = '{}\n\n{}'.format(label, format_struct_as_yaml(details))

        else:
            text = format_struct_as_yaml(details)

        log_fn(
            text,
            exc_info=exc_info
        )

    def submit_to_sentry(self, **additional_tags: Any) -> None:
        if self.submited_to_sentry:
            return

        data, tags, extra = self.get_sentry_details()

        if additional_tags:
            tags.update(additional_tags)

        self.sentry_event_id = gluetool_sentry.submit_message(
            'Failure: {}'.format(self.message),
            exc_info=self.exc_info,
            data=data,
            tags=tags,
            extra=extra
        )

        self.submited_to_sentry = True

        if self.sentry_event_id:
            self.sentry_event_url = gluetool_sentry.event_url(self.sentry_event_id, logger=get_logger())

    def reraise(self) -> NoReturn:
        if self.exception:
            raise self.exception

        raise Exception('Cannot reraise undefined exception')

    def handle(
        self,
        logger: gluetool.log.ContextAdapter,
        label: Optional[str] = None,
        sentry: bool = True,
        **details: Any
    ) -> None:
        self.details.update(details)

        self.log(logger.error, label=label)

        if sentry:
            self.submit_to_sentry()

            if self.sentry_event_url:
                logger.warning('submitted to Sentry as {}'.format(self.sentry_event_url))

            else:
                logger.warning('not submitted to Sentry')


class KnobSource(Generic[T]):
    """
    Represents one of the possible sources of a knob value. Child classes implement the actual
    "get the value" process.

    :param knob: parent knob instance.
    """

    def __init__(self, knob: 'Knob[T]') -> None:
        self.knob = knob

    def get_value(self, *args: Any) -> Result[Optional[T], Failure]:
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

    :param envvar: name of the environment variable.
    :param type_cast: a callback used to cast the raw string to the correct type.
    """

    def __init__(self, knob: 'Knob[T]', envvar: str, type_cast: Callable[[str], T]) -> None:
        super(KnobSourceEnv, self).__init__(knob)

        self.envvar = envvar
        self.type_cast = type_cast

    def get_value(self, *args: Any) -> Result[Optional[T], Failure]:
        if self.envvar not in os.environ:
            return Ok(None)

        return Ok(
            self.type_cast(os.environ[self.envvar])
        )

    def to_repr(self) -> List[str]:
        return [
            'envvar="{}"'.format(self.envvar),
            'envvar-type-cast={}'.format(self.type_cast.__name__)
        ]


class KnobSourceDefault(KnobSource[T]):
    """
    Use the given default value as the actual value of the knob.

    :param default: the value to be presented as the knob value.
    """

    def __init__(self, knob: 'Knob[T]', default: T) -> None:
        super(KnobSourceDefault, self).__init__(knob)

        self.default = default

    def get_value(self, *args: Any) -> Result[Optional[T], Failure]:
        return Ok(self.default)

    def to_repr(self) -> List[str]:
        return [
            'default="{}"'.format(self.default)
        ]


class KnobSourceDB(KnobSource[T]):
    """
    Read knob value from a database.

    Values are stored as JSON blobs, to preserve their types.
    """

    def get_value(self, session: Session, *args) -> Result[Optional[T], Failure]:  # type: ignore  # match parent
        from . import Failure
        from .db import Knob as KnobRecord
        from .db import SafeQuery

        r = SafeQuery.from_session(session, KnobRecord) \
            .filter(KnobRecord.knobname == self.knob.knobname) \
            .one_or_none()

        if r.is_error:
            return Error(Failure(
                'Cannot fetch knob value from db',
                caused_by=r.unwrap_error()
            ))

        knob = r.unwrap()

        if not knob:
            return Ok(None)

        try:
            return Ok(cast(T, json.loads(knob.value)))

        except json.JSONDecodeError as exc:
            return Error(Failure.from_exc('Cannot decode knob value', exc))

    def to_repr(self) -> List[str]:
        return [
            'has-db=yes'
        ]


class KnobSourceActual(KnobSource[T]):
    """
    Use value as-is.
    """

    def __init__(self, knob: 'Knob[T]', value: T) -> None:
        super(KnobSourceActual, self).__init__(knob)

        self.value = value

    def get_value(self, *args: Any) -> Result[Optional[T], Failure]:
        return Ok(self.value)

    def to_repr(self) -> List[str]:
        return [
            'actual="{}"'.format(self.value)
        ]


class KnobError(ValueError):
    def __init__(self, knob: 'Knob[T]', message: str, failure: Optional[Failure] = None) -> None:
        super(KnobError, self).__init__('Badly configured knob: {}'.format(message))

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
    3. the default value.

    A typical knob may look like this:

    .. code-block:: python3

       # As a two-state knob, `bool` is the best choice here.
       KNOB_LOGGING_JSON: Knob[bool] = Knob(
           # A knob name.
           'logging.json',

           # This knob is not backed by a database.
           has_db=False,

           # This knob gets its value from the following environment variable. It is necessary to provide
           # a callback that casts the raw string value to the proper type.
           envvar='ARTEMIS_LOG_JSON',
           envvar_cast=gluetool.utils.normalize_bool_option,

           # This knob gets its value when created. Note that this is *very* similar to the default value,
           # but the default value should stand out as the default, while this parameter represents e.g.
           # value read from a configuration file, and as such may be left unspecified - then the default
           # would be used.
           actual=a_yaml_config_file['logging']['json'],

           # The default value - note that it is properly typed.
           default=True
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
    :param envvar: if set, it is the name of the environment variable providing the value.
    :param envvar_cast: a callback used to cast the raw environment variable content to the correct type.
        Required when ``envvar`` is set.
    :param actual: if set, it is the currently known value, e.g. provided by a config file.
    :param default: if set, it is used as a default value.
    """

    def __init__(
        self,
        knobname: str,
        has_db: bool = True,
        envvar: Optional[str] = None,
        envvar_cast: Optional[Callable[[str], T]] = None,
        actual: Optional[T] = None,
        default: Optional[T] = None,
    ) -> None:
        self.knobname = knobname
        self._sources: List[KnobSource[T]] = []

        if has_db:
            self._sources.append(KnobSourceDB(self))

        if envvar is not None:
            if not envvar_cast:
                raise Exception('Knob {} defined with envvar but no envvar_cast'.format(knobname))

            self._sources.append(KnobSourceEnv(self, envvar, envvar_cast))

        if actual is not None:
            self._sources.append(KnobSourceActual(self, actual))

        if default is not None:
            self._sources.append(KnobSourceDefault(self, default))

        if not self._sources:
            raise KnobError(
                self,
                'no source specified - no DB, envvar, actual nor default value.'
            )

        # If the knob isn't backed by a database, it should be possible to deduce its value *now*,
        # as it depends on envvar, actual or default value. For such knobs, we provide a shortcut,
        # easy-to-use `value` attribute - no `Result`, no `unwrap()` - given the possible sources,
        # it should never fail to get a value from such sources.
        if not has_db:
            value, failure = self._get_value()

            # If we fail to get value from envvar/default sources, then something is wrong. Maybe there's
            # just the envvar source, no default one, and environment variable is not set? In any case,
            # this sounds like a serious bug.
            if value is None:
                raise KnobError(
                    self,
                    'no DB, yet other sources do not provide value! To fix, add an envvar, actual or default value.',
                    failure=failure
                )

            self.value = value

    def __repr__(self) -> str:
        return '<Knob: {}: {}>'.format(
            self.knobname,
            ', '.join(sum([source.to_repr() for source in self._sources], []))
        )

    def _get_value(self, *args: Any) -> Tuple[Optional[T], Optional[Failure]]:
        """
        The core method for getting the knob value. Returns two items:

        * the value, or ``None`` if the value was not found.
        * optional :py:class:`Failure` instance if the process failed because of an error.
        """

        for source in self._sources:
            r = source.get_value(*args)

            if r.is_error:
                return None, r.unwrap_error()

            value = r.unwrap()

            if value is None:
                continue

            return value, None

        return None, None

    def get_value(self, *args: Any) -> Result[T, Failure]:
        """
        Returns either the knob value, of :py:class:`Failure` instance describing the error encountered, including
        the "value does not exist" state.

        All positional arguments are passed down to code handling each different sources.
        """

        value, failure = self._get_value(*args)

        if value is not None:
            return Ok(value)

        if failure:
            return Error(failure)

        from . import Failure

        return Error(Failure('Cannot fetch knob value'))


#: Level of logging. Accepted values are Python logging levels as defined by Python's
#: https://docs.python.org/3.7/library/logging.html#levels[logging subsystem].
KNOB_LOGGING_LEVEL: Knob[int] = Knob(
    'logging.level',
    has_db=False,
    envvar='ARTEMIS_LOG_LEVEL',
    envvar_cast=lambda s: logging._nameToLevel.get(s.strip().upper(), logging.INFO),
    default=logging.INFO
)

#: If enabled, Artemis would emit log messages as JSON mappings.
KNOB_LOGGING_JSON: Knob[bool] = Knob(
    'logging.json',
    has_db=False,
    envvar='ARTEMIS_LOG_JSON',
    envvar_cast=gluetool.utils.normalize_bool_option,
    default=True
)

#: Path to a directory with configuration.
KNOB_CONFIG_DIRPATH: Knob[str] = Knob(
    'config.dirpath',
    has_db=False,
    envvar='ARTEMIS_CONFIG_DIR',
    envvar_cast=lambda s: os.path.expanduser(s.strip()),
    default=os.getcwd()
)

#: Broker URL.
KNOB_BROKER_URL: Knob[str] = Knob(
    'broker.url',
    has_db=False,
    envvar='ARTEMIS_BROKER_URL',
    envvar_cast=str,
    default='amqp://guest:guest@127.0.0.1:5672'
)

#: Cache URL.
KNOB_CACHE_URL: Knob[str] = Knob(
    'cache.url',
    has_db=False,
    envvar='ARTEMIS_CACHE_URL',
    envvar_cast=str,
    default='redis://127.0.0.1:6379'
)


#: An interval, in seconds, after which a broker client should ping the server over the established connection to
#: keep both parties aware the connection should be kept alive.
KNOB_BROKER_HEARTBEAT_TIMEOUT: Knob[int] = Knob(
    'broker.heartbeat-timeout',
    has_db=False,
    envvar='ARTEMIS_BROKER_HEARTBEAT_TIMEOUT',
    envvar_cast=int,
    default=60
)

#: Database URL.
KNOB_DB_URL: Knob[str] = Knob(
    'db.url',
    has_db=False,
    envvar='ARTEMIS_DB_URL',
    envvar_cast=str,
    default='sqlite:///test.db'
)

#: Path to a file with a password for decrypting files protected by Ansible Vault.
KNOB_VAULT_PASSWORD_FILEPATH: Knob[str] = Knob(
    'vault.password.filepath',
    has_db=False,
    envvar='ARTEMIS_VAULT_PASSWORD_FILE',
    envvar_cast=lambda s: os.path.expanduser(s.strip()),
    default=os.path.expanduser('~/.vault_password')
)

#: When enabled, Artemis would log SQL queries.
KNOB_LOGGING_DB_QUERIES: Knob[bool] = Knob(
    'logging.db.queries',
    has_db=False,
    envvar='ARTEMIS_LOG_DB_QUERIES',
    envvar_cast=gluetool.utils.normalize_bool_option,
    default=False
)

#: When enabled, Artemis would log events related to database connection pool.
KNOB_LOGGING_DB_POOL: Knob[str] = Knob(
    'logging.db.pool',
    has_db=False,
    envvar='ARTEMIS_LOG_DB_POOL',
    envvar_cast=str,
    default='no'
)

#: Size of the DB connection pool.
KNOB_DB_POOL_SIZE: Knob[int] = Knob(
    'db.pool.size',
    has_db=False,
    envvar='ARTEMIS_DB_POOL_SIZE',
    envvar_cast=int,
    default=20
)

#: Maximum size of connection pool overflow.
KNOB_DB_POOL_MAX_OVERFLOW: Knob[int] = Knob(
    'db.pool.max-overflow',
    has_db=False,
    envvar='ARTEMIS_DB_POOL_MAX_OVERFLOW',
    envvar_cast=int,
    default=10
)


def get_logger() -> gluetool.log.ContextAdapter:
    gluetool.color.switch(True)

    return gluetool.log.Logging.setup_logger(
        level=KNOB_LOGGING_LEVEL.value,
        json_output=KNOB_LOGGING_JSON.value,
        sentry=gluetool_sentry
    )


def get_config() -> Dict[str, Any]:
    return cast(
        Dict[str, Any],
        gluetool.utils.load_yaml(
            os.path.join(KNOB_CONFIG_DIRPATH.value, 'server.yml'),
            logger=get_logger()
        )
    )


def get_broker() -> dramatiq.brokers.rabbitmq.RabbitmqBroker:
    if os.getenv('IN_TEST', None):
        broker = dramatiq.brokers.stub.StubBroker(middleware=[
            dramatiq.middleware.age_limit.AgeLimit(),
            dramatiq.middleware.time_limit.TimeLimit(),
            dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
            dramatiq.middleware.callbacks.Callbacks(),
            dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
            artemis_middleware.Retries(),
            periodiq.PeriodiqMiddleware()
        ])

    else:
        # We need a better control over some aspects of our broker connection, e.g. heartbeat
        # and timeouts. This is possible, but we cannt use broker URL as a argument, this is
        # not supported with Dramatiq and Pika. Therefore, we need to parse the URL and construct
        # connection parameters, with expected content, and add more details when needed.

        import pika

        # TODO: for actual limiter, we would need to throw in either Redis or Memcached.
        # Using stub and a dummy key for now, but it's just not going to do its job properly.

        parsed_url = urllib.parse.urlparse(KNOB_BROKER_URL.value)

        broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
            middleware=[
                dramatiq.middleware.age_limit.AgeLimit(),
                dramatiq.middleware.time_limit.TimeLimit(),
                dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
                dramatiq.middleware.callbacks.Callbacks(),
                dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
                artemis_middleware.Retries(),
                periodiq.PeriodiqMiddleware()
            ],
            parameters=[{
                'host': parsed_url.hostname,
                'port': int(parsed_url.port),
                'credentials': pika.PlainCredentials(parsed_url.username, parsed_url.password),
                'heartbeat': KNOB_BROKER_HEARTBEAT_TIMEOUT.value,
                'blocked_connection_timeout': KNOB_BROKER_HEARTBEAT_TIMEOUT.value
            }]
        )

    dramatiq.set_broker(broker)

    return broker


def get_cache(logger: gluetool.log.ContextAdapter) -> redis.Redis:
    return cast(
        Callable[[str], redis.Redis],
        redis.Redis.from_url
    )(KNOB_CACHE_URL.value)


def get_db(logger: gluetool.log.ContextAdapter, application_name: Optional[str] = None) -> artemis_db.DB:
    """
    Return a DB instance.

    :param logger: logger to use for logging.
    :param application_name: if set, it is passed to DB driver. Some drivers can propagate this string
        down to server level and display it when inspecting DB connections, which may help debugging
        DB operations.
    """

    return artemis_db.DB(
        logger,
        KNOB_DB_URL.value,
        application_name=application_name
    )


def get_vault() -> artemis_vault.Vault:
    with open(KNOB_VAULT_PASSWORD_FILEPATH.value, 'r') as f:
        return artemis_vault.Vault(f.read())


def safe_call(fn: Callable[..., T], *args: Any, **kwargs: Any) -> Result[T, Failure]:
    """
    Call given function, with provided arguments.

    :returns: if an exception was raised during the function call, an error result is returned, wrapping the failure.
        Otherwise, a valid result is returned, wrapping function's return value.
    """

    try:
        return Ok(fn(*args, **kwargs))

    except Exception as exc:
        return Error(Failure.from_exc('failed to execute {}: {}'.format(fn.__name__, exc), exc))


def safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    expected_records: int = 1
) -> Result[bool, Failure]:
    """
    Execute a given SQL query, ``UPDATE`` or ``DELETE``, followed by an explicit commit. Verify the expected number
    of records has been changed.

    :returns: a valid boolean result if queries were executed successfully: ``True`` if changes were made, and
        the number of changed records matched the expectation, ``False`` otherwise. If the queries - including the
        commit - were rejected by lower layers or database, an invalid result is returned, wrapping
        a :py:class:`Failure` instance.
    """

    logger.debug('safe db change: {}'.format(str(query)))

    r = safe_call(session.execute, query)

    if r.is_error:
        return Error(
            Failure(
                'failed to execute update query',
                caused_by=r.unwrap_error(),
                query=str(query)
            )
        )

    query_result = cast(
        sqlalchemy.engine.ResultProxy,
        r.value
    )

    if query_result.rowcount != expected_records:
        logger.warning('expected {} matching rows, found {}'.format(expected_records, query_result.rowcount))

        return Ok(False)

    logger.debug('found {} matching rows, as expected'.format(query_result.rowcount))

    r = safe_call(session.commit)

    if r.is_error:
        failure = r.unwrap_error()

        if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
            logger.warning('expected {} matching rows, found 0'.format(expected_records))

            return Ok(False)

        return Error(
            Failure(
                'failed to commit query',
                caused_by=failure,
                query=str(query)
            )
        )

    return Ok(True)


def log_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    eventname: str,
    **details: Any
) -> Result[None, Failure]:
    """ Create event log record for guest """

    session.add(
        artemis_db.GuestEvent(
            guestname=guestname,
            eventname=eventname,
            **details
        )
    )

    r = safe_call(session.commit)

    if r.is_error:
        failure = r.unwrap_error()

        failure.details.update({
            'guestname': guestname,
            'eventname': eventname
        })

        gluetool.log.log_dict(logger.warning, 'failed to log event {}'.format(eventname), details)

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

    gluetool.log.log_dict(logger.info, 'logged event {}'.format(eventname), details)

    return Ok(None)


def log_error_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    message: str,
    failure: Failure
) -> Result[None, Failure]:
    """ Create event log record for guest """

    return log_guest_event(
        logger,
        session,
        guestname,
        'error',
        error=message,
        **{
            'failure': failure.get_event_details()
        }
    )


#: Context variables
#:
#: These are global, "shared" names for important objects that together represent a certain "execution context"
#: our code runs in. The entry points - places that call methods like :py:func:`get_logger` and :py:func:`get_db`,
#: usually the first piece of code that runs in reaction to events like HTTP connection or delivered message - are
#: expected to set these variables properly. It is then expected that following paths will update them as needed,
#: for example :py:var:`LOGGER` will gain more logging context and therefore the initial object would be replaced
#: with more specific loggers.
#:
#: Vast majority of our code expects very similar set of inputs - logger, db, session and so on. This approach
#: should keep things typed and correctly propagated while allowing the expansion of this virtual "context" by
#: simply addition of a new variable.
#:
#: See :py:mod:`contextvars` docs for details, in general these variables are stored as thread local data (not
#: completely true since they also play nicely with asyncio). Our work is being done in threads, tasks and API
#: requests are handled by threads with very visible entry points (actor, API handler), therefore it seems both
#: fitting our approach and safe at the same time - as long as the entry points take care of updating the variables
#: properly. But, we already have to pass an updated logger instance down the stream, we can assign it to a context
#: variable instead, therefore it shouldn't bring more work.
#:
#: On the other hand, things become less visible, code becomes depending on an apparently shared global state,
#: shared global variables. The names are shared, the value are *not*, thanks to thread-local magic. It seems
#: possible to develop fixtures to make this code easily testable, and we need to chose very carefuly which code
#: we switch to context variables and which would continue take arguments as its inputs. Code that exists in
#: multiple incarnations with the same API (task actors, metric syncs) may benefit greatly from this - no need
#: to pass N variables to each and every function plus a big red warning "this may use context variables" should
#: prevent most of the issues.
LOGGER: contextvars.ContextVar[gluetool.log.ContextAdapter] = contextvars.ContextVar('LOGGER', default=get_logger())
DATABASE: contextvars.ContextVar['artemis_db.DB'] = contextvars.ContextVar('DATABASE', default=get_db(LOGGER.get()))
SESSION: contextvars.ContextVar[sqlalchemy.orm.session.Session] = contextvars.ContextVar('SESSION')
CACHE: contextvars.ContextVar[redis.Redis] = contextvars.ContextVar('CACHE', default=get_cache(LOGGER.get()))

#: Context variables available as injectables.
CONTEXT_PROVIDERS: Dict[Tuple[str, Any], contextvars.ContextVar[Any]] = {
    ('logger', gluetool.log.ContextAdapter): LOGGER,
    ('db', artemis_db.DB): DATABASE,
    ('session', sqlalchemy.orm.session.Session): SESSION,
    ('cache', redis.Redis): CACHE
}


def with_context(fn: Callable[..., T]) -> Callable[['VarArg(Any)'], T]:  # type: ignore  # VarArg isn't a problem
    """
    Decorated function is injected with context variables by specifying them as parameters with known names and types.

    * ``logger`` :py:class:`gluetool.logger.ContextAdapter` - :py:var:`LOGGER`
    * ``db`` :py:class:`tft.artemis.db.DB` - :py:var:`DATABASE`
    * ``session`` :py:class:`sqlalchemy.orm.session.Session` - :py:var:`SESSION`
    * ``cache`` :py:class:`redis.Redis` - :py:var:`CACHE`

    The objects available for injecting are provided by :py:var:`CONTEXT_PROVIDERS` mapping.

    .. code-block:: python

       @with_context
       def foo(logger: ContextAdapter) -> str:
           return 'bar'

        foo()  # `foo(logger=LOGGER.get())` on background

    .. warning::

       At this moment, the decorator works with methods that accept only ``self`` and nothing else. The problem lies
       in extending the support to any number or type of arguments but preserving the assurance type annotations
       provide. Therefore, the use is limited.
    """

    annotation = fn.__annotations__

    @functools.wraps(fn)
    def wrapper(self: Any) -> T:
        kwargs: Dict[str, Any] = {}

        for (name, type_), var in CONTEXT_PROVIDERS.items():
            if name not in annotation or annotation[name] is not type_:
                continue

            kwargs[name] = var.get()

        return fn(self, **kwargs)

    return wrapper
