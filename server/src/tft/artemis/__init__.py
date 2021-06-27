import dataclasses
import datetime
import inspect
import itertools
import json
import logging
import os
import re
import sys
import traceback as _traceback
import urllib.parse
from types import FrameType, TracebackType
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Generic, Iterable, List, NoReturn, Optional, \
    Pattern, Tuple, Type, TypeVar, Union, cast

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
import jsonschema
import periodiq
import pkg_resources
import redis
import ruamel.yaml
import ruamel.yaml.compat
import sqlalchemy.orm.session
import stackprinter
from gluetool.result import Error, Ok, Result
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

if TYPE_CHECKING:
    from .drivers import PoolDriver
    from .environment import Environment

stackprinter.set_excepthook(
    style='darkbg2',
    source_lines=7,
    show_signature=True,
    show_vals='all',
    reverse=False,
    add_summary=False
)


#: Serves as a backup if user did not specify port in ``BROKER_URL`` knob value. We don't have a dedicated knob
#: for this value - if you want to use different port, do specify it in ``BROKER_URL`` then.
DEFAULT_RABBITMQ_PORT = 5672


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
S = TypeVar('S', bound='SerializableContainer')

FailureDetailsType = Dict[str, Any]

#: Represents a data structure created from a JSON input. The main purpose of this type to allow tracking of such data
#: instead of very open and easy to misunderstand ``Any``. A particular name is easier to follow in the code.
#:
#: Since JSON can be as simple as a single integer, ``79``, the type covers the primitive types, too. In reality,
#: our code will encounter mostly complex types, lists of dictionaries (e.g. list of cloud instances), therefore
#: including the primitive types will force users of ``JSONType`` to employ ``cast()`` heavily, to actually reveal
#: the real structure inside the otherwise opaque JSON blob received from a CLI tool. But that **is** a good thing.
JSONType = Union[str, int, float, List[Any], Dict[Any, Any], None]


# Gluetool Sentry instance
gluetool_sentry = gluetool.sentry.Sentry()


class SerializableContainer:
    """
    Mixing class bringing serialize/unserialize methods for dataclass-based containers.
    """

    def serialize_to_json(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def unserialize_from_json(cls: Type[S], serialized: Dict[str, Any]) -> S:
        return cls(**serialized)  # type: ignore


# Two logging helpers, very similar to `format_dict` and `log_dict`, but emitting a YAML-ish output.
# YAML is often more readable for humans, and, sometimes, we might use these on purpose, to provide
# more readable output.
#
# TODO: move to gluetool - posibly as a switch to log_dict, no need for a stand-alone functions.
def format_dict_yaml(data: Any) -> str:
    stream = ruamel.yaml.compat.StringIO()

    YAML = gluetool.utils.YAML()

    ruamel.yaml.scalarstring.walk_tree(data)

    YAML.dump(data, stream)

    return stream.getvalue()


def log_dict_yaml(
    writer: gluetool.log.LoggingFunctionType,
    intro: str,
    data: Any
) -> None:
    writer(f'{intro}:\n{format_dict_yaml(data)}', extra={
        'raw_intro': intro,
        'raw_struct': data
    })


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
        fail_guest_request: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
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
        # If the failure is irrecoverable, mark the guest request as failed by switching its state
        # to `ERROR`. This flag gives code chance to avoid this switch - there are places where
        # we can encounter irrecoverable failures without necessarily failing the whole request,
        # e.g. when releasing its resources.
        self.fail_guest_request = fail_guest_request

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
            self.traceback.reverse()

        if traceback:
            self.traceback = traceback

        if self.traceback is None:
            # This is what `traceback.extract_stack` does, but `extract_stack` does not let us save frame locals,
            # and we would like to see them, at least in Sentry.

            # start with the caller frame - the one creating the Failure
            f = sys._getframe().f_back

            self.traceback = _traceback.StackSummary.extract(
                cast(
                    Generator[Tuple[FrameType, int], None, None],
                    _traceback.walk_stack(f)
                ),
                capture_locals=True
            )
            self.traceback.reverse()

    @classmethod
    def from_exc(
        self,
        message: str,
        exc: Exception,
        caused_by: Optional['Failure'] = None,
        sentry: Optional[bool] = True,
        recoverable: bool = True,
        fail_guest_request: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
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
            fail_guest_request=fail_guest_request,
            scrubbed_command=scrubbed_command,
            command_output=command_output,
            environment=environment,
            **details
        )

    @classmethod
    def from_failure(
        self,
        message: str,
        caused_by: 'Failure',
        sentry: Optional[bool] = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
        **details: Any
    ) -> 'Failure':
        """
        Create a new ``Failure`` instance, representing a higher-level view of the problem that's been
        carried by ``failure``.

        This method serves for creating a chain of failures - since it is often useful to provide better
        error message, it is not a good approach to overwrite any attributes of the given failure. It is
        easier to create a new one, to provide this higher-level context, to "wrap" the original "low level"
        failure, keeping it attached to the new one.

        The main advantages of this approach are:

        * better higher-level context,
        * no loss of information,
        * ``recoverable`` effect is preserved.
        """

        return Failure(
            message,
            caused_by=caused_by,
            recoverable=caused_by.recoverable,
            fail_guest_request=caused_by.fail_guest_request,
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
        environment: Optional['Environment'] = None,
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
                'instance': f'Command "{" ".join(scrubbed_command)}" failed with exit code {exc.output.exit_code}',
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
        event_details['fail_guest_request'] = self.fail_guest_request

        # We don't want command or its output in the event details - hard to serialize, full of secrets, etc.
        event_details.pop('command_output', None)
        event_details.pop('scrubbed_command', None)

        # Guestname will be provided by event instance itself, no need to parse it as event details
        event_details.pop('guestname', None)

        # We don't want the raw Beaker XMLs in the event neither, too much internal stuff in those XMLs
        event_details.pop('job_results', None)

        if 'environment' in event_details:
            event_details['environment'] = event_details['environment'].serialize_to_json()

        if self.caused_by:
            event_details['caused_by'] = self.caused_by.get_event_details()

        if self.sentry_event_url:
            event_details['sentry'] = {
                'event_id': self.sentry_event_id,
                'event_url': self.sentry_event_url
            }

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
        extra: Dict[str, Any] = self.details.copy()

        extra['message'] = self.message
        extra['recoverable'] = self.recoverable
        extra['fail_guest_request'] = self.fail_guest_request

        if 'scrubbed_command' in extra:
            extra['scrubbed_command'] = gluetool.utils.format_command_line([extra['scrubbed_command']])

        if 'command_output' in extra:
            extra['stdout'] = process_output_to_str(extra['command_output'], stream='stdout')
            extra['stderr'] = process_output_to_str(extra['command_output'], stream='stderr')

            del extra['command_output']

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

        if 'environment' in extra:
            extra['environment'] = extra['environment'].serialize_to_json()

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
        details['fail_guest_request'] = self.fail_guest_request

        if self.exception:
            details['exception'] = self._exception_details(self.exception, self.details.get('scrubbed_command'))

        if self.exc_info:
            details['traceback'] = stackprinter.format(self.exc_info)  # noqa

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

        if self.sentry_event_url:
            details['sentry'] = {
                'event_id': self.sentry_event_id,
                'event_url': self.sentry_event_url
            }

        return details

    def log(
        self,
        log_fn: gluetool.log.LoggingFunctionType,
        label: Optional[str] = None
    ) -> None:
        exc_info = self.exc_info if self.exc_info else (None, None, None)

        details = self.get_log_details()

        if not label:
            label = 'failure'

        log_fn(f'{label}\n\n{format_dict_yaml(details)}', exc_info=exc_info)

    def submit_to_sentry(self, logger: gluetool.log.ContextAdapter, **additional_tags: Any) -> None:
        if self.submited_to_sentry:
            return

        data, tags, extra = self.get_sentry_details()

        if additional_tags:
            tags.update(additional_tags)

        try:
            self.sentry_event_id = gluetool_sentry.submit_message(
                f'Failure: {self.message}',
                exc_info=self.exc_info,
                data=data,
                tags=tags,
                extra=extra
            )

        except Exception as exc:
            Failure.from_exc('failed to submit to Sentry', exc).handle(logger, sentry=False)

        else:
            self.submited_to_sentry = True

        if self.sentry_event_id:
            self.sentry_event_url = gluetool_sentry.event_url(self.sentry_event_id, logger=logger)

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

        if sentry:
            self.submit_to_sentry(logger)

        self.log(logger.error, label=label)


class KnobSource(Generic[T]):
    """
    Represents one of the possible sources of a knob value. Child classes implement the actual
    "get the value" process.

    :param knob: parent knob instance.
    """

    def __init__(self, knob: 'Knob[T]') -> None:
        self.knob = knob

    def get_value(self, **kwargs: Any) -> Result[Optional[T], Failure]:
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
        super(KnobSourceEnv, self).__init__(knob)

        self.envvar = envvar

    def _fetch_from_env(self, envvar: str) -> Result[Optional[T], Failure]:
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

    def get_value(self, **kwargs: Any) -> Result[Optional[T], Failure]:
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
    ) -> Result[Optional[T], Failure]:
        if poolname is not None:
            pass

        elif pool is not None:
            poolname = pool.poolname

        else:
            return Error(Failure('either pool or poolname must be specified'))

        r_value = self._fetch_from_env(f'{self.envvar}_{poolname}')

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
    """

    def __init__(self, knob: 'Knob[T]', default: T) -> None:
        super(KnobSourceDefault, self).__init__(knob)

        self.default = default

    def get_value(self, **kwargs: Any) -> Result[Optional[T], Failure]:
        return Ok(self.default)

    def to_repr(self) -> List[str]:
        return [
            f'default="{self.default}"'
        ]


class KnobSourceDB(KnobSource[T]):
    """
    Read knob value from a database.

    Values are stored as JSON blobs, to preserve their types.

    This is a base class for sources that read the values from the database and provides necessary primitives.
    """

    def _fetch_from_db(self, session: Session, knobname: str) -> Result[Optional[T], Failure]:
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

        try:
            return Ok(cast(T, record.unserialize_value()))

        except json.JSONDecodeError as exc:
            return Error(Failure.from_exc('Cannot decode knob value', exc))

    def to_repr(self) -> List[str]:
        return [
            'has-db=yes'
        ]


class KnobSourceDBGlobal(KnobSourceDB[T]):
    """
    Read knob value from a database.
    """

    def get_value(  # type: ignore  # match parent
        self,
        *,
        session: Session,
        **kwargs: Any
    ) -> Result[Optional[T], Failure]:
        return self._fetch_from_db(session, self.knob.knobname)


class KnobSourceDBPerPool(KnobSourceDB[T]):
    """
    Read knob value from a database.

    When the parent knob is enabled to provide pool-specific values (via ``per_pool=True``),
    then a special knob names are searched in the database instead of the original one:

    * ``${original knob name}:${poolname}``
    * ``${original knob name}``
    """

    def get_value(  # type: ignore  # match parent
        self,
        *,
        session: Session,
        poolname: Optional[str] = None,
        pool: Optional['PoolDriver'] = None,
        **kwargs: Any
    ) -> Result[Optional[T], Failure]:
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
        super(KnobSourceActual, self).__init__(knob)

        self.value = value

    def get_value(self, **kwargs: Any) -> Result[Optional[T], Failure]:
        return Ok(self.value)

    def to_repr(self) -> List[str]:
        return [
            f'actual="{self.value}"'
        ]


class KnobError(ValueError):
    def __init__(self, knob: 'Knob[T]', message: str, failure: Optional[Failure] = None) -> None:
        super(KnobError, self).__init__(f'Badly configured knob: {message}')

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

        traits += sum([source.to_repr() for source in self._sources], [])

        return f'<Knob: {self.knobname}: {" ".join(traits)}>'

    def _get_value(
        self,
        skip_db: bool = False,
        skip_per_pool: bool = False,
        **kwargs: Any
    ) -> Tuple[Optional[T], Optional[Failure]]:
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

    def get_value(self, **kwargs: Any) -> Result[T, Failure]:
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

        Per-pool knobs don't have 1:1 mapping between a Python :py:ref:`Knob` instance and its DB record.
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
    default=os.getcwd()
)

KNOB_BROKER_URL: Knob[str] = Knob(
    'broker.url',
    'Broker URL.',
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

KNOB_BROKER_HEARTBEAT_TIMEOUT: Knob[int] = Knob(
    'broker.heartbeat-timeout',
    """
    An interval, in seconds, after which a broker client should ping the server over the established connection to
    keep both parties aware the connection should be kept alive.
    """,
    has_db=False,
    envvar='ARTEMIS_BROKER_HEARTBEAT_TIMEOUT',
    cast_from_str=int,
    default=60
)

KNOB_DB_URL: Knob[str] = Knob(
    'db.url',
    'Database URL.',
    has_db=False,
    envvar='ARTEMIS_DB_URL',
    cast_from_str=str,
    default='sqlite:///test.db'
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
    default=os.path.expanduser('~/.vault_password')
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
            artemis_middleware.Prometheus(),
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
            confirm_delivery=KNOB_BROKER_CONFIRM_DELIVERY.value,
            middleware=[
                dramatiq.middleware.age_limit.AgeLimit(),
                dramatiq.middleware.time_limit.TimeLimit(),
                dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
                dramatiq.middleware.callbacks.Callbacks(),
                dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
                artemis_middleware.Prometheus(),
                artemis_middleware.Retries(),
                periodiq.PeriodiqMiddleware()
            ],
            parameters=[{
                'host': parsed_url.hostname,
                'port': int(parsed_url.port or DEFAULT_RABBITMQ_PORT),
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
    password = KNOB_VAULT_PASSWORD.value

    if not password:
        with open(KNOB_VAULT_PASSWORD_FILEPATH.value, 'r') as f:
            password = f.read()

    return artemis_vault.Vault(password)


def safe_call(fn: Callable[..., T], *args: Any, **kwargs: Any) -> Result[T, Failure]:
    """
    Call given function, with provided arguments.

    :returns: if an exception was raised during the function call, an error result is returned, wrapping the failure.
        Otherwise, a valid result is returned, wrapping function's return value.
    """

    try:
        return Ok(fn(*args, **kwargs))

    except Exception as exc:
        return Error(Failure.from_exc('exception raised inside a safe block', exc))


def stringify_query(session: sqlalchemy.orm.session.Session, query: Any) -> str:
    """
    Return string representation of a given DB query.

    This helper wraps one tricky piece of information: since SQLAlchemy supports many SQL dialects,
    and these dialects can add custom operations to queries, it is necessary to be aware of the dialect
    when compiling the query. "Compilation" is what happens when we ask SQLAlchemy to transform the query
    to string.
    """

    return str(query.compile(dialect=session.bind.dialect))


def safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    expected_records: Union[int, Tuple[int, int]] = 1,
) -> Result[bool, Failure]:
    """
    Execute a given SQL query, ``INSERT``, ``UPDATE`` or ``DELETE``, followed by an explicit commit. Verify
    the expected number of records has been changed (or created).

    :returns: a valid boolean result if queries were executed successfully: ``True`` if changes were made, and
        the number of changed records matched the expectation, ``False`` otherwise. If the queries - including the
        commit - were rejected by lower layers or database, an invalid result is returned, wrapping
        a :py:class:`Failure` instance.
    """

    logger.debug(f'safe db change: {stringify_query(session, query)} - expect {expected_records} records')

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


def log_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    eventname: str,
    **details: Any
) -> Result[None, Failure]:
    """ Create event log record for guest """

    r = safe_db_change(
        logger,
        session,
        sqlalchemy.insert(artemis_db.GuestEvent.__table__).values(  # type: ignore  # GuestEvent *has* __table__
            guestname=guestname,
            eventname=eventname,
            details=json.dumps(details)
        )
    )

    if r.is_error:
        failure = r.unwrap_error()

        failure.details.update({
            'guestname': guestname,
            'eventname': eventname
        })

        gluetool.log.log_dict(logger.warning, f'failed to log event {eventname}', details)

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

    gluetool.log.log_dict(logger.info, f'logged event {eventname}', details)

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


#
# Helpful cache primitives
#
def refresh_cached_set(
    cache: redis.Redis,
    key: str,
    items: Dict[str, SerializableContainer]
) -> Result[None, Failure]:
    """
    Refresh a cache entry with a given set of items.

    The cache stores items serialized as JSON blobs, reachable by the key given to them by the set.

    :param key: cache key storing the set.
    :param items: set of items to store.
    """

    key_updated = f'{key}.updated'

    if not items:
        # When we get an empty set of items, we should remove the key entirely, to make queries looking for
        # return `None` aka "not found". It's the same as if we'd try to remove all entries, just with one
        # action.
        safe_call(
            cast(Callable[[str], None], cache.delete),
            key
        )

        safe_call(
            cast(Callable[[str, float], None], cache.set),
            key_updated,
            datetime.datetime.timestamp(datetime.datetime.utcnow())
        )

        return Ok(None)

    # Two steps: create new structure, and replace the old one. We cannot check the old one
    # and remove entries that are no longer valid.
    new_key = f'{key}.new'

    r_action = safe_call(
        cast(Callable[[str, str, Dict[str, str]], None], cache.hmset),
        new_key,
        {
            item_key: json.dumps(item.serialize_to_json())
            for item_key, item in items.items()
        }
    )

    if r_action.is_error:
        return Error(r_action.unwrap_error())

    safe_call(
        cast(Callable[[str, str], None], cache.rename),
        new_key,
        key
    )

    safe_call(
        cast(Callable[[str, float], None], cache.set),
        key_updated,
        datetime.datetime.timestamp(datetime.datetime.utcnow())
    )

    return Ok(None)


def get_cached_items(
    cache: redis.Redis,
    key: str,
    item_klass: Type[S]
) -> Result[Optional[Dict[str, S]], Failure]:
    """
    Return cached items of a given type in the form of a mapping between their names and the instances.

    Serves as a helper function for fetching homogenous sets of objects, like pool image infos.

    See :py:func:`get_cached_items_as_list` for the variant returning items in a list.
    """

    r_fetch = safe_call(
        cast(Callable[[str], Optional[Dict[bytes, bytes]]], cache.hgetall),
        key,
    )

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    serialized = r_fetch.unwrap()

    if serialized is None:
        return Ok(None)

    items: Dict[str, S] = {}

    for item_key, item_serialized in serialized.items():
        r_unserialize = safe_call(item_klass.unserialize_from_json, json.loads(item_serialized.decode('utf-8')))

        if r_unserialize.is_error:
            return Error(r_unserialize.unwrap_error())

        items[item_key.decode('utf-8')] = r_unserialize.unwrap()

    return Ok(items)


def get_cached_items_as_list(
    cache: redis.Redis,
    key: str,
    item_klass: Type[S]
) -> Result[List[S], Failure]:
    """
    Return cached items of a given type in the form of a list of instances.

    Serves as a helper function for fetching homogenous sets of objects, like pool image infos.

    See :py:func:`get_cached_items` for the variant returning items in the form of a mapping.
    """

    r_fetch = get_cached_items(cache, key, item_klass)

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    items = r_fetch.unwrap()

    return Ok(list(items.values()) if items else [])


def get_cached_item(
    cache: redis.Redis,
    key: str,
    item_key: str,
    item_klass: Type[S]
) -> Result[Optional[S], Failure]:
    r_fetch = safe_call(
        cast(Callable[[str, str], Optional[bytes]], cache.hget),
        key,
        item_key
    )

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    serialized = r_fetch.unwrap()

    if serialized is None:
        return Ok(None)

    r_unserialize = safe_call(item_klass.unserialize_from_json, json.loads(serialized.decode('utf-8')))

    if r_unserialize.is_error:
        return Error(r_unserialize.unwrap_error())

    return Ok(r_unserialize.unwrap())


#: Custom type for JSON schema. We don't expect the schema structure though, all we do is loading it
#: from a YAML file, then passing it to validators. The actual type could very well be ``Any``, but
#: given how JSON schema looks like, it's pretty much going to be a mapping with string keys. So using
#: this type, and adding our alias to it so we could follow JSON schemas in our code easily.
JSONSchemaType = Dict[str, Any]


def load_validation_schema(schema_path: str) -> Result[JSONSchemaType, Failure]:
    """
    Load a JSON schema for future use in data validation.

    :param schema_path: path to a schema file relative to ``schema`` directory in ``tft.artemis`` package.
    """

    root_schema_dirpath = pkg_resources.resource_filename('tft.artemis', 'schema')

    r_schema = safe_call(
        gluetool.utils.load_yaml,
        os.path.join(root_schema_dirpath, schema_path),
        loader_type='safe'
    )

    if r_schema.is_error:
        return Error(Failure.from_failure(
            'failed to load schema',
            r_schema.unwrap_error(),
            schema_path=schema_path
        ))

    return Ok(cast(JSONSchemaType, r_schema.unwrap()))


def validate_data(data: Any, schema: JSONSchemaType) -> Result[List[str], Failure]:
    """
    Validate a given data using a JSON schema.

    :return: either a list of validation errors, or a :py:class:`Failure` describing problem preventing
        the validation process.
    """

    try:
        jsonschema.validate(data, schema)

    except jsonschema.exceptions.ValidationError as exc:
        return Ok([exc.message])

    return Ok([])


def partition(predicate: Callable[[T], bool], iterable: Iterable[T]) -> Tuple[Iterable[T], Iterable[T]]:
    """
    Use a predicate to split the entries of the given iterable into two lists, one for true entries
    and second for false ones.
    """

    iter1, iter2 = itertools.tee(iterable)

    return filter(predicate, iter1), itertools.filterfalse(predicate, iter2)
