import contextvars
import dataclasses
import datetime
import inspect
import itertools
import json
import os
import sys
import traceback as _traceback
from types import FrameType, TracebackType
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Iterable, List, MutableSet, NoReturn, Optional, \
    Tuple, Type, TypeVar, Union, cast

import dramatiq
import dramatiq.brokers.rabbitmq
import dramatiq.brokers.stub
import dramatiq.middleware.age_limit
import dramatiq.middleware.callbacks
import dramatiq.middleware.current_message
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
import stackprinter
from gluetool.result import Error, Ok, Result

__VERSION__ = pkg_resources.get_distribution('tft-artemis').version


# Install additional Jinja2 filters. This must be done before we call `render_template` for the first
# time, because Jinja2 reuses anonymous environments.

jinja2.defaults.DEFAULT_FILTERS.update(
    jinja2_ansible_filters.core_filters.FilterModule().filters()
)

# Now we can import our stuff without any fear we'd miss DEFAULT_FILTERS update
from . import db as artemis_db  # noqa: E402
from . import middleware as artemis_middleware  # noqa: E402

if TYPE_CHECKING:
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


# Special context variable for YAML processor. `ruamel.YAML` instances keep internal state, and as such they cannot
# be shared between threads without some kind of serialization. Rather than introducing a lock, we can use context
# and keep a `YAML` instance for each thread. With a wrapper function, we can initialize missing instances when
# accessed for the first time (`contextvars` package does not support default factory).
_YAML: contextvars.ContextVar[Optional[ruamel.yaml.main.YAML]] = contextvars.ContextVar('_YAML', default=None)
_YAML_DUMPABLE_CLASSES: MutableSet[Type[object]] = set()


def get_yaml() -> ruamel.yaml.main.YAML:
    """
    Return a fully initialized instance of YAML processor.
    """

    YAML = _YAML.get()

    if YAML is None:
        YAML = gluetool.utils.YAML()
        _YAML.set(YAML)

        for cls in _YAML_DUMPABLE_CLASSES:
            YAML.register_class(cls)

    return YAML


# Gluetool Sentry instance
gluetool_sentry = gluetool.sentry.Sentry()


class SerializableContainer:
    """
    Mixin class bringing serialize/unserialize methods for dataclass-based containers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super(SerializableContainer, self).__init__(*args, **kwargs)  # type: ignore[call-arg]

    # All classes derived from SerializableContainer can be represented as YAML, because they
    # inherit the `to_yaml()` method, which then depends on `serialize_to_json()` - and what
    # we can represent as JSON, we can for sure represent as YAML as well.
    #
    # Instead of using decorator to mark classes derived from this one, we let interpreter call
    # this magic method every tim a subclass has been created.
    def __init_subclass__(cls: Type['SerializableContainer']) -> None:
        """
        Register given subclass as capable of being represented as YAML.
        """

        super(SerializableContainer, cls).__init_subclass__()

        _YAML_DUMPABLE_CLASSES.add(cls)

    def serialize_to_json(self) -> Dict[str, Any]:
        serialized = dataclasses.asdict(self)

        for field in dataclasses.fields(self):
            if not inspect.isclass(field.type):
                continue

            if not issubclass(field.type, SerializableContainer):
                continue

            serialized[field.name] = getattr(self, field.name).serialize_to_json()

        return serialized

    @classmethod
    def unserialize_from_json(cls: Type[S], serialized: Dict[str, Any]) -> S:
        unserialized = cls(**serialized)

        for field in dataclasses.fields(unserialized):
            if not inspect.isclass(field.type):
                continue

            if not issubclass(field.type, SerializableContainer):
                continue

            if field.name not in serialized:
                continue

            setattr(unserialized, field.name, field.type.unserialize_from_json(serialized[field.name]))

        return unserialized

    def serialize_to_str(self) -> str:
        return json.dumps(self.serialize_to_json())

    @classmethod
    def unserialize_from_str(cls: Type[S], serialized: str) -> S:
        return cls.unserialize_from_json(json.loads(serialized))

    @classmethod
    def to_yaml(cls, representer: ruamel.yaml.representer.Representer, container: S) -> Any:
        return representer.represent_dict(container.serialize_to_json())


# Two logging helpers, very similar to `format_dict` and `log_dict`, but emitting a YAML-ish output.
# YAML is often more readable for humans, and, sometimes, we might use these on purpose, to provide
# more readable output.
#
# TODO: move to gluetool - posibly as a switch to log_dict, no need for a stand-alone functions.
def format_dict_yaml(data: Any) -> str:
    stream = ruamel.yaml.compat.StringIO()

    YAML = get_yaml()

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
    ) -> 'Failure':
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
    ) -> 'Failure':
        self.details.update(details)

        if scrubbed_command:
            self.details['scrubbed_command'] = scrubbed_command

        if command_output:
            self.details['command_output'] = command_output

        if environment:
            self.details['environment'] = environment

        return self

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
            details['traceback'] = stackprinter.format(self.exc_info)  # noqa: FS002

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


def get_logger() -> gluetool.log.ContextAdapter:
    from .knobs import KNOB_LOGGING_JSON, KNOB_LOGGING_LEVEL

    gluetool.color.switch(True)

    return gluetool.log.Logging.setup_logger(
        level=KNOB_LOGGING_LEVEL.value,
        json_output=KNOB_LOGGING_JSON.value,
        sentry=gluetool_sentry
    )


def get_config() -> Dict[str, Any]:
    from .knobs import KNOB_CONFIG_DIRPATH

    return cast(
        Dict[str, Any],
        gluetool.utils.load_yaml(
            os.path.join(KNOB_CONFIG_DIRPATH.value, 'server.yml'),
            logger=get_logger()
        )
    )


def get_broker(
    logger: gluetool.log.ContextAdapter,
    application_name: Optional[str] = None
) -> dramatiq.brokers.rabbitmq.RabbitmqBroker:
    if os.getenv('IN_TEST', None):
        broker = dramatiq.brokers.stub.StubBroker(middleware=[
            dramatiq.middleware.age_limit.AgeLimit(),
            dramatiq.middleware.time_limit.TimeLimit(),
            dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
            dramatiq.middleware.callbacks.Callbacks(),
            dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
            dramatiq.middleware.current_message.CurrentMessage(),
            artemis_middleware.Prometheus(),
            artemis_middleware.Retries(),
            periodiq.PeriodiqMiddleware()
        ])

    else:
        from .knobs import KNOB_BROKER_CONFIRM_DELIVERY, KNOB_BROKER_URL

        # TODO: for actual limiter, we would need to throw in either Redis or Memcached.
        # Using stub and a dummy key for now, but it's just not going to do its job properly.

        broker_url = KNOB_BROKER_URL.value

        # Client properties must be encoded into URL, Pika does not allow `url` + `client_properties` at the same time.
        client_properties: Dict[str, str] = {}

        if application_name is not None:
            client_properties['connection_name'] = application_name

        if client_properties:
            import urllib.parse

            parsed_url = urllib.parse.urlparse(KNOB_BROKER_URL.value)

            parsed_query: Dict[str, Union[str, Dict[str, str]]] = {
                k: v
                for k, v in urllib.parse.parse_qsl(parsed_url.query)
            }

            parsed_query['client_properties'] = client_properties

            broker_url = urllib.parse.ParseResult(
                scheme=parsed_url.scheme,
                netloc=parsed_url.netloc,
                path=parsed_url.path,
                params=parsed_url.params,
                query=urllib.parse.urlencode(parsed_query),
                fragment=parsed_url.fragment
            ).geturl()

        logger.debug(f'final broker URL is {broker_url}')

        broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
            confirm_delivery=KNOB_BROKER_CONFIRM_DELIVERY.value,
            middleware=[
                dramatiq.middleware.age_limit.AgeLimit(),
                dramatiq.middleware.time_limit.TimeLimit(),
                dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
                dramatiq.middleware.callbacks.Callbacks(),
                dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
                dramatiq.middleware.current_message.CurrentMessage(),
                artemis_middleware.Prometheus(),
                artemis_middleware.Retries(),
                periodiq.PeriodiqMiddleware()
            ],
            url=broker_url
        )

    dramatiq.set_broker(broker)

    return broker


def get_cache(logger: gluetool.log.ContextAdapter) -> redis.Redis:
    from .knobs import KNOB_CACHE_URL

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

    from .knobs import KNOB_DB_URL

    return artemis_db.DB(
        logger,
        KNOB_DB_URL.value,
        application_name=application_name
    )


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
