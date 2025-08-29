# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import dataclasses
import enum
import importlib
import inspect
import itertools
import json
import logging
import os
import platform
import re
import resource
import shlex
import sys
import threading
import traceback as _traceback
from collections.abc import Generator, Iterable, Iterator, MutableSet
from types import FrameType, TracebackType
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    NoReturn,
    Optional,
    TypeVar,
    Union,
    cast,
)

import dramatiq
import dramatiq.brokers.rabbitmq
import dramatiq.brokers.stub
import dramatiq.middleware.age_limit
import dramatiq.middleware.callbacks
import dramatiq.middleware.current_message
import dramatiq.middleware.pipelines
import dramatiq.middleware.shutdown
import dramatiq.middleware.time_limit
import dramatiq.rate_limits.backends
import dramatiq.rate_limits.concurrent
import gluetool.log
import gluetool.sentry
import gluetool.utils
import jinja2
import jinja2.filters
import jinja2_ansible_filters.core_filters
import jsonschema
import periodiq
import pkg_resources
import redis
import ruamel.yaml
import ruamel.yaml.compat
import ruamel.yaml.nodes
import sentry_sdk
import sentry_sdk._types
import sentry_sdk.integrations.argv
import sentry_sdk.integrations.atexit
import sentry_sdk.integrations.dedupe
import sentry_sdk.integrations.excepthook
import sentry_sdk.integrations.logging
import sentry_sdk.integrations.modules
import sentry_sdk.integrations.stdlib
import sentry_sdk.integrations.threading
import sentry_sdk.serializer
import sentry_sdk.tracing
import sentry_sdk.transport
import sentry_sdk.types
import sentry_sdk.utils
import stackprinter
from gluetool.result import Error, Ok, Result
from returns.pipeline import is_successful
from returns.result import Failure as _Error, Result as _Result, Success as _Ok
from tmt.hardware import UNITS
from typing_extensions import ParamSpec, Self

__VERSION__ = pkg_resources.get_distribution('tft-artemis').version


# Install additional Jinja2 filters. This must be done before we call `render_template` for the first
# time, because Jinja2 reuses anonymous environments.

jinja2.filters.FILTERS.update(jinja2_ansible_filters.core_filters.FilterModule().filters())

# Now we can import our stuff without any fear we'd miss DEFAULT_FILTERS update
from . import (  # noqa: E402
    db as artemis_db,
    middleware as artemis_middleware,
)
from .knobs import (  # noqa: E402
    KNOB_DEPLOYMENT_ENVIRONMENT,
    KNOB_LOGGING_SENTRY,
    KNOB_SENTRY_DISABLE_CERT_VERIFICATION,
    KNOB_SENTRY_DSN,
    KNOB_SENTRY_EVENT_URL_TEMPLATE,
    KNOB_SENTRY_INTEGRATIONS,
    KNOB_SENTRY_ISSUES_SAMPLE_RATE,
    KNOB_SENTRY_TRACING_SAMPLE_PATTERN,
    KNOB_SENTRY_TRACING_SAMPLE_RATE,
    KNOB_TEMPLATE_BLOCK_DELIMITERS,
    KNOB_TEMPLATE_VARIABLE_DELIMITERS,
    KNOB_TRACING_ENABLED,
    Knob,
)

if TYPE_CHECKING:
    from .environment import Environment, SizeType
    from .tasks import TaskCall

stackprinter.set_excepthook(
    style='darkbg2', source_lines=7, show_signature=True, show_vals='all', reverse=False, add_summary=False
)


#: Serves as a backup if user did not specify port in ``BROKER_URL`` knob value. We don't have a dedicated knob
#: for this value - if you want to use different port, do specify it in ``BROKER_URL`` then.
DEFAULT_RABBITMQ_PORT = 5672

#: Default date/time format.
DATETIME_FMT: str = '%Y-%m-%dT%H:%M:%S.%f'


ExceptionInfoType = Union[
    # returned by sys.exc_info()
    tuple[type[BaseException], BaseException, Optional[TracebackType]],
    # this is way of saying "nothing happened, everything's fine"
    tuple[None, None, None],
]

# Type variable used in generic types
T = TypeVar('T')
U = TypeVar('U')

S = TypeVar('S', bound='SerializableContainer')
P = ParamSpec('P')

FailureDetailsType = dict[str, Any]

#: Represents a data structure created from a JSON input. The main purpose of this type to allow tracking of such data
#: instead of very open and easy to misunderstand ``Any``. A particular name is easier to follow in the code.
#:
#: Since JSON can be as simple as a single integer, ``79``, the type covers the primitive types, too. In reality,
#: our code will encounter mostly complex types, lists of dictionaries (e.g. list of cloud instances), therefore
#: including the primitive types will force users of ``JSONType`` to employ ``cast()`` heavily, to actually reveal
#: the real structure inside the otherwise opaque JSON blob received from a CLI tool. But that **is** a good thing.
JSONType = Union[str, int, float, list[Any], dict[Any, Any], None]


_YAML_DUMPABLE_CLASSES: MutableSet[type[object]] = set()


def get_yaml() -> ruamel.yaml.main.YAML:
    """
    Return a fully initialized instance of YAML processor.
    """

    yaml = gluetool.utils.YAML()

    for cls in _YAML_DUMPABLE_CLASSES:
        yaml.register_class(cls)

    return yaml


def get_logger() -> gluetool.log.ContextAdapter:
    from .knobs import KNOB_LOGGING_JSON, KNOB_LOGGING_LEVEL

    gluetool.color.switch(enabled=True)

    return gluetool.log.Logging.setup_logger(level=KNOB_LOGGING_LEVEL.value, json_output=KNOB_LOGGING_JSON.value)


# This knob needs to live in this module, because its default value includes
# __VERSION__ we can't import from knobs module (circular import).
#
# There is also yet another circular dependency: to render the template, render_template()
# needs KNOB_TEMPLATE_VARIABLE_DELIMITERS, and may fail and then need Failure, which might
# be not imported yet, so we can't use the knob directly, but via a helper get-release()
# which provides the deferred rendering.
_KNOB_RELEASE: Knob[str] = Knob(
    'deployment.release',
    'Optional name of the Artemis release (e.g. "0.0.35", "artemis@v0.0.35", "artemis@{{ __VERSION__ }}, etc.).',
    has_db=False,
    envvar='ARTEMIS_RELEASE',
    cast_from_str=str,
    default=__VERSION__,
)


def get_release() -> str:
    # TODO: for now, hardcode the output
    # There is a cycle of calls (sentry -> get_release -> render_template -> variable boundaries -> Failure -> Sentry)
    # Fixing it will take more work than simple move of functions around.

    return f'artemis@{__VERSION__}'


class TracingOp(enum.Enum):
    """
    Recognized tracing *operation* values.

    Inspired by :py:class:`sentry_sdk.const.OP`.
    """

    FUNCTION = 'function'

    DB = 'db'
    DB_TRANSACTION = 'db.transaction'
    DB_SESSION = 'db.session'
    DB_QUERY = 'db.query'
    DB_QUERY_ONE = 'db.query.one'
    DB_QUERY_ONE_OR_NONE = 'db.query.one_or_none'
    DB_QUERY_ALL = 'db.query.all'
    DB_QUERY_COUNT = 'db.query.count'
    DB_QUERY_DML = 'db.query.dml'

    HTTP_SERVER = 'http.server'
    HTTP_SERVER_MIDDLEWARE = 'http.server.middleware'

    QUEUE_TASK = 'queue.task'
    QUEUE_SUBMIT = 'queue.submit'

    SUBPROCESS = 'subprocess'


SpanT = TypeVar('SpanT', bound=sentry_sdk.tracing.Span)


class Sentry:
    @classmethod
    def _ingest_integrations(cls, logger: gluetool.log.ContextAdapter) -> list[sentry_sdk.integrations.Integration]:
        r_integrations = KNOB_SENTRY_INTEGRATIONS.get_value()

        if r_integrations.is_error:
            r_integrations.unwrap_error().handle(logger, label='Failed to load Sentry integrations', sentry=False)

            return []

        integrations = []

        for integration_name in r_integrations.unwrap().split(','):
            integration_name = integration_name.strip()

            module_name = f'sentry_sdk.integrations.{integration_name}'
            class_name = f'{integration_name.capitalize()}Integration'

            failure_details: dict[str, Any] = {
                'integration_name': integration_name,
                'module_name': module_name,
                'class_name': class_name,
            }

            try:
                module = importlib.import_module(module_name)

            except Exception as exc:
                Failure.from_exc('Failed to import Sentry integration', exc, **failure_details).handle(
                    logger, sentry=False
                )

                return []

            klass = getattr(module, class_name, None)

            if klass is None:
                Failure('Failed to find Sentry integration', **failure_details).handle(logger, sentry=False)

                return []

            try:
                if integration_name == 'logging':
                    # Disable sending any log messages as standalone events
                    integration: sentry_sdk.integrations.Integration = klass(event_level=None)

                else:
                    integration = klass()

            except Exception as exc:
                Failure.from_exc('Failed to instantiate Sentry integration', exc, **failure_details).handle(
                    logger, sentry=False
                )

                return []

            integrations.append(integration)

            logger.info(f'enabled {integration_name} Sentry integration')

        return integrations

    def __init__(self) -> None:
        logger = get_logger()

        self.enabled = False

        if KNOB_SENTRY_DSN.value in (None, 'undefined'):
            return

        self.enabled = True

        if KNOB_SENTRY_DISABLE_CERT_VERIFICATION.value is True:

            def _get_pool_options(
                self: sentry_sdk.transport.HttpTransport, *args: Any, **kwargs: Any
            ) -> dict[str, Any]:
                return {
                    # num_pools is a bit cryptic, but comes from the original method
                    'num_pools': 2,
                    'cert_reqs': 'CERT_NONE',
                }

            sentry_sdk.transport.HttpTransport._get_pool_options = _get_pool_options  # type: ignore[method-assign]

        integrations = Sentry._ingest_integrations(logger)

        # Controls how many variables and other items are captured in event and stack frames. The default
        # value of 10 is pretty small, 1000 should be more than enough for anything we ever encounter.
        sentry_sdk.serializer.MAX_DATABAG_BREADTH = 1000

        traces_sampler: Optional[sentry_sdk._types.TracesSampler]

        if KNOB_SENTRY_TRACING_SAMPLE_PATTERN.value.strip() != '.*':

            def traces_sampler(sampling_context: sentry_sdk._types.SamplingContext) -> float:
                # Use the parent sampling decision if we have an incoming trace.
                # Note: Sentry strongly recommends respecting the parent sampling decision,
                # as this ensures traces will be complete!
                parent_sampling_decision = sampling_context['parent_sampled']

                if parent_sampling_decision is not None:
                    return float(parent_sampling_decision)

                if _SENTRY_TRACING_SAMPLE_PATTERN.match(sampling_context['transaction_context']['name']):
                    return 1.0

                # Do not use the tracing sample rate - we have a valid pattern, trace only code matching the pattern,
                # everything else shall remain "invisible".
                return 0.0

        else:
            traces_sampler = None

        sentry_sdk.init(
            dsn=KNOB_SENTRY_DSN.value,
            release=get_release(),
            environment=KNOB_DEPLOYMENT_ENVIRONMENT.value,
            server_name=platform.node(),
            debug=KNOB_LOGGING_SENTRY.value,
            # We need to override one parameter of on of the default integrations,
            # so we're doomed to list all of them.
            integrations=integrations,
            # This will prevent sentry from auto enabling integrations based on the project dependencies. We are
            # already listing default integrations ourselves and having some form of control is useful to prevent
            # surprises like extensive sentry communication per normal request with middleware for fastapi/starlette
            # integrations.
            default_integrations=False,
            enable_db_query_source=False,
            # Issues
            sample_rate=KNOB_SENTRY_ISSUES_SAMPLE_RATE.value,
            # Tracing
            enable_tracing=KNOB_TRACING_ENABLED.value,
            traces_sample_rate=KNOB_SENTRY_TRACING_SAMPLE_RATE.value,
            traces_sampler=traces_sampler,
            # Profiling
            # We do not use Sentry for profiling
            profiles_sample_rate=0.0,
        )

    @classmethod
    def get_default_tags(cls) -> dict[str, Any]:
        from .knobs import KNOB_DEPLOYMENT, KNOB_DEPLOYMENT_ENVIRONMENT

        tags: dict[str, str] = {}

        # Special tag, "server_name", is used by Sentry for tracking issues per servers.
        tags['server_name'] = platform.node()

        if KNOB_DEPLOYMENT.value:
            tags['deployment'] = KNOB_DEPLOYMENT.value

        # Special tag, "environment", is used by Sentry for tracking issues per environment.
        if KNOB_DEPLOYMENT_ENVIRONMENT.value:
            tags['environment'] = KNOB_DEPLOYMENT_ENVIRONMENT.value

        return tags

    @classmethod
    def get_default_contexts(cls) -> dict[str, dict[str, Any]]:
        from .knobs import KNOB_COMPONENT

        contexts: dict[str, dict[str, Any]] = {}

        # App https://develop.sentry.dev/sdk/event-payloads/contexts/#app-context
        contexts['app'] = {
            'type': 'app',
            'app_identifier': KNOB_COMPONENT.value,
            'app_name': 'Artemis',
            'app_version': get_release(),
        }

        return contexts

    @classmethod
    def _apply_tracing_info(cls, span: SpanT, tags: dict[str, Any], data: dict[str, Any]) -> SpanT:
        for name, value in tags.items():
            span.set_tag(name, value)

        for name, value in data.items():
            span.set_data(name, value)

        return span

    @classmethod
    @contextlib.contextmanager
    def start_transaction(
        cls,
        op: TracingOp,
        description: str,
        scope: Optional[sentry_sdk.Scope] = None,
        tags: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> Generator[sentry_sdk.tracing.Transaction, None, None]:
        """
        Start new tracing transaction.

        :param op: category of the transaction.
        :param description: short, human-readable label describing the transaction.
        :param tags: tags to attach to the transaction. Tags should be simple, trivial, low-cardinality labels that
            maintainers would use for categorizing and searching transactions. Task name, pool name, HTTP method are
            good examples; task call or broker message would not be good tags.

            Additional tags can be added while the transaction is active, as new important pieces of information are
            revealed.
        :param data: additional data to attach to the transaction. Suitable for more complex payload than ``tags``.
            Individual data packages should be the same across the span of transaction and its spans.

            While additional data can be added while the transaction is active, it is not recommended to do so.
        :param context: additional data describing the bigger picture surrounding the transaction.
        """

        scope = scope or sentry_sdk.get_current_scope()

        with scope.start_transaction(op=op.value, name=description) as transaction:
            assert isinstance(transaction, sentry_sdk.tracing.Transaction)

            for name, value in {**cls.get_default_contexts(), **(context or {})}.items():
                transaction.set_context(name, value)

            yield cls._apply_tracing_info(transaction, {**cls.get_default_tags(), **(tags or {})}, data or {})

    @classmethod
    @contextlib.contextmanager
    def start_span(
        cls,
        op: TracingOp,
        description: Optional[str] = None,
        scope: Optional[sentry_sdk.Scope] = None,
        tags: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
    ) -> Generator[sentry_sdk.tracing.Span, None, None]:
        """
        Start new tracing span.

        :param op: category of the span.
        :param description: short, human-readable label describing the span.
        :param tags: tags to attach to the span. Tags should be simple, trivial, low-cardinality labels that maintainers
            would use for categorizing and searching span. Task name, pool name, HTTP method are good examples; task
            call or broker message would not be good tags.

            Additional tags can be added while the span is active, as new important pieces of information are revealed.
        :param data: additional data to attach to the span. Suitable for more complex payload than ``tags``.
            Individual data packages should be the same across the span of transaction and its spans.

            While additional data can be added while the span is active, it is not recommended to do so.
        """

        scope = scope or sentry_sdk.get_current_scope()

        with scope.start_span(op=op.value, name=description) as span:
            yield cls._apply_tracing_info(span, {**cls.get_default_tags(), **(tags or {})}, data or {})


SENTRY = Sentry()


class SerializableContainer:
    """
    Mixin class bringing serialize/unserialize methods for dataclass-based containers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

    # All classes derived from SerializableContainer can be represented as YAML, because they
    # inherit the `to_yaml()` method, which then depends on `serialize()` - and what
    # we can represent as JSON, we can for sure represent as YAML as well.
    #
    # Instead of using decorator to mark classes derived from this one, we let interpreter call
    # this magic method every tim a subclass has been created.
    def __init_subclass__(cls: type['SerializableContainer']) -> None:
        """
        Register given subclass as capable of being represented as YAML.
        """

        super().__init_subclass__()

        _YAML_DUMPABLE_CLASSES.add(cls)

    def __str__(self) -> str:
        """
        Return text representation of the container.

        :returns: human-readable rendering of the container.
        """

        return self.serialize_to_yaml()

    def __repr__(self) -> str:
        """
        Return text representation of the container.

        :returns: human-readable rendering of the container.
        """

        return self.serialize_to_yaml()

    def serialize(self) -> dict[str, Any]:
        """
        Return Python built-in types representing the content of this container.

        Works in a recursive manner, every container member that's a subclass of :py:class:`SerializableContainer`
        is processed as well.

        See :py:meth:`unserialize` for the reversal operation.
        """

        serialized = dataclasses.asdict(self)  # type: ignore[call-overload]

        for field in dataclasses.fields(self):  # type: ignore[arg-type]
            if not inspect.isclass(field.type):
                continue

            if not issubclass(field.type, SerializableContainer):
                continue

            serialized[field.name] = getattr(self, field.name).serialize()

        return cast(dict[str, Any], serialized)

    @classmethod
    def unserialize(cls, serialized: dict[str, Any]) -> Self:
        """
        Create container instance representing the content described with Python built-in types.

        Every container member whose type is a subclass of :py:class:`SerializableContainer` is restored as well.

        See :py:meth:`serialize` for the reversal operation.
        """

        unserialized = cls(**serialized)

        for field in dataclasses.fields(unserialized):  # type: ignore[arg-type]
            if not inspect.isclass(field.type):
                continue

            if not issubclass(field.type, SerializableContainer):
                continue

            if field.name not in serialized:
                continue

            setattr(unserialized, field.name, field.type.unserialize(serialized[field.name]))

        return unserialized

    def serialize_to_json(self) -> str:
        """
        Return JSON blob representing the content of this container.

        Works in a recursive manner, every container member that's a subclass of :py:class:`SerializableContainer`
        is processed as well.

        See :py:meth:`unserialize_from_json` for the reversal operation.
        """

        return json.dumps(self.serialize())

    @classmethod
    def unserialize_from_json(cls, serialized: str) -> Self:
        """
        Create container instance representing the content described with a JSON blob.

        Every container member whose type is a subclass of :py:class:`SerializableContainer` is restored as well.

        See :py:meth:`serialize_to_json` for the reversal operation.
        """

        return cls.unserialize(json.loads(serialized))

    def serialize_to_yaml(self) -> str:
        """
        Return YAML blob representing the content of this container.

        Works in a recursive manner, every container member that's a subclass of :py:class:`SerializableContainer`
        is processed as well.

        See :py:meth:`unserialize_from_yaml` for the reversal operation.
        """

        return format_dict_yaml(self.serialize())

    @classmethod
    def unserialize_from_yaml(cls, serialized: str) -> Self:
        """
        Create container instance representing the content described with a YAML blob.

        Every container member whose type is a subclass of :py:class:`SerializableContainer` is restored as well.

        See :py:meth:`serialize_to_yaml` for the reversal operation.
        """

        return cls.unserialize(get_yaml().load(serialized))

    @classmethod
    def to_yaml(cls, representer: ruamel.yaml.representer.Representer, container: S) -> Any:  # noqa: ANN401
        return representer.represent_dict(container.serialize())


_LOGGING_WRITER_THRESHOLDS = {
    loglevel_name.lower(): loglevel for loglevel_name, loglevel in logging._nameToLevel.items()
}


def is_logging_writer_visible(writer: gluetool.log.LoggingFunctionType) -> bool:
    """
    Check whether the current logging level is high enough for the writer to be actually acting.

    Formatting structures as YAML can be costly. This helper will try to guess whether the given writer would actually
    emit any output given the current loggign level. The guessing is best effort only, trying to match known logging
    method names against :py:mod:`logging` levels.

    :param writer: a logging method to inspect.
    :returns: ``True`` if the ``writer`` name is known, and the current logging level, as set via
        :py:data:`KNOB_LOGGING_LEVEL`, is equal or lower than the loglevel of the same name; ``False`` is returned
        otherwise.
    """

    loglevel_threshold = _LOGGING_WRITER_THRESHOLDS.get(writer.__name__)

    if loglevel_threshold is None:
        return True

    from .knobs import KNOB_LOGGING_LEVEL

    return KNOB_LOGGING_LEVEL.value <= loglevel_threshold


# ruamel.yaml does not narrow the type
_RuamelYamlDataType = Any


# Two logging helpers, very similar to `format_dict` and `log_dict`, but emitting a YAML-ish output.
# YAML is often more readable for humans, and, sometimes, we might use these on purpose, to provide
# more readable output.
#
# TODO: move to gluetool - posibly as a switch to log_dict, no need for a stand-alone functions.
def format_dict_yaml(data: _RuamelYamlDataType) -> str:
    stream = ruamel.yaml.compat.StringIO()

    yaml = get_yaml()

    ruamel.yaml.scalarstring.walk_tree(data)

    def strip_document_end_marker(s: str) -> str:
        s = s.removesuffix('...\n')

        return s.strip()

    yaml.dump(data, stream, transform=strip_document_end_marker)

    return stream.getvalue()


def log_dict_yaml(writer: gluetool.log.LoggingFunctionType, intro: str, data: _RuamelYamlDataType) -> None:
    if not is_logging_writer_visible(writer):
        return

    writer(f'{intro}:\n{format_dict_yaml(data)}', extra={'raw_intro': intro, 'raw_struct': data})


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


_DEFAULT_FAILURE_LOG_LABEL = 'failure'


def _sentry_stringify(
    v: Union[str, sentry_sdk.utils.AnnotatedValue, list[str], list[Union[sentry_sdk.utils.AnnotatedValue, str]], None],
) -> Iterator[str]:
    """
    Convert weird string-ish objects into strings we can use as part of serialized frames in Sentry.

    Sentry SDK uses several types to carry lines of code, deal with all of them.
    """

    if v is None:
        yield ''

    elif isinstance(v, str):
        yield v

    elif isinstance(v, sentry_sdk.utils.AnnotatedValue):
        yield str(v.value)

    elif isinstance(v, list):
        for s in v:
            yield (s.value or '') if isinstance(s, sentry_sdk.utils.AnnotatedValue) else s

    else:
        yield str(v)


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
        *,
        exc_info: Optional[ExceptionInfoType] = None,
        traceback: Optional[_traceback.StackSummary] = None,
        caused_by: Optional['Failure'] = None,
        sentry: Optional[bool] = True,
        recoverable: bool = True,
        fail_guest_request: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[list[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
        task_call: Optional['TaskCall'] = None,
        **details: Any,
    ) -> None:
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

        if task_call:
            self.details['task_call'] = task_call

        if exc_info:
            self.exception = exc_info[1]

            # This is what `traceback.extract_tb` does, but `extract_tb` does not let us save frame locals,
            # and we would like to see them, at least in Sentry.
            self.traceback = _traceback.StackSummary.extract(
                cast(Generator[tuple[FrameType, int], None, None], _traceback.walk_tb(exc_info[2])), capture_locals=True
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
                cast(Generator[tuple[FrameType, int], None, None], _traceback.walk_stack(f)), capture_locals=True
            )
            self.traceback.reverse()

    @classmethod
    def from_exc(
        cls,
        message: str,
        exc: Exception,
        *,
        caused_by: Optional['Failure'] = None,
        sentry: Optional[bool] = True,
        recoverable: bool = True,
        fail_guest_request: bool = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[list[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
        task_call: Optional['TaskCall'] = None,
        **details: Any,
    ) -> 'Failure':
        return Failure(
            message,
            exc_info=(exc.__class__, exc, exc.__traceback__),
            caused_by=caused_by,
            recoverable=recoverable,
            fail_guest_request=fail_guest_request,
            scrubbed_command=scrubbed_command,
            command_output=command_output,
            environment=environment,
            task_call=task_call,
            **details,
        )

    @classmethod
    def from_failure(
        cls,
        message: str,
        caused_by: 'Failure',
        *,
        sentry: Optional[bool] = True,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[list[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
        task_call: Optional['TaskCall'] = None,
        **details: Any,
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
            task_call=task_call,
            **details,
        )

    def update(
        self,
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[list[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
        environment: Optional['Environment'] = None,
        task_call: Optional['TaskCall'] = None,
        **details: Any,
    ) -> 'Failure':
        self.details.update(details)

        if scrubbed_command:
            self.details['scrubbed_command'] = scrubbed_command

        if command_output:
            self.details['command_output'] = command_output

        if environment:
            self.details['environment'] = environment

        if task_call:
            self.details['task_call'] = task_call

        return self

    @classmethod
    def _exception_details(cls, exc: BaseException, scrubbed_command: Optional[list[str]]) -> dict[str, str]:
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
                'type': 'GlueCommandError',
            }

        return {'instance': str(exc), 'type': str(type(exc))}

    @property
    def command_output(self) -> Optional[gluetool.utils.ProcessOutput]:
        return self.details.get('command_output')

    def get_event_details(self) -> dict[str, Any]:
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
            event_details['environment'] = event_details['environment'].serialize()

        if 'task_call' in event_details:
            event_details['task_call'] = event_details['task_call'].serialize()

        if self.caused_by:
            event_details['caused_by'] = self.caused_by.get_event_details()

        if self.sentry_event_url:
            event_details['sentry'] = {'event_id': self.sentry_event_id, 'event_url': self.sentry_event_url}

        return event_details

    @classmethod
    def _serialize_sentry_traceback(
        cls,
        message: str,
        frames: _traceback.StackSummary,
    ) -> dict[str, Any]:
        """
        Based on Sentry's stack trace serialization, this helper takes care of serializing
        a traceback saved by ``Failure`` instance itself, i.e. when there was no exception.
        """

        result = []
        for frame in frames:
            lineno = frame.lineno
            filename = frame.filename
            function = frame.name
            line = frame.line

            frame_result: dict[str, Union[int, str, list[str], dict[str, str], None]] = {
                'abs_path': filename,
                'filename': os.path.relpath(filename, os.getcwd()),
                'module': None,
                'function': function or '<unknown>',
                'lineno': lineno,
            }

            if line is not None and lineno is not None:
                # Lines are indexed from 0, but human representation starts with 1: "1st line".
                # Hence the decrement.
                pre_context, context_line, post_context = sentry_sdk.utils.get_lines_from_file(filename, lineno - 1)

                # Pre/post context is supposed to be a list of lines, the context line a string.
                frame_result.update(
                    {
                        'pre_context': list(_sentry_stringify(pre_context)),
                        'context_line': '\n'.join(_sentry_stringify(context_line)),
                        'post_context': list(_sentry_stringify(post_context)),
                    }
                )

            if frame.locals:
                frame_result['vars'] = frame.locals

            result.append(frame_result)

        return {
            # "Magic" structures, see sentry_sdk.utils for implementation creating these for exceptions.
            'module': None,
            # Type and value are required - but we have none of them, obviously, otherwise we'd use
            # the exception and its type.
            #
            # Instead of an actual type, to comply with the way Sentry displays events with a traceback,
            # we store the failure message as `type`, and ignore the `value` field. This should present
            # nice and good looking event.
            'type': message,
            'value': None,
            'mechanism': {'type': 'generic'},
            'stacktrace': {'frames': result},
        }

    def get_sentry_contexts(self) -> dict[str, dict[str, Any]]:
        contexts: dict[str, dict[str, Any]] = Sentry.get_default_contexts()

        # https://docs.sentry.io/platforms/python/enriching-events/context/#structured-context
        contexts['contexts'] = {
            'guestname': self.details.get('guestname'),
            'poolname': self.details.get('poolname'),
        }

        return contexts

    def get_sentry_cause_details(self, index: int) -> Iterator[dict[str, Any]]:
        """
        Turn the tree of causes of this failure into mappings, suitable for visualisation in Sentry.

        Unlike :py:meth:`get_sentry_details`, this method does not need to fit into objects expected by Sentry
        as we are generating content in one of such objects.

        :yields: mappings, each describing causes of this failure. First the immediate cause, then its cause, and so
            on until reaching the end of the sequence. Each mapping contains only a single key, ``cause.{index}``,
            with ``index`` being incremented for each cause, and the value is a simplified description of the given
            cause. These mappings can be then composed into one final mapping, with keys ``cause.0``, ``cause.1``,
            until ``cause.N`` for hte last cause.
        """

        cause = self.caused_by

        if not cause:
            return

        cause_details = cause.details.copy()

        cause_tags = Sentry.get_default_tags()
        cause_info = {
            'message': cause.message,
            'recoverable': cause.recoverable,
            'fail_guest_request': cause.fail_guest_request,
            'tags': cause_tags,
        }

        if 'scrubbed_command' in cause_details:
            cause_info['scrubbed_command'] = gluetool.utils.format_command_line([cause_details.pop('scrubbed_command')])

        if 'command_output' in cause_details:
            command_output = cause_details.pop('command_output')

            cause_info['stdout'] = process_output_to_str(command_output, stream='stdout')
            cause_info['stderr'] = process_output_to_str(command_output, stream='stderr')

        if 'task_call' in cause_details:
            cause_info['task_call'] = cause_details.pop('task_call').serialize()

        if 'guestname' in cause_details:
            cause_tags['guestname'] = cause_details.pop('guestname')

        if 'poolname' in cause_details:
            cause_tags['poolname'] = cause_details.pop('poolname')

        if cause.traceback:
            cause_info['traceback'] = [
                frame_formatted.strip() for frame_formatted in _traceback.format_list(cause.traceback)
            ]

        cause_info['details'] = cause_details

        yield {f'caused_by.{index}': cause_info}

        yield from cause.get_sentry_cause_details(index + 1)

    def get_sentry_details(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """
        Returns three mappings, data, tags and extra, accepted by Sentry as issue details.
        """

        event: dict[str, Any] = {}
        tags: dict[str, str] = Sentry.get_default_tags()
        extra: dict[str, Any] = self.details.copy()

        extra['message'] = self.message
        extra['recoverable'] = self.recoverable
        extra['fail_guest_request'] = self.fail_guest_request
        extra['env'] = os.environ.copy()

        if 'scrubbed_command' in extra:
            extra['scrubbed_command'] = gluetool.utils.format_command_line([extra['scrubbed_command']])

        if 'command_output' in extra:
            extra['stdout'] = process_output_to_str(extra['command_output'], stream='stdout')
            extra['stderr'] = process_output_to_str(extra['command_output'], stream='stderr')

            del extra['command_output']

        if 'guestname' in self.details:
            tags['guestname'] = self.details['guestname']

        if 'poolname' in self.details:
            tags['poolname'] = self.details['poolname']

        if self.exc_info:
            event, _ = cast(tuple[dict[str, Any], dict[str, Any]], sentry_sdk.utils.event_from_exception(self.exc_info))

        elif self.traceback:
            # Convert our traceback to format understood by Sentry, and store it in `data['stacktrace']` where Sentry
            # expects it to find when generating the message for submission.

            event.update(
                {
                    'level': 'error',
                    'exception': {'values': [Failure._serialize_sentry_traceback(self.message, self.traceback)]},
                }
            )

        if 'environment' in extra:
            extra['environment'] = extra['environment'].serialize()

        if 'task_call' in extra:
            extra['task_call'] = extra['task_call'].serialize()

        event.update({'message': f'Failure: {self.message}'})

        tags.update(
            {key: value for key, value in self.details.items() if key.startswith(('api_request_', 'api_response_'))}
        )

        for caused_by_details in self.get_sentry_cause_details(0):
            extra.update(caused_by_details)

        return event, tags, extra

    def get_log_details(self) -> dict[str, Any]:
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
            details['traceback'] = '\n'.join(
                line.rstrip()
                for line in stackprinter.format(self.exc_info, line_wrap=False).splitlines()  # noqa: FS002
            )

        if 'scrubbed_command' in details:
            details['scrubbed_command'] = gluetool.utils.format_command_line([details['scrubbed_command']])

        if 'command_output' in details:
            command_output = details['command_output']

            details['command_output'] = {
                'stdout': process_output_to_str(command_output, stream='stdout'),
                'stderr': process_output_to_str(command_output, stream='stderr'),
            }

        if 'environment' in details:
            details['environment'] = details['environment'].serialize()

        if 'task_call' in details:
            details['task_call'] = details['task_call'].serialize()

        if self.caused_by:
            details['caused-by'] = self.caused_by.get_log_details()

        if self.sentry_event_url:
            details['sentry'] = {'event_id': self.sentry_event_id, 'event_url': self.sentry_event_url}

        return details

    def _printable(self, label: str = _DEFAULT_FAILURE_LOG_LABEL) -> str:
        return f'{label}\n\n{format_dict_yaml(self.get_log_details())}'

    def __str__(self) -> str:
        return self._printable()

    def __repr__(self) -> str:
        return f'<Failure: message="{self.message}">'

    def log(self, log_fn: gluetool.log.LoggingFunctionType, label: str = _DEFAULT_FAILURE_LOG_LABEL) -> None:
        exc_info = self.exc_info if self.exc_info else (None, None, None)

        log_fn(self._printable(label=label), exc_info=exc_info)

    def submit_to_sentry(self, logger: gluetool.log.ContextAdapter, **additional_tags: Any) -> None:
        if self.submited_to_sentry:
            return

        if not SENTRY.enabled:
            return

        event, tags, extra = self.get_sentry_details()

        event['contexts'] = self.get_sentry_contexts()

        if additional_tags:
            tags.update(additional_tags)

        with sentry_sdk.push_scope() as scope:
            for name, value in tags.items():
                scope.set_tag(name, value)

            for name, value in extra.items():
                scope.set_extra(name, value)

            try:
                self.sentry_event_id = sentry_sdk.capture_event(cast(sentry_sdk.types.Event, event), scope=scope)

            except Exception as exc:
                Failure.from_exc('failed to submit to Sentry', exc).handle(logger, sentry=False)

            else:
                self.submited_to_sentry = True

            if self.sentry_event_id and KNOB_SENTRY_EVENT_URL_TEMPLATE.value:
                render_template(KNOB_SENTRY_EVENT_URL_TEMPLATE.value, EVENT_ID=self.sentry_event_id).map(
                    lambda sentry_event_url: setattr(self, 'sentry_event_url', sentry_event_url)
                ).alt(lambda failure: failure.handle(logger, sentry=False))

    def reraise(self) -> NoReturn:
        if self.exception:
            raise self.exception

        raise Exception('Cannot reraise undefined exception')

    def handle(
        self,
        logger: gluetool.log.ContextAdapter,
        label: str = _DEFAULT_FAILURE_LOG_LABEL,
        *,
        sentry: bool = True,
        **details: Any,
    ) -> None:
        self.details.update(details)

        if sentry:
            self.submit_to_sentry(logger)

        self.log(logger.error, label=label)


def get_config() -> dict[str, Any]:
    from .knobs import KNOB_CONFIG_DIRPATH

    return cast(
        dict[str, Any],
        gluetool.utils.load_yaml(os.path.join(KNOB_CONFIG_DIRPATH.value, 'server.yml'), logger=get_logger()),
    )


def get_worker_name() -> str:
    return f'{platform.node()}-{os.getpid()}-{threading.get_native_id()}'


def get_broker_middleware(logger: gluetool.log.ContextAdapter) -> list[dramatiq.Middleware]:
    from .knobs import (
        KNOB_COMPONENT,
        KNOB_WORKER_MAX_TASKS_PER_PROCESS,
        KNOB_WORKER_PROCESS_METRICS_ENABLED,
        KNOB_WORKER_TRAFFIC_METRICS_ENABLED,
    )

    middleware: list[dramatiq.Middleware] = []

    worker_name = get_worker_name()

    if KNOB_WORKER_MAX_TASKS_PER_PROCESS.value != 0:
        middleware.append(
            artemis_middleware.WorkerMaxTasksPerProcess(
                KNOB_WORKER_MAX_TASKS_PER_PROCESS.value,
                logger,
                # TODO: worker_name made out of node & pid leads to way too many labels!
                # worker_name
                f'worker-{KNOB_COMPONENT.value}',
            )
        )

    if KNOB_WORKER_PROCESS_METRICS_ENABLED.value is True:
        from .knobs import KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK

        middleware.append(artemis_middleware.WorkerMetrics(worker_name, KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK.value))

    if KNOB_WORKER_TRAFFIC_METRICS_ENABLED.value is True:
        middleware.append(artemis_middleware.WorkerTraffic(logger, get_cache(logger), worker_name))

    middleware += [
        artemis_middleware.AgeLimit(),
        dramatiq.middleware.time_limit.TimeLimit(),
        dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
        dramatiq.middleware.callbacks.Callbacks(),
        dramatiq.middleware.GroupCallbacks(dramatiq.rate_limits.backends.stub.StubBackend()),
        dramatiq.middleware.pipelines.Pipelines(),
        artemis_middleware.CurrentMessage(),
        artemis_middleware.Prometheus(),
        artemis_middleware.Retries(),
        periodiq.PeriodiqMiddleware(),
        artemis_middleware.SingletonTask(get_cache(logger)),
    ]

    return middleware


def get_broker(
    logger: gluetool.log.ContextAdapter, application_name: Optional[str] = None
) -> dramatiq.brokers.rabbitmq.RabbitmqBroker:
    from .knobs import KNOB_BROKER_CONFIRM_DELIVERY, KNOB_BROKER_URL

    middleware: list[dramatiq.Middleware] = get_broker_middleware(logger)

    # TODO: for actual limiter, we would need to throw in either Redis or Memcached.
    # Using stub and a dummy key for now, but it's just not going to do its job properly.

    broker_url = KNOB_BROKER_URL.value

    # Client properties must be encoded into URL, Pika does not allow `url` + `client_properties` at the same time.
    client_properties: dict[str, str] = {}

    if application_name is not None:
        client_properties['connection_name'] = application_name

    if client_properties:
        import urllib.parse

        parsed_url = urllib.parse.urlparse(KNOB_BROKER_URL.value)

        parsed_query: dict[str, Union[str, dict[str, str]]] = dict(urllib.parse.parse_qsl(parsed_url.query))

        parsed_query['client_properties'] = client_properties

        broker_url = urllib.parse.ParseResult(
            scheme=parsed_url.scheme,
            netloc=parsed_url.netloc,
            path=parsed_url.path,
            params=parsed_url.params,
            query=urllib.parse.urlencode(parsed_query),
            fragment=parsed_url.fragment,
        ).geturl()

    logger.debug(f'final broker URL is {broker_url}')

    broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
        confirm_delivery=KNOB_BROKER_CONFIRM_DELIVERY.value, middleware=middleware, url=broker_url
    )

    dramatiq.set_broker(broker)

    return broker


def get_cache(logger: gluetool.log.ContextAdapter) -> redis.Redis:
    from .knobs import KNOB_CACHE_URL

    return cast(Callable[[str], redis.Redis], redis.Redis.from_url)(KNOB_CACHE_URL.value)


def get_db(logger: gluetool.log.ContextAdapter, application_name: Optional[str] = None) -> artemis_db.DB:
    """
    Return a DB instance.

    :param logger: logger to use for logging.
    :param application_name: if set, it is passed to DB driver. Some drivers can propagate this string
        down to server level and display it when inspecting DB connections, which may help debugging
        DB operations.
    """

    from .knobs import KNOB_DB_URL

    with Sentry.start_span(TracingOp.DB, tags={'appname': application_name}):
        return artemis_db.DB(logger, KNOB_DB_URL.value, application_name=application_name)


def safe_call(fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> Result[T, Failure]:
    """
    Call given function, with provided arguments.

    :returns: if an exception was raised during the function call, an error result is returned, wrapping the failure.
        Otherwise, a valid result is returned, wrapping function's return value.
    """

    try:
        return Ok(fn(*args, **kwargs))

    except Exception as exc:
        return Error(Failure.from_exc('exception raised inside a safe block', exc))


def safe_call_and_handle(
    logger: gluetool.log.ContextAdapter, fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs
) -> Optional[T]:
    """
    Call given function, with provided arguments. If the call fails, log the resulting failure before returning it.

    .. note::

       Similar to :py:func:`tft.artemis.safe_call`, but

       * does handle the potential failure, and
       * does not return :py:class:`Result` instance but either the bare value or ``None``.

       This is on purpose, because such a helper fits the needs of cache-related helpers we use for tracking
       metrics. The failure to communicate with the case isn't a reason to interrupt the main body of work,
       but it still needs to be reported.

    :param logger: logger to use for logging.
    :param fn: function to decorate.
    :param args: positional arguments of ``fn``.
    :param kwargs: keyword arguments of ``fn``.
    :returns: if an exception was raised during the function call, a failure is logged and ``safe_call_and_handle``
        returns ``None``. Otherwise, the return value of the call is returned.
    """

    try:
        return fn(*args, **kwargs)

    except Exception as exc:
        Failure.from_exc('exception raised inside a safe block', exc).handle(logger)

        return None


def rewrap_to_gluetool(fn: Callable[P, _Result[T, U]]) -> Callable[P, Result[T, U]]:
    def _rewrap_to_gluetool(*args: P.args, **kwargs: P.kwargs) -> Result[T, U]:
        r = fn(*args, **kwargs)

        if is_successful(r):
            return Ok(r.unwrap())

        return Error(r.failure())

    return _rewrap_to_gluetool


#: Custom type for JSON schema. We don't expect the schema structure though, all we do is loading it
#: from a YAML file, then passing it to validators. The actual type could very well be ``Any``, but
#: given how JSON schema looks like, it's pretty much going to be a mapping with string keys. So using
#: this type, and adding our alias to it so we could follow JSON schemas in our code easily.
JSONSchemaType = dict[str, Any]


def construct_validation_schema(data: str) -> Result[JSONSchemaType, Failure]:
    """
    Construct a JSON schema for future use in data validation.

    :param data: raw YAML/JSON data representing the schema.
    """

    r_schema = safe_call(gluetool.utils.from_yaml, data, loader_type='safe')

    if r_schema.is_error:
        return Error(Failure.from_failure('failed to construct schema', r_schema.unwrap_error()))

    return Ok(cast(JSONSchemaType, r_schema.unwrap()))


def load_validation_schema(schema_path: str) -> Result[JSONSchemaType, Failure]:
    """
    Load a JSON schema for future use in data validation.

    :param schema_path: path to a schema file.
    """

    r_schema = safe_call(gluetool.utils.load_yaml, schema_path, loader_type='safe')

    if r_schema.is_error:
        return Error(Failure.from_failure('failed to load schema', r_schema.unwrap_error(), schema_path=schema_path))

    return Ok(cast(JSONSchemaType, r_schema.unwrap()))


def load_packaged_validation_schema(schema_subpath: str) -> Result[JSONSchemaType, Failure]:
    """
    Load a JSON schema for future use in data validation.

    :param schema_subpath: path to a schema file relative to ``schema`` directory in ``tft.artemis`` package.
    """

    root_schema_dirpath = pkg_resources.resource_filename('tft.artemis', 'schema')

    return load_validation_schema(os.path.join(root_schema_dirpath, schema_subpath))


def validate_data(data: JSONType, schema: JSONSchemaType) -> Result[list[str], Failure]:
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


def partition(predicate: Callable[[T], bool], iterable: Iterable[T]) -> tuple[Iterable[T], Iterable[T]]:
    """
    Use a predicate to split the entries of the given iterable into two lists, one for true entries
    and second for false ones.
    """

    iter1, iter2 = itertools.tee(iterable)

    return filter(predicate, iter1), itertools.filterfalse(predicate, iter2)


def logging_filter(
    logger: gluetool.log.ContextAdapter,
    items: list[T],
    filter_name: str,
    filter_callable: Callable[[gluetool.log.ContextAdapter, T], bool],
) -> Generator[T, None, None]:
    for item in items:
        if filter_callable(logger, item):
            log_dict_yaml(logger.debug, f'filter {filter_name}: allowed', item)

            yield item

        else:
            log_dict_yaml(logger.debug, f'filter {filter_name}: denied', item)


# Pre-compile Sentry tracing pattern.
try:
    _SENTRY_TRACING_SAMPLE_PATTERN = re.compile(KNOB_SENTRY_TRACING_SAMPLE_PATTERN.value)

except Exception as exc:
    Failure.from_exc(
        'failed to compile Sentry tracing sample pattern', exc, pattern=KNOB_SENTRY_TRACING_SAMPLE_PATTERN.value
    ).handle(get_logger())

    sys.exit(1)


# Pre-compile template delimiters.
try:
    TEMPLATE_VARIABLE_DELIMITERS = KNOB_TEMPLATE_VARIABLE_DELIMITERS.value.split(',', 1)

except Exception as exc:
    Failure.from_exc(
        'failed to compile template variable delimiters', exc, delimiters=KNOB_TEMPLATE_VARIABLE_DELIMITERS.value
    ).handle(get_logger())

    sys.exit(1)

try:
    TEMPLATE_BLOCK_DELIMITERS = KNOB_TEMPLATE_BLOCK_DELIMITERS.value.split(',', 1)

except Exception as exc:
    Failure.from_exc(
        'failed to compile template block delimiters', exc, delimiters=KNOB_TEMPLATE_BLOCK_DELIMITERS.value
    ).handle(get_logger())

    sys.exit(1)


def _template_filter_shell_quote(s: str) -> str:
    """
    Return a shell-escaped version of the string.

    .. code-block:: jinja

        # "foo bar" -> "'foo bar'"
        {{ "foo bar" | shell_quote }}
    """

    return shlex.quote(s)


def render_template(template: str, **kwargs: Any) -> _Result[str, Failure]:
    try:
        environment = jinja2.Environment(
            variable_start_string=TEMPLATE_VARIABLE_DELIMITERS[0],
            variable_end_string=TEMPLATE_VARIABLE_DELIMITERS[1],
            block_start_string=TEMPLATE_BLOCK_DELIMITERS[0],
            block_end_string=TEMPLATE_BLOCK_DELIMITERS[1],
        )

        environment.filters.update({'shell_quote': _template_filter_shell_quote})

        return _Ok(environment.from_string(template).render(**kwargs).strip())

    except Exception as exc:
        return _Error(Failure.from_exc('failed to render template', exc, template=template, variables=kwargs))


def template_environment(guest_request: Optional[artemis_db.GuestRequest]) -> dict[str, Any]:
    from .knobs import KNOB_DEPLOYMENT, KNOB_DEPLOYMENT_ENVIRONMENT

    env: dict[str, Any] = {
        'DEPLOYMENT': KNOB_DEPLOYMENT.value,
        'DEPLOYMENT_ENVIRONMENT': KNOB_DEPLOYMENT_ENVIRONMENT.value,
    }

    if guest_request is not None:
        env.update(
            {
                'GUEST_REQUEST': guest_request.serialize(),
                'GUESTNAME': guest_request.guestname,
                'ENVIRONMENT': guest_request.environment.serialize(),
            }
        )

    return env


def _rss_factory() -> 'SizeType':
    return UNITS.Quantity(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, UNITS.kilobytes)


@dataclasses.dataclass
class RSSWatcher:
    old_rss: 'SizeType' = dataclasses.field(default_factory=_rss_factory)
    new_rss: Optional['SizeType'] = None

    def snapshot(self) -> None:
        self.new_rss = _rss_factory()

    @property
    def delta(self) -> Optional['SizeType']:
        if self.new_rss is None:
            return None

        return UNITS.Quantity(self.new_rss.to('bytes').magnitude - self.old_rss.to('bytes').magnitude, UNITS.bytes)

    def format(self) -> str:
        delta = self.delta

        if self.new_rss is None or delta is None:
            return f'RSS: {self.old_rss.to("MB"):.2f}'

        return f'RSS: {self.old_rss.to("MB"):.2f} -> {self.new_rss.to("MB"):.2f}, {delta.to("MB"):.2f} delta'
