import logging
import os
import traceback as _traceback
import urllib.parse

import dramatiq
import dramatiq.brokers.rabbitmq
import dramatiq.brokers.stub
import dramatiq.middleware.age_limit
import dramatiq.middleware.time_limit
import dramatiq.middleware.shutdown
import dramatiq.middleware.callbacks
import gluetool.log
import gluetool.sentry
import gluetool.utils
from gluetool.result import Result, Ok, Error
import ruamel.yaml
import ruamel.yaml.compat
import sqlalchemy.orm.session
import periodiq


from . import db as artemis_db
from . import vault as artemis_vault
from . import middleware as artemis_middleware

from typing import cast, Any, Callable, Dict, List, NoReturn, Optional, Tuple, TypeVar, Union
from types import TracebackType

import stackprinter

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


DEFAULT_CONFIG_DIR = os.getcwd()
DEFAULT_BROKER_URL = 'amqp://guest:guest@127.0.0.1:5672'
DEFAULT_DB_URL = 'sqlite:///test.db'
DEFAULT_VAULT_PASSWORD_FILE = '~/.vault_password'

DEFAULT_RABBITMQ_HEARTBEAT_TIMEOUT = 60
"""
RabbitMQ client should ping the server over established connection to keep both parties
aware the connection should be kept alive.
"""

DEFAULT_RABBITMQ_BLOCKED_TIMEOUT = 300

# Gluetool Sentry instance
gluetool_sentry = gluetool.sentry.Sentry()


def format_struct_as_yaml(data: Any) -> str:
    stream = ruamel.yaml.compat.StringIO()

    YAML = gluetool.utils.YAML()

    ruamel.yaml.scalarstring.walk_tree(data)

    YAML.dump(data, stream)

    return cast(str, stream.getvalue())


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
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
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

        if scrubbed_command:
            self.details['scrubbed_command'] = scrubbed_command

        if command_output:
            self.details['command_output'] = command_output

        if exc_info:
            self.exception = exc_info[1]
            self.traceback = _traceback.extract_tb(exc_info[2])

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
        # these are common "details" so we add them as extra keyword arguments with their types
        scrubbed_command: Optional[List[str]] = None,
        command_output: Optional[gluetool.utils.ProcessOutput] = None,
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
            scrubbed_command=scrubbed_command,
            command_output=command_output,
            **details
        )

    def get_event_details(self) -> Dict[str, Any]:
        """
        Returns a mapping of failure details, suitable for storing in DB as a guest event details.
        """

        event_details = self.details.copy()

        event_details['message'] = self.message

        # We don't want command or its output in the event details - hard to serialize, full of secrets, etc.
        event_details.pop('command_output', None)
        event_details.pop('scrubbed_command', None)

        # Guestname will be provided by event instance itself, no need to parse it as event details
        event_details.pop('guestname', None)

        if self.caused_by:
            event_details['caused_by'] = self.caused_by.get_event_details()

        return event_details

    def get_sentry_details(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Returns two mappings, tags and extra, accepted by Sentry as issue details.
        """

        tags: Dict[str, str] = {}
        extra: Dict[str, Any] = {}

        extra['message'] = self.message

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

        if self.caused_by:
            caused_by_tags, caused_by_extra = self.caused_by.get_sentry_details()

            extra['caused_by'] = {
                'tags': caused_by_tags,
                'extra': caused_by_extra
            }

        return tags, extra

    def get_log_details(self) -> Dict[str, Any]:
        """
        Returns a mapping of failure details, suitable for logging subsystem.
        """

        details = self.details.copy()

        details['message'] = self.message

        if 'scrubbed_command' in details:
            details['scrubbed_command'] = gluetool.utils.format_command_line([details['scrubbed_command']])

        if 'command_output' in details:
            command_output = details['command_output']

            details['command_output'] = {}

            # This is a workaround for one problem in gluetool's ProcessOutput - it's stderr/stdout
            # are declared as strings, but often can contain bytes, because gluetool still sits
            # in Python 2 world :/
            if isinstance(command_output.stdout, bytes):
                details['command_output']['stdout'] = command_output.stdout.decode('utf-8')

            else:
                details['command_output']['stdout'] = command_output.stdout

            if isinstance(command_output.stderr, bytes):
                details['command_output']['stderr'] = command_output.stderr.decode('utf-8')

            else:
                details['command_output']['stderr'] = command_output.stderr

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

        tags, extra = self.get_sentry_details()

        if additional_tags:
            tags.update(additional_tags)

        self.sentry_event_id = gluetool_sentry.submit_message(
            'Failure: {}'.format(self.message),
            exception=self.exception if self.exception else '<no exception>',
            traceback=self.traceback,
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


def get_logger() -> gluetool.log.ContextAdapter:
    gluetool.color.switch(True)

    return gluetool.log.Logging.setup_logger(
        level=getattr(logging, os.getenv('ARTEMIS_LOG_LEVEL', 'INFO')),
        json_output=gluetool.utils.normalize_bool_option(os.getenv('ARTEMIS_LOG_JSON', 'yes')),
        sentry=gluetool_sentry
    )


def get_config() -> Dict[str, Any]:
    config_dir = os.path.expanduser(os.getenv('ARTEMIS_CONFIG_DIR', DEFAULT_CONFIG_DIR))

    return cast(
        Dict[str, Any],
        gluetool.utils.load_yaml(
            os.path.join(config_dir, 'server.yml'),
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
            artemis_middleware.Retries(),
            periodiq.PeriodiqMiddleware()
        ])

    else:
        # We need a better control over some aspects of our broker connection, e.g. heartbeat
        # and timeouts. This is possible, but we cannt use broker URL as a argument, this is
        # not supported with Dramatiq and Pika. Therefore, we need to parse the URL and construct
        # connection parameters, with expected content, and add more details when needed.

        import pika

        broker_url = os.getenv('ARTEMIS_BROKER_URL', DEFAULT_BROKER_URL)
        parsed_url = urllib.parse.urlparse(broker_url)

        broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
            middleware=[
                dramatiq.middleware.age_limit.AgeLimit(),
                dramatiq.middleware.time_limit.TimeLimit(),
                dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
                dramatiq.middleware.callbacks.Callbacks(),
                artemis_middleware.Retries(),
                periodiq.PeriodiqMiddleware()
            ],
            parameters=[{
                'host': parsed_url.hostname,
                'port': int(parsed_url.port),
                'credentials': pika.PlainCredentials(parsed_url.username, parsed_url.password),
                'heartbeat': int(os.getenv('ARTEMIS_BROKER_HEARTBEAT_TIMEOUT', DEFAULT_RABBITMQ_HEARTBEAT_TIMEOUT)),
                'blocked_connection_timeout': int(
                    os.getenv('ARTEMIS_BROKER_BLOCKED_TIMEOUT', DEFAULT_RABBITMQ_BLOCKED_TIMEOUT)
                ),
            }]
        )

    dramatiq.set_broker(broker)

    return broker


def get_db_url() -> str:
    return os.getenv('ARTEMIS_DB_URL', DEFAULT_DB_URL)


def get_db(logger: gluetool.log.ContextAdapter) -> artemis_db.DB:
    return artemis_db.DB(
        logger,
        get_db_url()
    )


def get_vault() -> artemis_vault.Vault:
    password_filepath = os.path.expanduser(
        os.getenv('ARTEMIS_VAULT_PASSWORD_FILE', DEFAULT_VAULT_PASSWORD_FILE)
    )

    with open(password_filepath, 'r') as f:
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


def safe_db_execute(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    expected_rows: int = 1
) -> Result[bool, Failure]:
    """
    Execute a given SQL query, followed by an explicit commit.

    The main purpose of this function is to provide helper for queries that modify database state with respect
    to concurrent access. We often need to update records in a way that works as a sort of a locking, providing
    a consistent, serialized access. We need to prepare the query, execute it, commit the transaction and make
    sure it updated/deleted the expected amount of records - all these steps can be broken by exceptions.

    :returns: if the commit was successfull, a valid result is returned. If the commit failed,
        .e.g. because another thread changed the database content and made the query invalid,
        an error result is returned, wrapping the failure.
    """

    logger.warning('safe execute: {}'.format(str(query)))

    r = safe_call(session.execute, query)

    if r.is_error:
        failure = r.unwrap_error()

        return Error(
            Failure(
                'failed to execute query: {}'.format(failure.message),
                caused_by=failure
            )
        )

    query_result = cast(
        sqlalchemy.engine.ResultProxy,
        r.value
    )

    if query_result.rowcount != expected_rows:
        logger.warning('expected {} matching rows, found {}'.format(expected_rows, query_result.rowcount))

        return Ok(False)

    r = safe_call(session.commit)

    if r.is_ok:
        logger.warning('found {} matching rows, as expected'.format(query_result.rowcount))

        return Ok(True)

    return Error(
        Failure(
            'failed to commit query: {}'.format(r.unwrap_error().message),
            caused_by=r.unwrap_error()
        )
    )


def log_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    eventname: str,
    **details: Any
) -> None:
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
        r.unwrap_error().handle(
            logger,
            label='failed to store guest event',
            guestname=guestname,
            eventname=eventname
        )

        logger.warning('failed to log event {}'.format(eventname))
        return

    gluetool.log.log_dict(logger.info, 'logged event {}'.format(eventname), details)


def log_error_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    message: str,
    failure: Failure
) -> None:
    """ Create event log record for guest """

    log_guest_event(
        logger,
        session,
        guestname,
        'error',
        error=message,
        **{
            'failure': failure.get_event_details()
        }
    )
