import logging
import os
import traceback as _traceback

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
import sqlalchemy.orm.session

import artemis.db
import artemis.vault
import artemis.middleware

from typing import cast, Any, Callable, Dict, NoReturn, Optional, Tuple, TypeVar, Union
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


DEFAULT_CONFIG_DIR = os.getcwd()
DEFAULT_BROKER_URL = 'amqp://guest:guest@127.0.0.1:5672'
DEFAULT_DB_URL = 'sqlite:///test.db'
DEFAULT_VAULT_PASSWORD_FILE = '~/.vault_password'

# Gluetool Sentry instance
gluetool_sentry = gluetool.sentry.Sentry()


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
        parent: Optional['Failure'] = None,
        sentry: Optional[bool] = True,
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

        self.parent = parent

        self.command_output: Optional[gluetool.utils.ProcessOutput] = command_output

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
            command_output=command_output,
            **details
        )

    def get_event_details(self) -> Dict[str, Any]:
        event_details = self.details.copy()

        # We don't want command or its output in the event details - hard to serialize, full of secrets, etc.
        event_details.pop('command_output', None)
        event_details.pop('scrubbed_command', None)
        # Guestname will be provided by event instance itself, no need to parse it as event details
        event_details.pop('guestname', None)

        return event_details

    def get_sentry_details(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:

        tags = {}
        extra = {}

        if 'scrubbed_command' in self.details:
            extra['scrubbed_command'] = gluetool.utils.format_command_line(self.details['scrubbed_command'])

        if 'command_output' in self.details:
            extra['stderr'] = self.details['command_output'].stderr

        if 'guestname' in self.details:
            tags['guestname'] = self.details['guestname']

        if 'poolname' in self.details:
            tags['poolname'] = self.details['poolname']

        return tags, extra

    def log(
        self,
        log_fn: gluetool.log.LoggingFunctionType,
        label: str = Optional[None]
    ) -> None:
        exc_info = self.exc_info if self.exc_info else (None, None, None)

        if label:
            # Sometimes label already contains message
            if self.message in label:
                msg = label
            else:
                msg = '{}: {}'.format(label, self.message)
        else:
            msg = self.message

        items = [msg]

        if 'scrubbed_command' in self.details:
            items += [
                '',
                'COMMAND:',
                gluetool.utils.format_command_line([self.details['scrubbed_command']])
            ]

        if self.command_output:

            items += [
                '',
                'STDERR:',
                gluetool.log.format_blob(self.command_output.stderr or '')
            ]

        log_fn(
            '\n'.join(items),
            exc_info=exc_info,
            extra=self.details
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


def get_logger() -> gluetool.log.ContextAdapter:
    gluetool.color.switch(True)

    return gluetool.log.Logging.setup_logger(
        level=logging.INFO,
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
            artemis.middleware.Retries()
        ])

    else:
        broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
            url=os.getenv('ARTEMIS_BROKER_URL', DEFAULT_BROKER_URL),
            middleware=[
                dramatiq.middleware.age_limit.AgeLimit(),
                dramatiq.middleware.time_limit.TimeLimit(),
                dramatiq.middleware.shutdown.ShutdownNotifications(notify_shutdown=True),
                dramatiq.middleware.callbacks.Callbacks(),
                artemis.middleware.Retries()
            ]
        )

    dramatiq.set_broker(broker)

    return broker


def get_db_url() -> str:
    return os.getenv('ARTEMIS_DB_URL', DEFAULT_DB_URL)


def get_db(logger: gluetool.log.ContextAdapter) -> artemis.db.DB:
    return artemis.db.DB(
        logger,
        get_db_url()
    )


def get_vault() -> artemis.vault.Vault:
    password_filepath = os.path.expanduser(
        os.getenv('ARTEMIS_VAULT_PASSWORD_FILE', DEFAULT_VAULT_PASSWORD_FILE)
    )

    with open(password_filepath, 'r') as f:
        return artemis.vault.Vault(f.read())


def safe_call(fn: Callable[..., T], *args: Any, **kwargs: Any) -> Result[T, Failure]:
    """
    Call given function, with provided arguments.

    :returns: if an exception was raised during the function call, an error result is returned, wrapping the failure.
        Otherwise, a valid result is returned, wrapping function's return value.
    """

    try:
        return Ok(fn(*args, **kwargs))

    except Exception as exc:
        return Error(Failure.from_exc('failed to execute {}'.format(fn.__name__), exc))


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
                parent=failure
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
            parent=r.unwrap_error()
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
        artemis.db.GuestEvent(
            guestname=guestname,
            eventname=eventname,
            **details
        )
    )

    logger.warning('logged guest request event {}: guestname={} details={}'.format(
        eventname,
        guestname,
        details)
    )


def log_error_guest_event(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    error: Failure,
    label: str,
    sentry: bool = False,
    **details: Any
) -> None:
    """ Create error event log record for guest """

    error.log(logger.error, label='{}: {}: '.format(label, guestname))

    if details:
        error.details.update(details)

    log_guest_event(logger, session, guestname, 'error', error=error.message, **error.get_event_details())

    if sentry:
        error.submit_to_sentry()
