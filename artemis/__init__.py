import logging
import os
import sys
import traceback as _traceback

import dramatiq
import dramatiq.brokers.rabbitmq
import dramatiq.brokers.stub
import dramatiq.middleware.age_limit
import dramatiq.middleware.time_limit
import dramatiq.middleware.shutdown
import dramatiq.middleware.callbacks
import dramatiq.middleware.retries
import gluetool.log
import gluetool.utils
from gluetool.result import Result, Ok, Error

import artemis.db
import artemis.vault

from typing import cast, Any, Callable, Dict, Optional, Tuple, TypeVar, Union
from types import TracebackType


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


class Failure:
    """
    Bundles exception related info.

    :param tuple exc_info: Exception information as returned by :py:func:`sys.exc_info`.

    :ivar Exception exception: Shortcut to ``exc_info[1]``, if available, or ``None``.
    :ivar tuple exc_info: Exception information as returned by :py:func:`sys.exc_info`.
    :ivar str sentry_event_id: If set, the failure was reported to the Sentry under this ID.
    """

    def __init__(
        self,
        message: str,
        exc_info: Optional[ExceptionInfoType] = None,
        traceback: Optional[_traceback.StackSummary] = None
    ):
        self.message = message
        self.exc_info = exc_info

        self.sentry_event_id: Optional[str] = None
        self.sentry_event_url: Optional[str] = None

        self.exception = None
        self.traceback = None

        if exc_info:
            self.exception = exc_info[1]
            self.traceback = _traceback.extract_tb(exc_info[2])

        if traceback:
            self.traceback = traceback

        if self.traceback is None:
            self.traceback = _traceback.extract_stack()

    @classmethod
    def from_exc(self, message: str, exc: Exception):
        # type: (...) -> Failure

        return Failure(
            message,
            exc_info=(
                exc.__class__,
                exc,
                exc.__traceback__
            )
        )

    def log(
        self,
        log_fn: gluetool.log.LoggingFunctionType,
        label: str = Optional[None]
    ) -> None:
        if label:
            log_fn(
                '{}: {}'.format(label, self.message),
                exc_info=self.exc_info
            )


def get_logger() -> gluetool.log.ContextAdapter:
    return gluetool.log.Logging.setup_logger(
        level=logging.INFO
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
            dramatiq.middleware.shutdown.ShutdownNotifications(),
            dramatiq.middleware.callbacks.Callbacks(),
            dramatiq.middleware.retries.Retries()
        ])

    else:
        broker = dramatiq.brokers.rabbitmq.RabbitmqBroker(
            url=os.getenv('ARTEMIS_BROKER_URL', DEFAULT_BROKER_URL)
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


def safe_call(fn: Callable[..., T], *args: Any, **kwargs: Any) -> Result[T, gluetool.log.ExceptionInfoType]:
    try:
        return Ok(fn(*args, **kwargs))

    except Exception:
        return Error(sys.exc_info())
