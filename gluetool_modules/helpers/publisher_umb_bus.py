# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import copy
import itertools
import time

import gluetool
from gluetool.log import ContextAdapter, LoggerMixin
from gluetool.utils import normalize_path

import proton
import proton.handlers
import proton.reactor

from typing import Any, Dict, List, NamedTuple, Optional, Union  # noqa
from typing_extensions import TypedDict  # noqa

# Proton does not have typing available, change once they are available
ProtonContainer = Any
ProtonEvent = Any
ProtonMessage = Any

DEFAULT_GLOBAL_TIMEOUT = 120
DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_SENDABLE_TIMEOUT = 30

DEFAULT_ON_AUTH_ERROR_RETRIES = 3
DEFAULT_ON_AUTH_ERROR_DELAY = 0.5

EnvironmentType = TypedDict(
    'EnvironmentType',
    {
        'certificate': str,
        'broker-ca': str,
        'topic': str,
        'urls': List[str]
    }
)

UMBErrorDescription = NamedTuple('UMBErrorDescription', (
    ('name', str),
    ('description', str)
))


class ContainerAdapter(ContextAdapter):
    def __init__(self, logger, topic):
        # type: (ContextAdapter, str) -> None
        super(ContainerAdapter, self).__init__(logger, {'ctx_container_url': (100, topic)})


class TestHandler(LoggerMixin, proton.handlers.MessagingHandler):  # type: ignore
    def __init__(self, module, urls, messages, topic, *args, **kwargs):
        # type: (UMBPublisher, List[str], List[ProtonMessage], str, *Any, **Any) -> None
        super(TestHandler, self).__init__(ContainerAdapter(module.logger, topic), *args, **kwargs)

        self._module = module

        self.urls = urls
        self.messages = messages
        self.topic = topic
        self.pending = {}  # type: Dict[str, str]

        self._step_timeout = None
        self._global_timeout = None

        # note: self.error collides with LoggerMixin's self.error
        self.handler_error = None  # type: Optional[UMBErrorDescription]

    def _set_timeout(self, container, name, delay, label):
        # type: (ProtonContainer, str, float, str) -> None
        attr = '_{}_timeout'.format(name)

        self._cancel_timeout(name)

        self.debug('  setting {} timeout to {} seconds: {}'.format(name, delay, label))

        setattr(self, attr, container.schedule(delay, self))

    def _cancel_timeout(self, name):
        # type: (str) -> None
        attr = '_{}_timeout'.format(name)

        task = getattr(self, attr)

        if task is None:
            return

        self.debug('  canceling {} timeout'.format(name))

        task.cancel()
        setattr(self, attr, None)

    def _stop(self, event, stop_container=True, stop_connection=True):
        # type: (ProtonEvent, bool, bool) -> None
        self.debug('  stop because of: {}'.format(event))

        self._cancel_timeout('step')
        self._cancel_timeout('global')

        if event.container and stop_container:
            self.debug('  stopping container!')

            event.container.stop()

        if event.connection and stop_connection:
            self.debug('  stopping connection!')

            event.connection.close()

    def on_start(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_start: {}'.format(event))

        self.handler_error = None

        event.container.connected = False
        ssl = proton.SSLDomain(proton.SSLDomain.MODE_CLIENT)

        assert self._module._environment
        assert isinstance(self._module._environment['certificate'], str)
        certificate = normalize_path(self._module._environment['certificate'])  # type: str
        assert isinstance(self._module._environment['broker-ca'], str)
        broker_ca = normalize_path(self._module._environment['broker-ca'])  # type: str

        ssl.set_credentials(certificate, certificate, None)
        ssl.set_trusted_ca_db(broker_ca)
        ssl.set_peer_authentication(proton.SSLDomain.VERIFY_PEER)
        conn = event.container.connect(urls=self.urls, ssl_domain=ssl)

        event.container.create_sender(conn, target=self.topic)

        self._set_timeout(event.container, 'step', self._module.option('connect-timeout'), 'waiting for connection')
        self._set_timeout(event.container, 'global', self._module.option('global-timeout'), 'global timeout')

    def on_timer_task(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_timer_task: {}'.format(event))

        self.warn('timeout expired, stopping container')

        self._stop(event)

    def on_connection_opened(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_connection_opened: {}'.format(event))

        event.container.connected = True

        self.debug('  connection opened successfully: {}'.format(event.connection.hostname))

        # If we get so far, errors so far has been just transient errors. We have to reset the error
        # signal, because from this point, we could successfully send messages but still signal error
        # by having self.handler_error set, despite the fact it didn't stop us from sending messages.
        self.debug('  resetting error signal')
        self.handler_error = None

        self._set_timeout(event.container, 'step', self._module.option('sendable-timeout'), 'waiting for sendable')

    def on_sendable(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_sendable: {}'.format(event))

        self._cancel_timeout('step')

        self.send_messages(event)  # type: ignore

    def send_messages(self, event):
        # type: (ProtonEvent) -> None
        self.debug('send_messages: {}'.format(event))

        if not self.messages:
            # this should not happen :/
            raise gluetool.GlueError('There are no messages left to send out.')

        for message in self.messages[:]:
            self.debug('  sending the message')
            gluetool.log.log_dict(self.debug, '  header', message.headers)
            gluetool.log.log_dict(self.debug, '  body', message.body)

            pending_message = proton.Message(address=self.topic, body=gluetool.log.format_dict(message.body),
                                             content_type='text/json')
            self.debug('  pending message: {}'.format(pending_message))

            if not self._module.dryrun_allows('Sending messages to the message bus'):
                self.messages.remove(message)
                continue

            delivery = event.sender.send(pending_message)
            self.pending[delivery] = message

        event.sender.close()
        if not self._module.dryrun_allows('Waiting for messages to be sent'):
            self._stop(event)

    def update_pending(self, event):
        # type: (ProtonEvent) -> None
        self.debug('update_pending: {}'.format(event))

        del self.pending[event.delivery]

        if self.pending:
            return

        self.debug('  no more pending messages')

        if self.messages:
            self.debug('  {} messages unsent (rejected or released)'.format(len(self.messages)))

        else:
            self.debug('  all messages successfully sent')

        self._stop(event)

    def on_settled(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_settled: {}'.format(event))

        msg = self.pending[event.delivery]
        self.messages.remove(msg)

        self.update_pending(event)

    def on_rejected(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_rejected: {}'.format(event))

        self.update_pending(event)

    def on_released(self, event):
        # type: (ProtonEvent) -> None
        self.debug('on_released: {}'.format(event))

        self.update_pending(event)

    def _handle_connection_error(self, event_name, message, event, **kwargs):
        # type: (str, str, ProtonEvent, **Any) -> None
        self.debug('{}: {}'.format(event_name, event))

        self.warn('  connection error: {}'.format(message))

        if event.link:
            self.handler_error = UMBErrorDescription(
                name=event.link.remote_condition.name,
                description=event.link.remote_condition.description
            )

        else:
            self.handler_error = UMBErrorDescription(
                name=message,
                description='<no detailed description available>'
            )

        if self.handler_error:
            self.warn('  signaling error {}: {}'.format(self.handler_error.name, self.handler_error.description))

        self._stop(event, **kwargs)

    def on_connection_error(self, event):
        # type: (ProtonEvent) -> None
        self._handle_connection_error('on_connection_error', 'connection error', event)

    def on_link_error(self, event):
        # type: (ProtonEvent) -> None
        self._handle_connection_error('on_link_error', 'link error', event)

    def on_session_error(self, event):
        # type: (ProtonEvent) -> None
        self._handle_connection_error('on_session_error', 'session error', event)

    def on_transport_error(self, event):
        # type: (ProtonEvent) -> None
        self._handle_connection_error('on_transport_error', 'transport error', event,
                                      stop_container=False,
                                      stop_connection=(event.transport.condition.name in self.fatal_conditions))

    def on_transport_tail_closed(self, event):
        # type: (ProtonEvent) -> None
        self._handle_connection_error('on_transport_tail_closed', 'transport error', event,
                                      stop_container=False, stop_connection=False)


class UMBPublisher((gluetool.Module)):
    """
    This module sends messages via Unified Message Bus (UMB).
    """

    name = 'publisher-umb-bus'
    description = 'Sending messages over UMB.'

    options = [
        ('UMB environment options', {
            'environments': {
                'help': 'Definitions of UMB environments.',
                'metavar': 'FILE'
            },
            'environment': {
                'help': 'What environment to use.'
            }
        }),
        ('Timeout options', {
            'connect-timeout': {
                'help': 'Wait at max N second before giving up on a broker connection (default: %(default)s).',
                'type': int,
                'metavar': 'N',
                'default': DEFAULT_CONNECT_TIMEOUT
            },
            'sendable-timeout': {
                'help': """
                        Wait at max N second before giving up before broker allows message sending
                        (default: %(default)s)).
                        """,
                'type': int,
                'metavar': 'N',
                'default': DEFAULT_SENDABLE_TIMEOUT
            },
            'global-timeout': {
                'help': 'Wait at max N second before giving up on the whole publishing action (default: %(default)s).',
                'type': int,
                'metavar': 'N',
                'default': DEFAULT_GLOBAL_TIMEOUT
            },
            'on-error-retries': {
                'help': """
                        When broker responds with an error, try to connect and repeat procedure N times
                        (default: %(default)s).
                        """,
                'type': int,
                'metavar': 'N',
                'default': DEFAULT_ON_AUTH_ERROR_RETRIES
            },
            'on-error-delay': {
                'help': """
                        Delay between each retry of ``--on-error-retries`` should be N seconds
                        (default: %(default)s).
                        """,
                'type': float,
                'metavar': 'N',
                'default': DEFAULT_ON_AUTH_ERROR_DELAY
            }
        })
    ]

    required_options = ('environments', 'environment')
    shared_functions = ['publish_bus_messages']

    supported_dryrun_level = gluetool.glue.DryRunLevels.ISOLATED

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(UMBPublisher, self).__init__(*args, **kwargs)

        self._environment = None  # type: Optional[EnvironmentType]

    def publish_bus_messages(self, messages, topic=None, **kwargs):
        # type: (Union[List[Any], Any], Optional[str], **Any) -> None
        """
        Publish one or more message to the message bus.

        A message is an object with two properties:

            * ``headers`` - a ``dict`` representing `headers` of the message,
            * ``body`` - an objet representing the actual data being send over the bus. Its actual
              type depends entirely on the message, it can be ``dict`` or``list`` or any other primitive
              type.

        :param list messages: Either ``list`` or a single `message`.
        :param str topic: If set, overrides the bus topic set by the configuration.
        :raises gluetool.GlueError: When there are messages that module failed to send.
        """

        orig_args = (copy.copy(messages),)
        orig_kwargs = gluetool.utils.dict_update({}, kwargs, {'topic': topic})

        assert self._environment
        topic = topic or self._environment.get('topic')

        if not topic:
            raise gluetool.GlueError('No topic to send message to, cannot continue')

        if not isinstance(messages, list):
            messages = [messages]

        messages_count = len(messages)

        isolated_run = False
        if not self.isolatedrun_allows('Connecting to message bus'):
            isolated_run = True

        if not isolated_run:
            for i in itertools.count(start=1):
                self.info('Publishing {} messages on the UMB, attempt #{}'.format(messages_count, i))

                # We used to create container just once, but suddenly, SEGFAULTs start to pop up when
                # code tried to retry sending messages, using the pre-created container, by calling its
                # `run()`. maybe we don't understand it fully...
                #
                # As a workaround, let's create the container from the scratch for each attempt.

                assert topic
                assert self._environment and self._environment['urls']
                handler = TestHandler(self, self._environment['urls'], messages, topic)
                container = proton.reactor.Container(handler)
                container.run()

                # Everything went fine (probably) because handler signals no error
                if handler.handler_error is None:
                    break

                # Here should come breaking in case of fatal errors, should we need it.
                # ...

                self.warn('Retrying because of error: {}'.format(handler.handler_error.name), sentry=True)

                if i == self.option('on-error-retries') + 1:
                    self.warn('Ran out of allowed retry attempts, giving up on message bus')
                    break

                time.sleep(self.option('on-error-delay'))

        if not messages:
            self.info('{} messages successfully sent'.format(messages_count))

        if messages and not isolated_run:
            raise gluetool.GlueError('Could not send all the messages, {} remained.'.format(len(messages)))

        self.overloaded_shared('publish_bus_messages', *orig_args, **orig_kwargs)

    def execute(self):
        # type: () -> None
        environments = gluetool.utils.load_yaml(self.option('environments'), logger=self.logger)

        self._environment = environments.get(self.option('environment'), None)

        if self._environment is None:
            raise gluetool.GlueError("No such environment '{}'".format(self.option('environment')))
