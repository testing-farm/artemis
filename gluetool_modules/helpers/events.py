# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.log import log_dict


# Type annotations
from typing import Any, Callable, Dict, List, Optional, NamedTuple, Tuple  # noqa

#: Represents an event handler, with its arguments
#:
#: :ivar callable callback: function to call to handle the event.
#: :ivar tuple args: additional positional arguments.
#: :ivar dict kwargs: additional keyword arguments.
EventCallback = Callable[..., None]
EventHandler = NamedTuple('EventHandler', (
        ('callback', EventCallback),
        ('args', Tuple[Any, ...]),
        ('kwargs', Dict[Any, Any])
    ))


class Events(gluetool.Module):
    """
    Let modules trigger and react to arbitrary events, defined by modules. Other modules can subscribe
    to events and run their code in reaction.

    Event names
    ===========

    Events are defined simply by the fact that a module calls ``trigger_event`` shared function
    with a name of the event - at this moment, the event of the given name exists, and disappears
    when all registered handlers are dispatched. There is no global table of allowed events,
    it all depends on producers.

    Global handlers
    ===============

    It is possible to setup "global" handlers by preparing a YAML file - or multiple such files - which
    is then given to ``--handler-map`` option.

    .. code-block:: yaml

       ---

       - event: <event #1 name>
         <action>:
           <action parameters>

    At this moment, the only supported action is ``execute-commands``. Its ``parameters`` is a list of commands
    as accepted by ``execute-command`` module. These commands are run when the event triggers. Templating is
    supported (by ``execute-command`` module), and event arguments are injected into the templating context when
    rendering the final command shape.

    .. code-block:: yaml

       - event: restraint-runner.test-set-finished
         execute-commands:
           - scp -r {{ output.directory }} foo@bar.baz:/cold-storage/{{ guest.environment.arch }}
    """

    name = 'events'

    options = {
        'handler-map': {
            'help': 'Path to a map of global handlers (default: none).',
            'action': 'append',
            'type': str,
            'default': []
        }
    }

    shared_functions = ['trigger_event', 'register_event_handler', 'unregister_event_handler']

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(Events, self).__init__(*args, **kwargs)

        self._handlers = {}  # type: Dict[str, List[EventHandler]]

    def register_event_handler(self, event, callback, *args, **kwargs):
        # type: (str, EventCallback, *Any, **Any) -> None
        """
        Register an event handler.

        A handler (``callback``) is a function accepting at least one positional argument, the name
        of the triggered event which is given as the first argument. Additional positional and
        keyword arguments are constructed using two sources:

        * arguments provided by the event - module triggering the event may provide several positional
          and keyword arguments, describing the properties of the event;
        * arguments provided when registering the handler.

        Arguments provided when registering the event are used first, then those from event are added.

        :param str event: name of the event.
        :param callable callback: function to call.
        :param tuple args: additional positional arguments for the callback.
        :param dict kwargs: additional keyword arguments for the callback.
        """

        log_dict(self.debug, 'register handler {} for event {}'.format(callback, event), (args, kwargs))

        if event not in self._handlers:
            self._handlers[event] = []

        handler = EventHandler(callback=callback, args=args, kwargs=kwargs)

        self._handlers[event].append(handler)

    def unregister_event_handler(self, event, callback):
        # type: (str, EventCallback) -> None
        """
        Unregister a previosly registered event handler.

        :param str event: name of the event.
        :param callable callback: callback used when registering the handler.
        """

        self.debug('unregister handler {} for event {}'.format(callback, event))

        if event not in self._handlers:
            return

        self._handlers[event] = [
            handler for handler in self._handlers[event] if handler.callback != callback
        ]

    def _dispatch_handlers(self, event, *args, **kwargs):
        # type: (str, *Any, **Any) -> None
        """
        Dispatch all handlers registered for an event.

        :param str event: the name of the event.
        :param tuple args: event positional arguments.
        :param dict kwargs: event keyword arguments.
        """

        log_dict(self.debug, 'dispatch handlers for event {}'.format(event), (args, kwargs))

        if event not in self._handlers:
            return

        for handler in self._handlers[event]:
            final_args = handler.args + args
            final_kwargs = gluetool.utils.dict_update({}, handler.kwargs, kwargs)

            log_dict(self.debug, 'dispatching handler {}'.format(handler.callback), (final_args, final_kwargs))

            handler.callback(event, *final_args, **final_kwargs)

    def trigger_event(self, event, *args, **kwargs):
        # type: (str, *Any, **Any) -> None
        """
        Trigger the event. Results in dispatching of all handlers registered for an event.

        :param str event: the name of the event.
        :param tuple args: event positional arguments.
        :param dict kwargs: event keyword arguments.
        """

        self.info('triggering event {}'.format(event))

        self._dispatch_handlers(event, *args, **kwargs)

    def execute(self):
        # type: () -> None
        if not self.option('handler-map'):
            return

        for handler_map_path in gluetool.utils.normalize_path_option(self.option('handler-map')):
            handler_map = gluetool.utils.load_yaml(handler_map_path, logger=self.logger)

            for handler_description in handler_map:
                event = handler_description['event']

                if 'execute-commands' in handler_description:
                    # Dummy, one-purpose callback that just passes commands from a map down to the shared
                    # function of execute-command module. Event arguments are passed as an extra context.
                    def _callback(triggered_event, commands=None, **kwargs):
                        # type: (Any, Optional[List[str]], **Any) -> None
                        self.require_shared('execute_commands')

                        self.shared('execute_commands', commands, context_extra=kwargs)

                    self.register_event_handler(event, _callback, commands=handler_description['execute-commands'])
