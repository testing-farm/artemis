import logging

import mock
import pytest

import gluetool
import gluetool_modules.helpers.events

from mock import MagicMock

from . import create_module, testing_asset as _testing_asset, check_loadable


def local_testing_asset(*bits):
    return _testing_asset('events', *bits)


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.helpers.events.Events)[1]

    return module


def register_dummy_handler(module, event_name='dummy-event'):
    mock_callback = MagicMock()
    mock_args = tuple(MagicMock(),)
    mock_kwargs = {'foo': MagicMock()}

    module.register_event_handler(event_name, mock_callback, *mock_args, **mock_kwargs)

    return mock_callback, mock_args, mock_kwargs


@pytest.fixture(name='module_with_handler')
def fixture_module_with_handler(module):
    mock_callback, mock_args, mock_kwargs = register_dummy_handler(module)

    return module, mock_callback, mock_args, mock_kwargs


def test_sanity(module):
    """
    Test whether it is possible to instantiate the module (via including the fixture).
    """


def test_loadable(module):
    """
    Test whether it is possible to load the module via ``gluetool`` native mechanisms.
    """

    check_loadable(module.glue, 'gluetool_modules/helpers/events.py', 'Events')


def test_shared(module):
    """
    Test whether the loaded module provides the shared functions.
    """

    assert module.has_shared('trigger_event')
    assert module.has_shared('register_event_handler')
    assert module.has_shared('unregister_event_handler')


def test_register_event_handler(module_with_handler):
    """
    Test whether registering a handler works.
    """

    module, mock_callback, mock_args, mock_kwargs = module_with_handler

    assert 'dummy-event' in module._handlers
    assert len(module._handlers['dummy-event']) == 1
    assert module._handlers['dummy-event'][0].callback is mock_callback
    assert module._handlers['dummy-event'][0].args == mock_args
    assert module._handlers['dummy-event'][0].kwargs == mock_kwargs


def test_unregister_event_handler(module_with_handler):
    """
    Test whether unregistering a handler works.
    """

    module, mock_callback1, mock_args1, mock_kwargs1 = module_with_handler
    mock_callback2, mock_args2, mock_kwargs2 = register_dummy_handler(module, event_name='dummy-event')

    assert len(module._handlers['dummy-event']) == 2

    module.unregister_event_handler('dummy-event', mock_callback1)

    assert len(module._handlers['dummy-event']) == 1
    assert module._handlers['dummy-event'][0].callback == mock_callback2


def test_unregister_event_handler_with_no_handlers(module_with_handler):
    """
    Test whether unregistering handlers when no handlers are registered for the event does nothing.
    """

    module, mock_callback1, _, _ = module_with_handler

    assert 'dummy-event-2' not in module._handlers

    saved_handlers = {
        event: event_handlers[:] for event, event_handlers in module._handlers.iteritems()
    }

    module.unregister_event_handler('dummy-event-2', MagicMock())

    assert module._handlers == saved_handlers


def test_unregister_event_handler_not_registered(module_with_handler):
    """
    Test whether unregistering unregistered handler changes nothing.
    """

    module, _, _, _ = module_with_handler

    saved_handlers = {
        event: event_handlers[:] for event, event_handlers in module._handlers.iteritems()
    }

    module.unregister_event_handler('dummy-event', MagicMock())

    assert module._handlers == saved_handlers


def test_dispatch_handlers_other_event(module_with_handler):
    """
    Test whether dispatching handlers for an event without any handlers does nothing.
    """

    module, mock_callback1, _, _ = module_with_handler

    module._dispatch_handlers('dummy-event-2')

    mock_callback1.assert_not_called()


def test_dispatch_handlers(module_with_handler):
    """
    Test whether dispatching handlers works.
    """

    module, mock_callback, mock_args, mock_kwargs = module_with_handler

    mock_event_args = tuple(MagicMock())
    mock_event_kwargs = {'bar': MagicMock()}

    final_args = mock_args + mock_event_args
    final_kwargs = mock_kwargs.copy()
    final_kwargs.update(mock_event_kwargs)

    module._dispatch_handlers('dummy-event', *mock_event_args, **mock_event_kwargs)

    mock_callback.assert_called_once_with('dummy-event', *final_args, **final_kwargs)


def test_trigger_event(module, monkeypatch):
    """
    Test whether triggering event via shared function works.
    """

    mock_dispatch_handlers = MagicMock()
    mock_args = tuple(MagicMock())
    mock_kwargs = {'foo': MagicMock()}

    monkeypatch.setattr(module, '_dispatch_handlers', mock_dispatch_handlers)

    module.trigger_event('dummy-event', *mock_args, **mock_kwargs)

    mock_dispatch_handlers.assert_called_once_with('dummy-event', *mock_args, **mock_kwargs)


def test_execute_no_handlers(module):
    """
    Test module execution without any handlers.
    """

    module.execute()

    assert module._handlers == {}


def test_execute(module, monkeypatch):
    """
    Test module execution, it should create handlers for given configuration.
    """

    mock_require_shared = MagicMock(return_value=True)
    mock_shared = MagicMock()
    mock_event_argument = MagicMock()

    module._config['handler-map'] = local_testing_asset('dummy-handlers.yml')

    monkeypatch.setattr(module, 'require_shared', mock_require_shared)
    monkeypatch.setattr(module, 'shared', mock_shared)

    module.execute()

    handlers = module._handlers
    assert 'dummy-event' not in handlers
    assert 'dummy-event-2' not in handlers
    assert 'dummy-event-3' in handlers

    dummy_event_handlers = handlers['dummy-event-3']
    assert len(dummy_event_handlers) == 1

    handler = dummy_event_handlers[0]
    assert handler.callback is not None
    assert handler.callback.func_code.co_name == '_callback'
    assert handler.args == tuple()
    assert handler.kwargs == {
        'commands': [
            'command-1',
            'command-2'
        ]
    }

    module.trigger_event('dummy-event-3', arg=mock_event_argument)

    mock_require_shared.assert_called_once_with('execute_commands')
    mock_shared.assert_called_once_with('execute_commands', ['command-1', 'command-2'], context_extra={
        'arg': mock_event_argument
    })
