# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
import smtplib
import socket

import mock
import pytest

import gluetool
import gluetool_modules.helpers.smtp
import gluetool_modules.libs.mail

from mock import MagicMock

from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(gluetool_modules.helpers.smtp.SMTP)[1]


@pytest.fixture(name='mock_smtp')
def fixture_mock_smtp(monkeypatch):
    mock_SMTP = MagicMock()
    mock_SMTP.sendmail = MagicMock()
    mock_SMTP.mock_quit = MagicMock()

    mock_SMTP_klass = MagicMock(return_value=mock_SMTP)

    monkeypatch.setattr(smtplib, 'SMTP', mock_SMTP_klass)

    return mock_SMTP


@pytest.fixture(name='mock_message')
def fixture_mock_message(module):
    mock_message = MagicMock()
    mock_lowered_message = MagicMock()
    mock_lower_message = MagicMock(return_value=mock_lowered_message)

    monkeypatch.setattr(module, '_lower_message', mock_lower_message)

    return mock_message


@pytest.fixture(name='mock_messages')
def fixture_mock_messages():
    mock_message = gluetool_modules.libs.mail.Message(
        sender='dummy sender',
        recipients=['foo', 'bar'],
        cc=['baz']
    )
    mock_lowered_message = MagicMock(as_string=MagicMock(return_value='dummy message'))

    return mock_message, mock_lowered_message


def test_sanity(module):
    """
    Test whether it is possible to instantiate the module (via including the fixture).
    """


def test_loadable(module):
    """
    Test whether it is possible to load the module via ``gluetool`` native mechanisms.
    """

    check_loadable(module.glue, 'gluetool_modules/helpers/smtp.py', 'SMTP')


def test_shared(module):
    """
    Test whether the loaded module provides the shared functions.
    """

    assert module.has_shared('send_email')


def test_archive_bcc_unset(module):
    assert module.archive_bcc == []


def test_archive_bcc(module):
    module._config['archive-bcc'] = ['foo,bar', 'baz']

    assert module.archive_bcc == ['foo', 'bar', 'baz']


def test_send_email_private(module, mock_smtp, mock_messages, monkeypatch):
    mock_message, mock_lowered_message = mock_messages

    module._send_email(mock_message, mock_lowered_message)

    mock_lowered_message.as_string.assert_called_once()
    mock_smtp.sendmail.assert_called_once_with('dummy sender', ['foo', 'bar', 'baz'], 'dummy message')
    mock_smtp.quit.assert_called_once()


@pytest.mark.parametrize('mock_exception', [
    socket.error('dummy exception'),
    smtplib.SMTPException('dummy exception')
])
def test_send_email_private_error(module, mock_smtp, mock_messages, mock_exception, log, monkeypatch):
    mock_message, mock_lowered_message = mock_messages

    mock_smtp.sendmail.side_effect = mock_exception

    module._send_email(mock_message, mock_lowered_message)

    mock_lowered_message.as_string.assert_called_once()
    mock_smtp.sendmail.assert_called_once_with('dummy sender', ['foo', 'bar', 'baz'], 'dummy message')
    mock_smtp.quit.assert_not_called()

    assert log.match(message='Cannot send e-mail, SMTP raised an exception: dummy exception', levelno=logging.WARN)


def test_send_email(module, mock_messages, monkeypatch):
    mock_message, mock_lowered_message = mock_messages

    mock_lower_message = MagicMock(return_value=mock_lowered_message)
    mock_send_email = MagicMock()

    monkeypatch.setattr(module, '_lower_message', mock_lower_message)
    monkeypatch.setattr(module, '_send_email', mock_send_email)

    module.send_email(mock_message)

    mock_lower_message.assert_called_once_with(mock_message)
    mock_send_email.assert_called_once_with(mock_message, mock_lowered_message)


def test_lower_message(module, mock_messages, log):
    mock_message, _ = mock_messages

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == mock_message.sender
    assert lowered_message['To'] == ', '.join(mock_message.recipients)
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] is None

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail sender is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail recipients are not set')


def test_lower_message_with_reply_to(module, mock_messages, log):
    mock_message, _ = mock_messages

    mock_message.reply_to = 'dummy reply-to'

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == mock_message.sender
    assert lowered_message['To'] == ', '.join(mock_message.recipients)
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] == 'dummy reply-to'

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail sender is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail recipients are not set')


def test_lower_message_with_reply_to_from_option(module, mock_messages, log):
    mock_message, _ = mock_messages

    module._config['reply-to'] = 'dummy reply-to'

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == mock_message.sender
    assert lowered_message['To'] == ', '.join(mock_message.recipients)
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] == 'dummy reply-to'

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail sender is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail recipients are not set')


def test_lower_message_without_sender(module, mock_messages, log):
    mock_message, _ = mock_messages

    mock_message.sender = None

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == mock_message.sender
    assert lowered_message['To'] == ', '.join(mock_message.recipients)
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] is None

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert log.match(levelno=logging.WARNING, message='E-mail sender is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail recipients are not set')


def test_lower_message_with_sender_from_option(module, mock_messages, log):
    mock_message, _ = mock_messages

    mock_message.sender = None
    module._config['sender'] = 'dummy sender'

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == 'dummy sender'
    assert lowered_message['To'] == ', '.join(mock_message.recipients)
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] is None

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail recipients are not set')


def test_lower_message_without_recipients(module, mock_messages, log):
    mock_message, _ = mock_messages

    mock_message.recipients = []

    lowered_message = module._lower_message(mock_message)

    assert lowered_message['Subject'] == mock_message.subject
    assert lowered_message['From'] == mock_message.sender
    assert lowered_message['To'] == ''
    assert lowered_message['Cc'] == ', '.join(mock_message.cc + module.archive_bcc)

    assert lowered_message['Reply-To'] is None

    assert log.match(levelno=logging.WARNING, message='E-mail subject is not set')
    assert not log.match(levelno=logging.WARNING, message='E-mail sender is not set')
    assert log.match(levelno=logging.WARNING, message='E-mail recipients are not set')
