# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import smtplib
import socket
from email.mime.text import MIMEText

import gluetool
from gluetool import utils

# Type annotations
from typing import TYPE_CHECKING, List # noqa

if TYPE_CHECKING:
    import gluetool_modules.libs.mail # noqa


class SMTP(gluetool.Module):
    """
    Send e-mails over SMTP.
    """

    name = 'smtp'
    description = 'Send e-mails over SMTP'

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY
    options = [
        ('SMTP options', {
            'smtp-server': {
                'help': 'Outgoing SMTP server (default: %(default)s).',
                'default': 'localhost'
            },
            'smtp-port': {
                'help': 'SMTP server port (default: %(default)s).',
                'type': int,
                'default': 25
            }
        }),
        ('Message options', {
            'archive-bcc': {
                'help': 'If set, it will send copy of every outgoing e-mail to given e-mail addresses.',
                'metavar': 'EMAIL,...',
            },
            'reply-to': {
                'help': """
                        If set, and when a message has no ``Reply-To`` header,
                        this e-mail would be used (default: %(default)s).
                        """,
                'default': None,
                'metavar': 'EMAIL'
            },
            'sender': {
                'help': """
                        If set, and when a message has no sender address set,
                        this e-mail would be used (default: %(default)s).
                        """,
                'default': None,
                'metavar': 'EMAIL'
            }
        })
    ]

    shared_functions = ['send_email', ]

    @utils.cached_property
    def archive_bcc(self):
        # type: () -> List[str]
        """
        List of archive (Bcc) recipients.
        """

        return gluetool.utils.normalize_multistring_option(self.option('archive-bcc'))

    def _lower_message(self, message):
        # type: (gluetool_modules.libs.mail.Message) -> MIMEText
        """
        "Lower" a message from our representation to object understood by Python's SMTP libraries.

        :param gluetool_modules.libs.mail.Message message: the message to lower.
        :rtype: MIMEText
        """

        message.log(self.debug)

        if not message.subject:
            self.warn('E-mail subject is not set')

        if not message.sender:
            if self.option('sender'):
                message.sender = self.option('sender')
            else:
                self.warn('E-mail sender is not set')

        if not message.recipients:
            self.warn('E-mail recipients are not set')

        if not message.reply_to:
            if self.option('reply-to'):
                message.reply_to = self.option('reply-to')
            else:
                self.warn('E-mail Reply-To is not set')

        content = '{}\n\n{}\n\n{}'.format(message.header, message.body, message.footer)

        msg = MIMEText(content)
        msg['Subject'] = message.subject
        msg['From'] = message.sender
        msg['To'] = ', '.join(message.recipients)
        msg['Cc'] = ', '.join(message.cc)

        for name, value in message.xheaders.iteritems():
            msg[name] = value

        if message.reply_to:
            msg.add_header('Reply-To', message.reply_to)

        return msg

    def _send_email(self, message, lowered_message):
        # type: (gluetool_modules.libs.mail.Message, MIMEText) -> None
        """
        Send a single "lowered" message.

        :param gluetool_modules.libs.mail.Message message: the message to send out.
        :param MIMEText lowered_message: "lowered" representation of ``message``.
        """

        if not self.dryrun_allows('Sending an e-mail'):
            return

        self.info('Sending e-mail: from {} to {}, "{}"'.format(
            message.sender, ', '.join(message.recipients), message.subject
        ))

        # Adding our Bcc recipients - not modifying the message, it's read-only from
        # our point of view.
        recipients = message.recipients + message.cc + message.bcc + self.archive_bcc

        gluetool.log.log_dict(self.debug, 'final recipients', recipients)

        try:
            smtp = smtplib.SMTP(self.option('smtp-server'), self.option('smtp-port'))
            # smtplib python2 stubs lack enough annotations. So ignoring type WRT disallow_untyped_calls
            # TODO rm "type: ignore" when python 2 support is removed
            smtp.sendmail(message.sender, recipients, lowered_message.as_string())  # type: ignore
            smtp.quit()  # type: ignore

        except (socket.error, smtplib.SMTPException) as exc:
            self.warn('Cannot send e-mail, SMTP raised an exception: {}'.format(exc), sentry=True)

    def send_email(self, message):
        # type: (gluetool_modules.libs.mail.Message) -> None
        """
        Send an e-mail message.

        :param gluetool_modules.libs.mail.Message message: the message to send out.
        """

        lowered_message = self._lower_message(message)

        self._send_email(message, lowered_message)
