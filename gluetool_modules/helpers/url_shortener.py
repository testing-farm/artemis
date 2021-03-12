import requests

import gluetool

# Type annotations
from typing import Optional  # noqa


class URLShortener(gluetool.Module):
    """
    Provides shared function for shortening URLs.

    It can also be used to sanitize URLs that point to internal Red Hat network
    if used with shortener that is accessible only within the internal Red Hat
    network.
    """

    name = 'url-shortener'
    description = 'Provides shared function for shortening URLs.'

    options = [
        ('General options', {
            'shortener-url': {
                'help': 'URL of the shortener.',
                'type': str
            },
        }),
        ('Test options', {
            'print-shortened-url': {
                'help': 'Print shortened url passed as parameter.',
                'type': str
            },
        }),
    ]

    required_options = ['shortener-url']

    shared_functions = ['get_shortened_url']

    def get_shortened_url(self, url, raise_on_error=True, logger=None):
        # type: (str, bool, Optional[gluetool.log.ContextAdapter]) -> str
        """
        Retun the shortened url.

        :param url: The url to be shortened.
        :type url: str
        """

        logger = logger or self.logger

        shortener = '{}?{}'.format(self.option('shortener-url'), url)

        response = requests.get(shortener)

        if response.status_code < 200 or response.status_code > 299:
            try:
                response.raise_for_status()

            except requests.exceptions.HTTPError as e:
                if raise_on_error:
                    raise gluetool.GlueError(str(e))

                logger.warning('Failed to shorten URL: {}'.format(e), sentry=True)

            return url

        return response.text

    def execute(self):
        # type: () -> None

        if self.option('print-shortened-url'):
            self.info(self.get_shortened_url(self.option('print-shortened-url')))
