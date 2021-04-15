# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
import re
import ftplib

from six.moves.urllib.parse import urlsplit
from gluetool.utils import cached_property, render_template
from gluetool.log import log_dict


class ComposeUrl(gluetool.Module):
    """
    Provides compose url. Source of the url could be:
        * Static compose url obtained from `static-compose-url` option
        * OSCI compose url deduced from `primary-task`

    Note: Static compose url has higher priority
    """
    name = 'compose-url'
    description = 'Provides compose url.'

    options = [
        ('OSCI compose options', {
            'hostname': {
                'help': 'address of server, where OSCI composes are stored, including protocol, eg http://'
            },
            'directory-path-template': {
                'help': 'template for compose directory path'
            },
            'name-regex-template': {
                'help': 'template for regex for compose directory name matching'
            }
        }),
        ('Static compose options', {
            'static-compose-url': {
                'help': 'Url of compose, which will be provided to rest of pipeline'
            }
        })
    ]

    shared_functions = ['get_compose_url']

    @cached_property
    def directory_path(self):
        directory_path_template = self.option('directory-path-template')

        if directory_path_template is None:
            return None

        return render_template(directory_path_template, logger=self.logger, **self.shared('eval_context'))

    @cached_property
    def name_regex(self):
        name_regex_template = self.option('name-regex-template')

        if name_regex_template is None:
            return None

        return render_template(name_regex_template, logger=self.logger, **self.shared('eval_context'))

    @cached_property
    def osci_compose_url(self):
        """
        Generates compose url from primary_task object.

        :requires: ``primary_task`` shared function (from brew, koji and the likes)
        :returns: ``str`` with url to packages of particular brew build
        """
        self.require_shared('primary_task')
        primary_task = self.shared('primary_task')

        hostname = self.option('hostname')

        compose_regex = re.compile(r'{}\/{}'.format(re.escape(self.directory_path), self.name_regex))

        try:
            ftphost = urlsplit(hostname).netloc
        except Exception as exc:
            raise gluetool.GlueError('urlsplit failed to parse "{}" with error: {}'.format(hostname, exc))

        if not ftphost:
            raise gluetool.GlueError("urlsplit returned empty string")
        else:
            try:
                ftp = ftplib.FTP(ftphost)
                ftp.login()
                composes_dirs = ftp.nlst(self.directory_path)
                ftp.close()
            except ftplib.all_errors as ftperror:
                raise gluetool.GlueError("ftplib returned an error: {}".format(ftperror))

        # Apply pattern to all composes_dirs.
        # This will yield many "no match" values (match returns None), but we'll get rid of them later.
        matches = [(comp, compose_regex.match(comp)) for comp in composes_dirs]

        log_dict(self.debug, 'Pattern matches on found compose directories', matches)

        # Find the biggest match group, but consider only actual matches,
        # skipping those "no match" values mentioned above.
        try:
            winning_pair = max(
                [(compose, match) for compose, match in matches if match],
                key=lambda pair: int(pair[1].group(1))
            )
        except ValueError:
            raise gluetool.SoftGlueError(
                "Unable to find OSCI compose for {} ({}) in '{}' directory".format(
                    primary_task.component,
                    primary_task.id,
                    self.directory_path
                )
            )

        compose = winning_pair[0]

        compose_url = '{}/{}'.format(hostname, compose)

        self.info('OSCI compose found: {}'.format(compose_url))

        return compose_url

    def sanity(self):
        hostname = self.option('hostname')
        static_compose_url = self.option('static-compose-url')

        if not (hostname or static_compose_url):
            raise gluetool.GlueError('Either --hostname or --static-compose-url has to be specified.')

        if hostname and static_compose_url:
            self.warn('Both --hostname and --static-compose-url specified, --static-compose-url will be used.')

    def get_compose_url(self):
        static_compose_url = self.option('static-compose-url')

        if static_compose_url:
            self.info('Using static compose url: {}'.format(static_compose_url))
            return static_compose_url

        return self.osci_compose_url
