# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import os
import re
import shutil
from collections.abc import Generator
from typing import Optional, TypedDict, cast

import gluetool.log
from gluetool.result import Error, Ok, Result

from tft.artemis.drivers import (
    CLISessionPermanentDir,
    FlavorBasedPoolDriver,
    PoolData,
    PoolImageInfo,
    PoolResourcesIDs,
    Tags,
)

from ... import Failure
from ...environment import Flavor

# Limits imposed on tags in IBM cloud.
# https://cloud.ibm.com/docs/account?topic=account-tag&interface=ui#limits
#
# The length limit includes the name and colon!
TAG_MAX_LENGTH = 128
# NOTE(ivasilev) IBMCloud is petty about allowed characters in tags - only [A-Z][0-9] _-.: are allowed.
# COLDSTORE_URL is the one of our typical tags that it doesn't play nice with, so will be replacing all
# forbidden characters with prefixes.
TAG_FORBIDDEN_CHARACTERS_PATTERN = re.compile(r'[^.a-zA-Z0-9 _\-]')


@dataclasses.dataclass
class IBMCloudPoolData(PoolData):
    instance_id: Optional[str] = None
    instance_name: Optional[str] = None


@dataclasses.dataclass
class IBMCloudPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    assorted_resource_ids: Optional[list[dict[str, str]]] = None


@dataclasses.dataclass
class IBMCloudFlavor(Flavor):
    numa_count: Optional[int] = None


class IBMResourceInfoType(TypedDict):
    name: str
    tags: list[str]


def _sanitize_tags(tags: Tags) -> Generator[tuple[str, str], None, None]:
    """
    Sanitize tags to make their values acceptable for IBM API and CLI.

    Namely replace forbidden characters with more acceptable ones.
    """

    def _sanitize_string(s: str) -> str:
        return TAG_FORBIDDEN_CHARACTERS_PATTERN.sub('_', s)

    for name, value in tags.items():
        name = _sanitize_string(name)
        value = _sanitize_string(value or '')

        if len(name) >= TAG_MAX_LENGTH:
            yield name[:TAG_MAX_LENGTH], ''

        elif value:
            yield name, value[: TAG_MAX_LENGTH - len(name) - 1]

        else:
            yield name, ''


def _serialize_tags(tags: Tags) -> list[str]:
    """
    Serialize tags to make them acceptable for IBM CLI.

    IBM accepts tags in form of ``key:value`` items, separated by comma:

    .. code-block:: python

       foo:bar,baz,...

    See https://cloud.ibm.com/docs/account?topic=account-tag&interface=ui for more details.
    """

    return [f'{name}:{value}' if value else name for name, value in _sanitize_tags(tags)]


class IBMCloudSession(CLISessionPermanentDir):
    CLI_PREFIX = 'ibmcloud'
    CLI_CMD = 'ibmcloud'
    CLI_CONFIG_DIR_ENV_VAR = 'IBMCLOUD_HOME'

    PLUGINS_DIR = '.bluemix/plugins'

    def _login(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        assert self.pool.pool_config['api-key']
        r_login = self._run_cmd(
            logger,
            [
                'login',
                '--apikey',
                self.pool.pool_config['api-key'],
                '-r',
                self.pool.pool_config['default-region'],
                # Do not ask if existing plugins need update, trust the process
                '-q',
            ],
            json_format=False,
            commandname='ibmcloud.login',
        )
        if r_login.is_error:
            return Error(Failure.from_failure('failed to log into tenant', r_login.unwrap_error()))

        return Ok(None)

    def _prepare_session_dir(self, logger: gluetool.log.ContextAdapter) -> Result[None, Failure]:
        plugins_abspath = os.path.join(self.session_dir_path, self.PLUGINS_DIR)
        # If there is no plugins in the session dir -> need to install some for driver to work. Plugins directory will
        # be created after a call to login, but it will be holding just a configuration file. To make sure there
        # are plugins there we'll need to check for subdirectories in the plugins dir.
        try:
            if next(os.walk(plugins_abspath))[1]:
                return Ok(None)
        except StopIteration:
            # Well, the plugins directory is not there at all - definitely need to install something
            pass

        # Make sure pool configuration has installed-plugins-dir defined, then copy its contents under plugins_dir
        # as is
        assert self.pool.pool_config['installed-plugins-dir']
        try:
            shutil.copytree(self.pool.pool_config['installed-plugins-dir'], plugins_abspath)
        except (shutil.Error, OSError) as exc:
            return Error(Failure.from_exc('failed to copy plugins from pool config dir', exc))

        return Ok(None)


class IBMCloudDriver(FlavorBasedPoolDriver[PoolImageInfo, IBMCloudFlavor]):
    drivername = 'abstract-ibmcloud-driver'

    flavor_info_class = IBMCloudFlavor
    pool_data_class = IBMCloudPoolData

    def tag_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        instance_name: str,
        tags: Tags,
    ) -> Result[None, Failure]:
        instance_tags = ','.join(_serialize_tags(tags))
        logger.debug(f'Adding the following tags to instance {instance_name}: {instance_tags}')

        with IBMCloudSession(logger, self) as ibm_session:
            r_tag_instance = ibm_session.run(
                logger,
                [
                    'resource',
                    'tag-attach',
                    '--tag-names',
                    instance_tags,
                    '--resource-name',
                    instance_name,
                ],
                json_format=False,
                commandname='ibmcloud.tag-attach',
            )

        if r_tag_instance.is_error:
            return Error(
                Failure.from_failure(f'Tagging instance {instance_name} failed', r_tag_instance.unwrap_error())
            )
        return Ok(None)

    def get_instance_tags(self, logger: gluetool.log.ContextAdapter, instance_name: str) -> Result[list[str], Failure]:
        with IBMCloudSession(logger, self) as ibm_session:
            r_instance_tags = ibm_session.run(
                logger,
                ['resource', 'search', f'name:{instance_name}', '--json'],
                json_format=True,
                commandname='ibmcloud.resource-get',
            )

        if r_instance_tags.is_error:
            return Error(
                Failure.from_failure(
                    f'Locating ibmcloud resource associated with {instance_name} failed', r_instance_tags.unwrap_error()
                )
            )

        tags = cast(dict[str, list[IBMResourceInfoType]], r_instance_tags.unwrap())
        if not tags.get('items'):
            # No such resource found
            return Error(Failure(f'Unexpected output of ibmcloud resource show command for {instance_name}: {tags}'))
        return Ok(tags['items'][0].get('tags', []))
