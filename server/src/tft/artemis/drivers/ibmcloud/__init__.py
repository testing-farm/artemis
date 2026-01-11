# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import os
import re
import shutil
from collections.abc import Generator
from typing import Any, Optional, TypedDict, cast

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

from ... import Failure, render_template
from ...db import GuestRequest
from ...environment import Flavor
from ...knobs import Knob

# Limits imposed on tags in IBM cloud.
# https://cloud.ibm.com/docs/account?topic=account-tag&interface=ui#limits
#
# The length limit includes the name and colon!
TAG_MAX_LENGTH = 128
# NOTE(ivasilev) IBMCloud is petty about allowed characters in tags - only [A-Z][0-9] _-.: are allowed.
# COLDSTORE_URL is the one of our typical tags that it doesn't play nice with, so will be replacing all
# forbidden characters with prefixes.
TAG_FORBIDDEN_CHARACTERS_PATTERN = re.compile(r'[^.a-zA-Z0-9 _\-]')

KNOB_INSTANCE_NAME_TEMPLATE: Knob[str] = Knob(
    'ibmcloud.mapping.instance-name.template',
    'A pattern for artemis guest name',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_IBMCLOUD_RESOURCE_GROUP_NAME_TEMPLATE',
    cast_from_str=str,
    default='artemis-{{ GUESTNAME }}',
)


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

    instance_name_template = None

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
        # Cornercase - no instance tags assigned
        if tags.get('items') == []:
            return Ok([])

        if not tags.get('items'):
            # No 'items' key discovered in the data that was sent
            return Error(Failure(f'Unexpected output of ibmcloud resource show command for {instance_name}: {tags}'))

        return Ok(tags['items'][0].get('tags', []))

    def get_instance_name(self, guest_request: GuestRequest) -> Result[str, Failure]:
        if not self.instance_name_template:
            r_instance_name_template = KNOB_INSTANCE_NAME_TEMPLATE.get_value(entityname=self.poolname)
            if r_instance_name_template.is_error:
                return Error(Failure('Could not get instance_name template'))

            # Let's set instance name template in the driver class once and for all
            self.instance_name_template = r_instance_name_template.unwrap()

        r_rendered = render_template(
            self.instance_name_template,
            GUESTNAME=guest_request.guestname,
            ENVIRONMENT=guest_request.environment,
        )
        if r_rendered.is_error:
            return Error(Failure('Could not render instance_name template'))

        return Ok(r_rendered.unwrap())

    def list_instances_by_guest_request(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, list_instances_command: list[str]
    ) -> Result[list[dict[str, Any]], Failure]:
        """
        This method will list all allocated instances that correspond to the given guest request.
        Order is newest -> oldest by time of creation.
        """
        with IBMCloudSession(logger, self) as session:
            r_instances_list = session.run(logger, list_instances_command, commandname='ibmcloud.vm-list')

            if r_instances_list.is_error:
                return Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

            # Let's get expected name to match against
            r_expected_name = self.get_instance_name(guest_request)
            if r_expected_name.is_error:
                return Error(
                    Failure.from_failure('failed to get expected instance name', r_expected_name.unwrap_error())
                )
            expected_name = r_expected_name.unwrap()

            res = [
                instance
                for instance in cast(dict[str, Any], r_instances_list.unwrap()).get('pvmInstances', [])
                if instance['name'].startswith(expected_name)
            ]

            # Now order result ourselves by creation date in case ibmcloud API changes
            try:
                res = sorted(res, key=lambda x: datetime.datetime.strptime(x['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ'))
            except ValueError:
                # Something got broken, will need to rely on what ibmcloud sent us
                logger.warning('Double check time format, could not convert time data')

            return Ok(res)

    def show_instance(self, logger: gluetool.log.ContextAdapter, instance_id: str) -> Result[Any, Failure]:
        """This method will show a single instance details."""

        raise NotImplementedError
