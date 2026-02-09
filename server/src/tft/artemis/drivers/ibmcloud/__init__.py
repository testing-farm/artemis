# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import functools
import os
import re
import shutil
from collections.abc import Generator
from typing import Any, Generic, Optional, TypedDict, TypeVar, cast

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result
from returns.pipeline import is_successful

from tft.artemis.drivers import (
    CLISessionPermanentDir,
    FlavorBasedPoolDriver,
    Instance,
    PoolData,
    PoolImageInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ResourceManager,
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
    envvar='ARTEMIS_IBMCLOUD_INSTANCE_NAME_TEMPLATE',
    cast_from_str=str,
    default='artemis-{{ GUESTNAME }}',
)

IBMCLOUD_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


@dataclasses.dataclass
class IBMCloudInstance(Instance):
    status: str
    created_at: datetime.datetime

    def __post_init__(self) -> None:
        self.status = self.status.lower()

    @functools.cached_property
    def is_pending(self) -> bool:
        raise NotImplementedError

    @functools.cached_property
    def is_ready(self) -> bool:
        raise NotImplementedError

    @functools.cached_property
    def is_error(self) -> bool:
        raise NotImplementedError

    def serialize(self) -> dict[str, Any]:
        serialized = super().serialize()

        if self.created_at:
            serialized['created_at'] = self.created_at.strftime(IBMCLOUD_DATETIME_FORMAT)

        return serialized

    @classmethod
    def unserialize(cls, serialized: dict[str, Any]) -> 'IBMCloudInstance':
        instance = super().unserialize(serialized)

        if serialized['created_at']:
            instance.created_at = datetime.datetime.strptime(serialized['created_at'], IBMCLOUD_DATETIME_FORMAT)

        return instance


IBMCloudInstanceT = TypeVar('IBMCloudInstanceT', bound=IBMCloudInstance)


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


class IBMCloudDriver(FlavorBasedPoolDriver[PoolImageInfo, IBMCloudFlavor], Generic[IBMCloudInstanceT]):
    drivername = 'abstract-ibmcloud-driver'

    flavor_info_class = IBMCloudFlavor
    pool_data_class = IBMCloudPoolData

    datetime_format = IBMCLOUD_DATETIME_FORMAT

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: dict[str, Any],
    ) -> None:
        super().__init__(logger, poolname, pool_config)
        self.instance_resource_manager = ResourceManager(
            logger=logger,
            pool=self,
            resource_type='instance',
            resource_list_callback=self.list_instances_by_guest_request,
            resource_create_callback=self.create_guest,
            resource_identifier_callback=self.get_instance_name,
        )

    @classmethod
    def timestamp_to_datetime(cls, timestamp: str) -> Result[datetime.datetime, Failure]:
        try:
            return Ok(datetime.datetime.strptime(timestamp, IBMCLOUD_DATETIME_FORMAT))
        except Exception as exc:
            return Error(
                Failure.from_exc(
                    'failed to parse timestamp', exc, timestamp=timestamp, strptime_format=IBMCLOUD_DATETIME_FORMAT
                )
            )

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
        r_instance_name_template = KNOB_INSTANCE_NAME_TEMPLATE.get_value(entityname=self.poolname)
        if r_instance_name_template.is_error:
            return Error(Failure('Could not get instance_name template'))

        r_rendered = render_template(
            r_instance_name_template.unwrap(),
            GUESTNAME=guest_request.guestname,
            ENVIRONMENT=guest_request.environment,
        )
        if not is_successful(r_rendered):
            return Error(Failure('Could not render instance_name template'))

        return Ok(r_rendered.unwrap())

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        r_instance = self.instance_resource_manager.acquire(logger, guest_request, session)
        if r_instance.is_error:
            return Ok(
                ProvisioningProgress(
                    state=ProvisioningState.CANCEL,
                    pool_data=IBMCloudPoolData(),
                    pool_failures=[r_instance.unwrap_error()],
                )
            )

        instance = r_instance.unwrap()
        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=IBMCloudPoolData(instance_id=instance.id, instance_name=instance.name),
                ssh_info=instance.image.ssh,
            )
        )

    def list_instances_by_guest_request(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest
    ) -> Result[list[IBMCloudInstanceT], Failure]:
        """
        This method will list all allocated instances that correspond to the given guest request.
        Order is newest -> oldest by time of creation.
        """
        # Let's get expected name to match against
        r_expected_name = self.get_instance_name(guest_request)
        if r_expected_name.is_error:
            return Error(Failure.from_failure('failed to get expected instance name', r_expected_name.unwrap_error()))
        expected_name = r_expected_name.unwrap()

        r_instances_list = self.list_instances(logger, name_filter=expected_name)
        if r_instances_list.is_error:
            return Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

        res = r_instances_list.unwrap()

        # Now order result ourselves by creation date in case ibmcloud API changes, oldest come first
        try:
            res = sorted(res, key=lambda x: x.created_at)
        except ValueError:
            return Error(Failure('Double check time format, could not convert time data'))

        return Ok(res)

    def _show_instance(self, logger: gluetool.log.ContextAdapter, instance_id: str) -> Result[Any, Failure]:
        """This method will show a single instance details."""

        raise NotImplementedError

    def create_instance(  # type: ignore[override]
        self,
        logger: gluetool.log.ContextAdapter,
        flavor: Flavor,
        image: PoolImageInfo,
        instance_name: str,
        user_data_file: Optional[str] = None,
    ) -> Result[IBMCloudInstanceT, Failure]:
        """This method will issue a cloud instance create request"""

        raise NotImplementedError

    def list_instances(
        self, logger: gluetool.log.ContextAdapter, name_filter: Optional[str] = None
    ) -> Result[list[IBMCloudInstanceT], Failure]:
        """This method will issue a cloud guest list command and return a list of raw instances data"""

        raise NotImplementedError
