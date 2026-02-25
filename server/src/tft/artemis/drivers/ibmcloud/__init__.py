# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import abc
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
from returns.result import Failure as _Error, Result as _Result, Success as _Ok

from tft.artemis.drivers import (
    BackendFlavorT,
    CLISessionPermanentDir,
    ConsoleUrlData,
    FlavorBasedPoolDriver,
    Instance,
    PoolData,
    PoolImageInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ResourceCreationOutcome,
    ResourceCreationRequest,
    ResourceManager,
    Tags,
)

from ... import Failure, render_template, rewrap_to_gluetool
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
class IBMCloudPoolData(PoolData):
    instance_id: Optional[str] = None
    instance_name: Optional[str] = None


@dataclasses.dataclass
class IBMCloudPoolResourcesIDs(PoolResourcesIDs):
    instance_id: Optional[str] = None
    assorted_resource_ids: Optional[list[dict[str, str]]] = None


@dataclasses.dataclass
class IBMCloudInstance(Instance):
    status: str
    created_at: datetime.datetime

    def __post_init__(self) -> None:
        self.status = self.status.lower()

    @abc.abstractmethod
    @functools.cached_property
    def is_pending(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    @functools.cached_property
    def is_ready(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    @functools.cached_property
    def is_error(self) -> bool:
        raise NotImplementedError

    def to_pool_resource_ids(self) -> IBMCloudPoolResourcesIDs:
        return IBMCloudPoolResourcesIDs(instance_id=self.id)

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
class IBMCloudFlavor(Flavor):
    numa_count: Optional[int] = None


class IBMResourceInfoType(TypedDict):
    name: str
    tags: list[str]


@dataclasses.dataclass
class InstanceCreationRequest(ResourceCreationRequest):
    flavor: Flavor
    image: PoolImageInfo
    tags: Optional[Tags] = None
    post_install_script: Optional[str] = None


@dataclasses.dataclass
class InstanceCreationOutcome(ResourceCreationOutcome[IBMCloudInstanceT]):
    flavor: Flavor
    image: PoolImageInfo


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


class IBMCloudDriver(
    FlavorBasedPoolDriver[PoolImageInfo, IBMCloudFlavor, BackendFlavorT, IBMCloudInstanceT],
    abc.ABC,
    Generic[IBMCloudInstanceT, BackendFlavorT],
):
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
        self.instance_resource_manager: ResourceManager[
            IBMCloudInstanceT, InstanceCreationRequest, InstanceCreationOutcome[IBMCloudInstanceT]
        ] = ResourceManager(
            logger=logger,
            pool=self,
            resource_type='instance',
            list_resources=self._query_instances_by_guest_request,
            resource_name=self._render_instance_name,
            create_resource_request=self._create_instance_request,
            create_resource=self._create_instance,
            reuse_resource=self._reuse_instance,
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

    def _render_instance_name(self, guest_request: GuestRequest) -> _Result[str, Failure]:
        r_instance_name_template = KNOB_INSTANCE_NAME_TEMPLATE.get_value(entityname=self.poolname)
        if r_instance_name_template.is_error:
            return _Error(
                Failure.from_failure('Could not get instance_name template', r_instance_name_template.unwrap_error())
            )

        return render_template(
            r_instance_name_template.unwrap(),
            GUESTNAME=guest_request.guestname,
            ENVIRONMENT=guest_request.environment,
        ).alt(lambda failure: Failure.from_failure('Could not render instance name template', failure))

    def _create_instance_request(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
    ) -> _Result[InstanceCreationRequest, Failure]:
        r_image_flavor_pairs = self._collect_image_flavor_pairs(logger, session, guest_request)

        if r_image_flavor_pairs.is_error:
            return _Error(r_image_flavor_pairs.unwrap_error())

        can_acquire, pairs = r_image_flavor_pairs.unwrap()

        if not can_acquire.can_acquire:
            assert can_acquire.reason is not None

            return _Error(Failure(can_acquire.reason.message))

        instance_request = InstanceCreationRequest(image=pairs[0][0], flavor=pairs[0][1])

        self.log_acquisition_attempt(
            logger, session, guest_request, flavor=instance_request.flavor, image=instance_request.image
        )

        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return _Error(
                Failure.from_failure('Could not generate post-install script', r_post_install_script.unwrap_error())
            )

        instance_request.post_install_script = r_post_install_script.unwrap()

        return _Ok(instance_request)

    def _query_instances_by_guest_request(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest
    ) -> _Result[list[IBMCloudInstanceT], Failure]:
        """
        Fetch list of instances for a given guest request from the backend infrastructure.

        :returns: list of instances, sorted by their time of creation, from the newest to the oldest.
        """

        r_instances_list = self.list_instances(logger)
        if r_instances_list.is_error:
            return _Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

        # Let's get expected name to match against
        r_expected_name = self._render_instance_name(guest_request)
        if not is_successful(r_expected_name):
            return _Error(Failure.from_failure('failed to get expected instance name', r_expected_name.failure()))
        expected_name = r_expected_name.unwrap()

        res = [instance for instance in r_instances_list.unwrap() if instance.name.startswith(expected_name)]

        # Now order result ourselves by creation date in case ibmcloud API changes, oldest come first
        try:
            res = sorted(res, key=lambda x: x.created_at)
        except ValueError:
            return _Error(Failure('Double check time format, could not convert time data'))

        return _Ok(res)

    @rewrap_to_gluetool
    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> _Result[ProvisioningProgress, Failure]:
        return (
            self.instance_resource_manager.acquire(logger, guest_request, session)
            .bind(
                lambda instance_outcome: _Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.PENDING,
                        pool_data=IBMCloudPoolData(
                            instance_id=instance_outcome.resource.id, instance_name=instance_outcome.resource.name
                        ),
                        ssh_info=instance_outcome.image.ssh,
                    )
                )
            )
            .lash(
                lambda failure: _Error(failure)
                if failure.recoverable
                else _Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=IBMCloudPoolData(),
                        pool_failures=[failure],
                    )
                )
            )
        )

    @abc.abstractmethod
    def _show_instance(self, logger: gluetool.log.ContextAdapter, instance_id: str) -> Result[Any, Failure]:
        """This method will show a single instance details."""

        raise NotImplementedError

    @abc.abstractmethod
    def _create_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_name: str,
        instance_request: InstanceCreationRequest,
    ) -> _Result[InstanceCreationOutcome[IBMCloudInstanceT], Failure]:
        """
        Create new instance.

        Send requests or invoke commands to instruct the backend infrastructure to create new instance for the given
        guest request.
        """

        raise NotImplementedError

    def _reuse_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        instance_request: InstanceCreationRequest,
        instance: IBMCloudInstanceT,
    ) -> _Result[InstanceCreationOutcome[IBMCloudInstanceT], Failure]:
        """
        Reuse existing instance.
        """

        return _Ok(
            InstanceCreationOutcome(
                resource=instance,
                flavor=instance_request.flavor,
                image=instance_request.image,
            )
        )

    @abc.abstractmethod
    def list_instances(self, logger: gluetool.log.ContextAdapter) -> Result[list[IBMCloudInstanceT], Failure]:
        """This method will issue a cloud guest list command and return a list of raw instances data"""

        raise NotImplementedError

    # The following are necessary implementations of abstract methods the driver does not have use for. They are
    # required, but we will remove them in the future.
    def acquire_console_url(
        self, logger: gluetool.log.ContextAdapter, guest: GuestRequest
    ) -> Result[ConsoleUrlData, Failure]:
        return Error(Failure('unsupported driver method', poolname=self.poolname, method='acquire_console_url'))
