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
    KNOB_INSTANCES_PER_REQUEST_LIMIT,
    CLISessionPermanentDir,
    FlavorBasedPoolDriver,
    PoolData,
    PoolImageInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    Resource,
    Tags,
    create_tempfile,
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
class IBMCloudInstance(Resource):
    id: str
    name: str
    status: str
    created_at: datetime.datetime

    image: PoolImageInfo

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

    def _get_instance_name(self, guest_request: GuestRequest) -> Result[str, Failure]:
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

    def list_instances_by_guest_request(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest
    ) -> Result[list[IBMCloudInstanceT], Failure]:
        """
        This method will list all allocated instances that correspond to the given guest request.
        Order is newest -> oldest by time of creation.
        """
        r_instances_list = self.list_instances(logger)
        if r_instances_list.is_error:
            return Error(Failure.from_failure('failed to list instances', r_instances_list.unwrap_error()))

        # Let's get expected name to match against
        r_expected_name = self._get_instance_name(guest_request)
        if r_expected_name.is_error:
            return Error(Failure.from_failure('failed to get expected instance name', r_expected_name.unwrap_error()))
        expected_name = r_expected_name.unwrap()

        res = [instance for instance in r_instances_list.unwrap() if instance.name.startswith(expected_name)]

        # Now order result ourselves by creation date in case ibmcloud API changes, oldest come first
        try:
            res = sorted(res, key=lambda x: x.created_at)
        except ValueError:
            return Error(Failure('Double check time format, could not convert time data'))

        return Ok(res)

    def do_acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
    ) -> Result[ProvisioningProgress, Failure]:
        r_image_flavor_pairs = self._collect_image_flavor_pairs(logger, session, guest_request)

        if r_image_flavor_pairs.is_error:
            return Error(r_image_flavor_pairs.unwrap_error())

        can_acquire, pairs = r_image_flavor_pairs.unwrap()

        if not can_acquire.can_acquire:
            assert can_acquire.reason is not None

            return Error(Failure(can_acquire.reason.message))

        image, flavor = pairs[0]

        self.log_acquisition_attempt(logger, session, guest_request, flavor=flavor, image=image)

        # Get expected instance name from template
        r_instance_name = self._get_instance_name(guest_request)
        if r_instance_name.is_error:
            return Error(Failure.from_failure('Could not get instance name', r_instance_name.unwrap_error()))
        instance_name = r_instance_name.unwrap()

        # Let's first check that there is no instance tied to this guest_request already. If there is one, then let's
        # use already allocated resources to continue with the provisioning instead of requesting new ones and leaving
        # old instance untracked.
        r_existing_instances: Result[list[IBMCloudInstanceT], Failure] = self.list_instances_by_guest_request(
            logger, guest_request
        )

        if r_existing_instances.is_error:
            return Error(Failure.from_failure('Listing guests failed', r_existing_instances.unwrap_error()))

        # Try to reuse already allocated instances
        existing_instances = r_existing_instances.unwrap()

        if existing_instances:
            # Let's check state first - if the guest is already broken it is of no use to us, while instances in build
            # or active state can be reused.

            pending_instances = [
                instance for instance in existing_instances if instance.is_pending or instance.is_ready
            ]
            error_instances = [instance for instance in existing_instances if instance.is_error]
            leftover_instances = pending_instances[1:] + error_instances

            # Schedule cleanup of resources we won't use
            for leftover in leftover_instances:
                self.dispatch_resource_cleanup(
                    logger,
                    session,
                    IBMCloudPoolResourcesIDs(instance_id=leftover.id),
                    guest_request=guest_request,
                )

            if pending_instances:
                # At least one reusable instance has been found
                # Instances are sorted by provisioning time, let's take the first provisioned one.
                instance_to_use = pending_instances[0]

                if len(pending_instances) > 1:
                    Failure(
                        'Multiple reusable instances found for a guest request',
                        guestname=guest_request.guestname,
                        poolname=self.poolname,
                        instance_ids=[instance.name for instance in pending_instances],
                        chosen_instance=instance_to_use.name,
                    ).handle(logger)

                return Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.PENDING,
                        pool_data=IBMCloudPoolData(instance_id=instance_to_use.id, instance_name=instance_to_use.name),
                        ssh_info=image.ssh,
                    )
                )
            # If we ended up here this means all preallocated resources are in unusable state. At the same time we may
            # not be able to use the expected artemis-GUESTNAME naming as ibmcloud won't allow two instances with the
            # same name. So let's generate a postfix, append it to the expected name, this way the instance will be
            # tracked in a list_instances call among related to this guest request.
            # To avoid going into eternal loop the iterations will be limited by instances_per_request_limit knob,
            # and once exhausted a definitive cancel state will be returned so that request could be given another
            # chance by a different pool.
            claimed_names = {leftover.name for leftover in leftover_instances}

            if instance_name in claimed_names:
                r_max_instances_limit = KNOB_INSTANCES_PER_REQUEST_LIMIT.get_value(entityname=self.poolname)
                if r_max_instances_limit.is_error:
                    return Error(Failure('Could not get max instances per request limit'))

                # Can't use the expected instance_name because there is a leftover resource with this name. Let's try
                # to pick up a new one
                for postfix in range(1, r_max_instances_limit.unwrap()):
                    instance_name = f'{instance_name}-{postfix}'
                    if instance_name not in claimed_names:
                        break
                else:
                    # seems that all allowed names are already claimed by leftover instances, which means something
                    # is wrong -> can't continue
                    return Ok(
                        ProvisioningProgress(
                            state=ProvisioningState.CANCEL,
                            pool_data=IBMCloudPoolData(),
                            pool_failures=[Failure('Too many leftover instances')],
                        )
                    )

        r_post_install_script = self.generate_post_install_script(guest_request)
        if r_post_install_script.is_error:
            return Error(
                Failure.from_failure('Could not generate post-install script', r_post_install_script.unwrap_error())
            )

        post_install_script = r_post_install_script.unwrap()
        if post_install_script:
            with create_tempfile(file_contents=post_install_script) as user_data_file:
                r_output: Result[IBMCloudInstanceT, Failure] = self.create_instance(
                    logger=logger,
                    flavor=flavor,
                    image=image,
                    instance_name=instance_name,
                    user_data_file=user_data_file,
                )
        else:
            r_output = self.create_instance(logger=logger, flavor=flavor, image=image, instance_name=instance_name)

        if r_output.is_error:
            return Error(r_output.unwrap_error())

        created = r_output.unwrap()

        if not created.id:
            return Error(Failure('Instance id not found'))

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=IBMCloudPoolData(instance_id=created.id, instance_name=created.name),
                ssh_info=image.ssh,
            )
        )

    def _show_instance(self, logger: gluetool.log.ContextAdapter, instance_id: str) -> Result[Any, Failure]:
        """This method will show a single instance details."""

        raise NotImplementedError

    def create_instance(
        self,
        logger: gluetool.log.ContextAdapter,
        flavor: Flavor,
        image: PoolImageInfo,
        instance_name: str,
        user_data_file: Optional[str] = None,
    ) -> Result[IBMCloudInstanceT, Failure]:
        """This method will issue a cloud instance create request"""

        raise NotImplementedError

    def list_instances(self, logger: gluetool.log.ContextAdapter) -> Result[list[IBMCloudInstanceT], Failure]:
        """This method will issue a cloud guest list command and return a list of raw instances data"""

        raise NotImplementedError
