# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import os
import re
import stat
import threading
from typing import Any, Dict, List, Optional, Tuple, cast

import bs4
import gluetool.log
import gluetool.utils
import pint
import sqlalchemy.orm.session
from gluetool.log import log_xml
from gluetool.result import Error, Ok, Result

from .. import Failure, log_dict_yaml
from ..db import GuestRequest
from ..environment import And, Constraint, ConstraintBase, Environment, FlavorBoot, Operator, Or
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolResourcesMetrics, ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, CLIOutput, HookImageInfoMapper, PoolData, PoolDriver, PoolImageInfo, \
    PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, ProvisioningState, SerializedPoolResourcesIDs, \
    create_tempfile, run_cli_tool, test_cli_error

NodeRefType = Any


KNOB_RESERVATION_DURATION: Knob[int] = Knob(
    'beaker.reservation.duration',
    'A time, in seconds, for which the guest would be initially reserved.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_DURATION',
    cast_from_str=int,
    default=86400
)


NO_DISTRO_MATCHES_RECIPE_ERROR_PATTEN = re.compile(r'^Exception: .+:No distro tree matches Recipe:')


@dataclasses.dataclass
class BeakerPoolData(PoolData):
    job_id: str


@dataclasses.dataclass
class BeakerPoolResourcesIDs(PoolResourcesIDs):
    job_id: Optional[str] = None


#: Mapping of operators to their Beaker representation. :py:attr:`Operator.MATCH` is missing on purpose: it is
#: intercepted in :py:func:`operator_to_beaker_op`.
OPERATOR_SIGN_TO_OPERATOR = {
    Operator.EQ: '==',
    Operator.NEQ: '!=',
    Operator.GT: '>',
    Operator.GTE: '>=',
    Operator.LT: '<',
    Operator.LTE: '<='
}


CONSTRAINT_DISK_PATTERN = re.compile(r'disk(?:\[[+-]?\d+\])?\.')
CONSTRAINT_DISK_EXPANSION_PATTERN = re.compile(r'(?:disk\[[+-]?\d+\].(?:is_expansion|min_size|max_size|expanded_length))|(?:disk\.expanded_length)')  # noqa: E501
CONSTRAINT_DISK_SIZE = re.compile(r'disk\[\d+\]\.size')


def _new_tag(tag_name: str, **attrs: str) -> bs4.BeautifulSoup:
    return bs4.BeautifulSoup('', 'xml').new_tag(tag_name, **attrs)


def operator_to_beaker_op(operator: Operator, value: str) -> Tuple[str, str]:
    """
    Convert constraint operator to Beaker "op".
    """

    if operator in OPERATOR_SIGN_TO_OPERATOR:
        return OPERATOR_SIGN_TO_OPERATOR[operator], value

    # MATCH has special handling - convert the pattern to a wildcard form - and that may be weird :/
    return 'like', value.replace('.*', '%').replace('.+', '%')


def constraint_to_beaker_filter(constraint: ConstraintBase) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert a given constraint to XML tree representing Beaker filter compatible with Beaker's ``hostRequires``
    element.
    """

    if isinstance(constraint, And):
        grouping_and = _new_tag('and')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(child_constraint)

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            grouping_and.append(r_child_element.unwrap())

        return Ok(grouping_and)

    if isinstance(constraint, Or):
        grouping_or = _new_tag('or')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(child_constraint)

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            grouping_or.append(r_child_element.unwrap())

        return Ok(grouping_or)

    constraint = cast(Constraint, constraint)

    if constraint.name.startswith('cpu.'):
        cpu = _new_tag('cpu')

        if constraint.name == 'cpu.cores':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            processors = _new_tag('processors', op=op, value=value)

            cpu.append(processors)

        elif constraint.name == 'cpu.model':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            processors = _new_tag('model', op=op, value=value)

            cpu.append(processors)

        elif constraint.name == 'cpu.model_name':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            processors = _new_tag('model_name', op=op, value=value)

            cpu.append(processors)

        else:
            return Error(Failure(
                'contraint not supported by driver',
                constraint=constraint.format()  # noqa: FS002
            ))

        return Ok(cpu)

    if CONSTRAINT_DISK_PATTERN.match(constraint.name):
        if CONSTRAINT_DISK_EXPANSION_PATTERN.match(constraint.name):
            return Ok(_new_tag('or'))

        disk = _new_tag('disk')

        if CONSTRAINT_DISK_SIZE.match(constraint.name):
            # `disk.size` is represented as quantity, for Beaker XML we need to convert to bytes, integer.
            op, value = operator_to_beaker_op(
                constraint.operator,
                str(int(cast(pint.Quantity, constraint.value).to('B').magnitude))
            )

            size = _new_tag('size', op=op, value=value)

            disk.append(size)

        elif CONSTRAINT_DISK_EXPANSION_PATTERN.match(constraint.name):
            # ignored
            pass

        else:
            return Error(Failure(
                'contraint not supported by driver',
                constraint=constraint.format(),  # noqa: FS002
                constraint_name=constraint.name
            ))

        return Ok(disk)

    if constraint.name == 'arch':
        op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

        system = _new_tag('system')
        arch = _new_tag('arch', op=op, value=value)

        system.append(arch)

        return Ok(system)

    if constraint.name == 'memory':
        # `memory` is represented as quantity, for Beaker XML we need to convert to mibibytes, integer.
        op, value = operator_to_beaker_op(
            constraint.operator,
            str(int(cast(pint.Quantity, constraint.value).to('MiB').magnitude))
        )

        system = _new_tag('system')
        memory = _new_tag('memory', op=op, value=value)

        system.append(memory)

        return Ok(system)

    return Error(Failure(
        'contraint not supported by driver',
        constraint=constraint.format(),  # noqa: FS002
        constraint_name=constraint.name
    ))


def _prune_beaker_filter(tree: bs4.BeautifulSoup) -> Result[bs4.BeautifulSoup, Failure]:
    # Conversion process produces empty `and` and `or` tags, thanks to how Beaker deals with disks without flavors.
    # The following code is a crude attempt to get rid of some of them (there may be some left, empty `or` in `and`
    # in `or`) would keep the last `or` since we run just two swipes. But that's good enough for now.
    def _remove_empty(tag_name: str) -> None:
        for el in tree.find_all(tag_name):
            if len(el.contents) == 0:
                el.extract()

    _remove_empty('or')
    _remove_empty('and')

    def _remove_singles(tag_name: str) -> None:
        for el in tree.find_all(tag_name):
            if len(el.contents) == 1:
                el.replace_with(el.contents[0])

    _remove_singles('or')
    _remove_singles('and')

    return Ok(tree)


def environment_to_beaker_filter(environment: Environment) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert a given environment to Beaker XML tree representing Beaker filter compatible with Beaker's ``hostRequires``
    element.

    .. note::

       Converts the `environment`, not just the constraints: in our world, ``arch`` stands separated from
       the constraints while in Beaker, ``arch`` is part of the XML filter subtree. Therefore if there are no
       constraints, this helper emits a XML filter based on architecture alone.

    :param environment: environment as a source of constraints.
    :returns: a constraint representing the environment.
    """

    r_constraints = environment.get_hw_constraints()

    if r_constraints.is_error:
        return Error(r_constraints.unwrap_error())

    constraints = r_constraints.unwrap()

    if constraints is None:
        r_beaker_filter = constraint_to_beaker_filter(Constraint.from_arch(environment.hw.arch))

    else:
        r_beaker_filter = constraint_to_beaker_filter(And([
            Constraint.from_arch(environment.hw.arch),
            constraints
        ]))

    if r_beaker_filter.is_error:
        return r_beaker_filter

    return _prune_beaker_filter(r_beaker_filter.unwrap())


def groups_to_beaker_filter(avoid_groups: List[str]) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert given lists of groups to Beaker XML tree representing Beaker filter compatible with Beaker's
    ``hostRequires`` element.

    For each ``group`` from ``avoid_groups`` list, a following element is created:

    .. code-block:: xml

       <group op="!=" value="$group"/>

    :param avoid_groups: list of Beaker groups to filter out when provisioning.
    :returns: a Beaker filter representing groups to avoid.
    """

    # This is a container for all per-tag group elements. When called with an empty list, this would result
    # in an empty <and/> element being returned - but that's OK, _prune_beaker_filter() can deal with such
    # elements, and it simplifies handling of return values, no pesky `if is None` tests.
    container = _new_tag('and')

    for group in avoid_groups:
        container.append(_new_tag('group', op='!=', value=group))

    return Ok(container)


def merge_beaker_filters(filters: List[bs4.BeautifulSoup]) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Merge given Beaker filters into a single filter.

    Each filter must be a single element, but may have child elements. Filters would be merged into
    a single tree in which all filters must be satisfied for the final filter to be satisfied.

    :param filters: filters to merge.
    :returns: a Beaker filter taking all given filters into account.
    """

    # When called with an empty list, this would result in an empty <and/> element being returned - but that's OK,
    # _prune_beaker_filter() can deal with such elements, and it simplifies handling of return values, no pesky
    # `if is None` tests.
    if not filters:
        return Ok(_new_tag('and'))

    container = filters.pop(0)

    while filters:
        next_filter = filters.pop(0)

        # When the container is already an <and/> element, we can simply add the next filter to container's
        # children.
        if container.name == 'and':
            # Children of two <and/> elements can be easily merged, avoiding a nested <and/>.
            if next_filter.name == 'and':
                # TODO: for some reason, without a list only the first child is yielded from .children :/
                for child in list(next_filter.children):
                    container.append(child)

            else:
                container.append(next_filter)

        # For any other element, we need to create a new container, <and/>, and add our current container to it
        # as well as the next filter. That way, both branches needs to be satisfied for the final filter to be
        # happy.
        else:
            new_container = _new_tag('and')

            new_container.append(container)
            new_container.append(next_filter)

            container = new_container

    return _prune_beaker_filter(container)


def create_beaker_filter(
    environment: Environment,
    avoid_groups: List[str]
) -> Result[Optional[bs4.BeautifulSoup], Failure]:
    """
    From given inputs, create a Beaker filter.

    :param environment: environment as a source of constraints.
    :param avoid_groups: list of Beaker groups to filter out when provisioning.
    :returns: a Beaker filter taking all given inputs into account.
    """

    beaker_filters: List[bs4.BeautifulSoup] = []

    if environment.has_hw_constraints:
        r_beaker_filter = environment_to_beaker_filter(environment)

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filters.append(r_beaker_filter.unwrap())

    if avoid_groups:
        r_beaker_filter = groups_to_beaker_filter(avoid_groups)

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filters.append(r_beaker_filter.unwrap())

    if not beaker_filters:
        return Ok(None)

    r_beaker_filter = merge_beaker_filters(beaker_filters)

    if r_beaker_filter.is_error:
        return Error(r_beaker_filter.unwrap_error())

    return _prune_beaker_filter(r_beaker_filter.unwrap())


def _create_wow_options(
    logger: gluetool.log.ContextAdapter,
    guest_request: GuestRequest,
    distro: PoolImageInfo
) -> Result[List[str], Failure]:
    return Ok([
        'workflow-simple',
        '--dry-run',
        '--prettyxml',
        '--distro', distro.id,
        '--arch', guest_request.environment.hw.arch,
        '--task', '/distribution/dummy',
        '--reserve',
        '--reserve-duration', str(KNOB_RESERVATION_DURATION.value)
    ])


class BeakerDriver(PoolDriver):
    pool_data_class = BeakerPoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super(BeakerDriver, self).__init__(logger, poolname, pool_config)

        # Prepare `bkr` command with options we can already deduce.
        self._bkr_command = [
            'bkr'
        ]

        if self.pool_config.get('username') and self.pool_config.get('password'):
            self._bkr_command += [
                '--username', self.pool_config['username'],
                '--password', self.pool_config['password']
            ]

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
        return HookImageInfoMapper(self, 'BEAKER_ENVIRONMENT_TO_IMAGE')

    @property
    def avoid_groups(self) -> List[str]:
        return cast(List[str], self.pool_config.get('avoid-groups', []))

    def _run_bkr(
        self,
        logger: gluetool.log.ContextAdapter,
        options: List[str],
        commandname: Optional[str] = None
    ) -> Result[CLIOutput, Failure]:
        """
        Run bkr command with additional options

        :param gluetool.log.ContextAdapter logger: logger to use for logging.
        :param List(str) options: options for the command
        :returns: either a valid result, :py:class:`CLIOutput` instance, or an error with a :py:class:`Failure`
            describing the problem.
        """

        r_run = run_cli_tool(
            logger,
            self._bkr_command + options,
            json_output=False,
            poolname=self.poolname,
            commandname=commandname
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        return Ok(r_run.unwrap())

    def _handle_no_distro_matches_recipe_error(
        self,
        failure: Failure,
        guest_request: GuestRequest,
        pool_data: Optional[BeakerPoolData] = None
    ) -> Result[ProvisioningProgress, Failure]:
        # TODO: it would be cleaner to use some "empty" pool data but there are types guarding the pool data
        # from ever to be optional. But since we return CANCEL anyway, it should be safe until we find a better
        # way.
        pool_data = pool_data or BeakerPoolData(job_id='never-to-be-used')

        failure.recoverable = False

        PoolMetrics.inc_error(self.poolname, 'no-distro-matches-recipe')

        return Ok(ProvisioningProgress(
            state=ProvisioningState.CANCEL,
            pool_data=pool_data,
            pool_failures=[failure]
        ))

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = BeakerPoolResourcesIDs(job_id=job_id)

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = BeakerPoolResourcesIDs.unserialize(raw_resource_ids)

        if resource_ids.job_id is not None:
            r_output = self._run_bkr(logger, ['job-cancel', resource_ids.job_id], commandname='bkr.job-cancel')

            if r_output.is_error:
                return Error(r_output.unwrap_error())

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        return Ok(None)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        # TODO: is it true that `name` is equal to `id` in Beaker? Is really each `name` we get from
        # the `compose` => `image name` mapping really the same as "ID" of the distro? I believe this
        # is indeed correct, but needs checking.
        #
        # The thing is: this could be true even for OpenStack and AWS, if user would use `compose` => `image ID` map.
        # We want the right-hand side to be human-readable and easy to follow, therefore OpenStack and AWS have this
        # extra level of dereference.

        return Ok(PoolImageInfo(
            name=imagename,
            id=imagename,
            boot=FlavorBoot(),
            ssh=PoolImageSSHInfo()
        ))

    def _create_job_xml(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Create job xml with bkr workflow-simple and environment variables

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bs4.BeautifulSoup, Failure]
        :returns: :py:class:`result.Result` with job xml, or specification of error.
        """

        r_beaker_filter = create_beaker_filter(guest_request.environment, self.avoid_groups)

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filter = r_beaker_filter.unwrap()

        r_distro = self.image_info_mapper.map(logger, guest_request)

        if r_distro.is_error:
            return Error(r_distro.unwrap_error())

        distro = r_distro.unwrap()

        r_wow_options = _create_wow_options(logger, guest_request, distro)

        if r_wow_options.is_error:
            return Error(r_wow_options.unwrap_error())

        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
            image=distro
        )

        r_workflow_simple = self._run_bkr(logger, r_wow_options.unwrap(), commandname='bkr.workflow-simple')
        if r_workflow_simple.is_error:
            return Error(r_workflow_simple.unwrap_error())

        bkr_output = r_workflow_simple.unwrap()

        try:
            job_xml = bs4.BeautifulSoup(bkr_output.stdout, 'xml')

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse job XML',
                exc,
                command_output=bkr_output.process_output
            ))

        if beaker_filter is None:
            return Ok(job_xml)

        log_xml(logger.debug, 'job', job_xml)
        log_xml(logger.debug, 'filter', beaker_filter)

        host_requires = job_xml.find_all('hostRequires')

        if len(job_xml.find_all('hostRequires')) != 1:
            return Error(Failure(
                'job XML is missing hostRequires element',
                job=job_xml.prettify()
            ))

        list(host_requires)[0].append(beaker_filter)

        log_xml(logger.debug, 'job with filter', job_xml)

        return Ok(job_xml)

    def _submit_job(
        self,
        logger: gluetool.log.ContextAdapter,
        job: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Submit a Beaker job.

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param xml job: A job to submit.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        log_xml(self.logger.debug, 'job to submit', job)

        with create_tempfile(
            file_contents=job.prettify(),
            prefix='beaker-job-',
            suffix='.xml'
        ) as job_filepath:
            # Temporary file has limited permissions, but we'd like to make the file inspectable.
            os.chmod(job_filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            r_job_submit = self._run_bkr(logger, ['job-submit', job_filepath], commandname='bkr.job-submit')

        if r_job_submit.is_error:
            return Error(r_job_submit.unwrap_error())

        bkr_output = r_job_submit.unwrap()

        # Parse job id from output
        try:
            # Submitted: ['J:1806666']
            first_job_index = bkr_output.stdout.index('\'') + 1
            last_job_index = len(bkr_output.stdout) - bkr_output.stdout[::-1].index('\'') - 1

            # J:1806666
            job_id = bkr_output.stdout[first_job_index:last_job_index]

        except Exception as exc:
            return Error(Failure.from_exc(
                'cannot convert job-submit output to job ID',
                exc,
                command_output=bkr_output.process_output
            ))

        logger.info(f'Job submitted: {job_id}')

        return Ok(job_id)

    def _create_job(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[str, Failure]:
        r_job_xml = self._create_job_xml(
            logger,
            session,
            guest_request
        )

        if r_job_xml.is_error:
            return Error(r_job_xml.unwrap_error())

        return self._submit_job(logger, r_job_xml.unwrap())

    def _get_job_results(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: str
    ) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Run 'bkr job-results' comand and return job results.

        :param str job_id: Job id that will be rescheduled.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job results, or specification of error.
        """

        r_results = self._run_bkr(logger, ['job-results', job_id], commandname='bkr.job-results')

        if r_results.is_error:
            return Error(r_results.unwrap_error())

        bkr_output = r_results.unwrap()

        try:
            return Ok(bs4.BeautifulSoup(bkr_output.stdout, 'xml'))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse job results XML',
                exc,
                command_output=bkr_output.process_output
            ))

    def _parse_job_status(
        self,
        logger: gluetool.log.ContextAdapter,
        job_results: bs4.BeautifulSoup
    ) -> Result[Tuple[str, str], Failure]:
        """
        Parse job results and return its result and status.

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[Tuple[str, str], Failure]
        :returns: a tuple with two items, job result and status, or specification of error.
        """

        if not job_results.find('job') or len(job_results.find_all('job')) != 1:
            return Error(Failure(
                'job results XML has unknown structure',
                job_results=job_results.prettify()
            ))

        job = job_results.find('job')

        if not job['result']:
            return Error(Failure(
                'job results XML does not contain result attribute',
                job_results=job_results.prettify()
            ))

        if not job['status']:
            return Error(Failure(
                'job results XML does not contain status attribute',
                job_results=job_results.prettify()
            ))

        return Ok((job['result'].lower(), job['status'].lower()))

    def _parse_guest_address(
        self,
        logger: gluetool.log.ContextAdapter,
        job_results: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Parse job results and return guest address

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with guest address, or specification of error.
        """

        if not job_results.find('recipe')['system']:
            return Error(Failure(
                'System element was not found in job results',
                job_results=job_results.prettify()
            ))

        return Ok(job_results.find('recipe')['system'])

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.

        :param BeakerGuest guest: Guest that will be updated.
        :param threading.Event cancelled: if set, method should cancel its operation, release resources, and return.
        :rtype: Result[BeakerGuest, Failure]
        :returns: :py:class:`result.Result` with guest, or specification of error.
        """

        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_job_results = self._get_job_results(logger, BeakerPoolData.unserialize(guest_request).job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        job_results = r_job_results.unwrap()

        r_job_status = self._parse_job_status(logger, job_results)

        if r_job_status.is_error:
            return Error(r_job_status.unwrap_error())

        job_result, job_status = r_job_status.unwrap()

        logger.info(f'current job status {BeakerPoolData.unserialize(guest_request).job_id}:{job_result}:{job_status}')

        if job_result == 'pass':
            r_guest_address = self._parse_guest_address(logger, job_results)

            if r_guest_address.is_error:
                return Error(r_guest_address.unwrap_error())

            return Ok(ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=BeakerPoolData.unserialize(guest_request),
                address=r_guest_address.unwrap()
            ))

        if job_result == 'new':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=BeakerPoolData.unserialize(guest_request),
                delay_update=r_delay.unwrap()
            ))

        job_is_failed = \
            job_result == 'fail' \
            or job_status == 'aborted' \
            or (job_status == 'reserved' and job_result == 'warn')  # job failed, needs a bit more time to update status

        if job_is_failed:
            return Ok(ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=BeakerPoolData.unserialize(guest_request),
                pool_failures=[Failure(
                    'beaker job failed',
                    job_result=job_result,
                    job_status=job_status,
                    job_results=job_results.prettify()
                )]
            ))

        return Error(Failure(
            'unknown status',
            job_result=job_result,
            job_status=job_status,
            job_results=job_results.prettify()
        ))

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.

        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bool, Failure]
        :returns: Ok with True if guest can be acquired.
        """

        # First, check the parent class, maybe its tests already have the answer.
        r_answer = super(BeakerDriver, self).can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        # Parent implementation does not care, but we still might: support for HW constraints is still
        # far from being complete and fully tested, therefore we should check whether we are able to
        # convert the constraints - if there are any - to a Beaker XML filter.

        if not guest_request.environment.has_hw_constraints:
            return Ok(True)

        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()

        # since `has_hw_constraints` was positive, there should be constraints...
        assert constraints is not None

        r_filter = constraint_to_beaker_filter(constraints)

        if r_filter.is_error:
            return Error(r_filter.unwrap_error())

        return Ok(True)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key master_key: master key to upload to the guest.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, str]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        log_dict_yaml(logger.info, 'provisioning environment', guest_request._environment)

        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(poolname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        r_create_job = self._create_job(logger, session, guest_request)

        if r_create_job.is_error:
            failure = r_create_job.unwrap_error()

            if test_cli_error(failure, NO_DISTRO_MATCHES_RECIPE_ERROR_PATTEN):
                return self._handle_no_distro_matches_recipe_error(failure, guest_request)

            return Error(r_create_job.unwrap_error())

        # The returned guest doesn't have address. The address will be added by executing `update_guest()`
        # after. The reason of this solution is slow beaker system provisioning. It can take hours and
        # we can't use a thread for so large amount of time.

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=BeakerPoolData(job_id=r_create_job.unwrap()),
            delay_update=r_delay.unwrap()
        ))

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        if BeakerPoolData.is_empty(guest_request):
            return Ok(True)

        r_job_cancel = self._dispatch_resource_cleanup(
            logger,
            job_id=BeakerPoolData.unserialize(guest_request).job_id,
            guest_request=guest_request
        )

        if r_job_cancel.is_error:
            return Error(r_job_cancel.unwrap_error())

        return Ok(True)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super(BeakerDriver, self).fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        r_query_instances = self._run_bkr(
            logger,
            ['system-list', '--mine'],
            commandname='bkr.system-list'
        )

        if r_query_instances.is_error:
            failure = r_query_instances.unwrap_error()
            command_output = failure.details.get('command_output', None)

            if command_output and command_output.stderr \
               and command_output.stderr.decode('utf-8').strip().lower() == 'nothing matches':
                # This is a a valid result, meaning "0 machines". Setting our "raw output" to a corresponding value
                # instead of adding some special flag. Empty string has 0 lines, 0 machines...
                raw_machines = ''

            else:
                return Error(failure)

        else:
            raw_machines = r_query_instances.unwrap().stdout

        if raw_machines:
            resources.usage.instances = len(raw_machines.splitlines())

        else:
            # Not an error, just an empty list which means, hm, 0 instances.
            resources.usage.instances = 0

        # For the actual numbers of cores, memory and other metrics, we'd have to query each and every machine from
        # the list above. Is it worth it? At this moment it's not. But it can be done. Leaving them unspecified for
        # now.

        return Ok(resources)


PoolDriver._drivers_registry['beaker'] = BeakerDriver
