# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import math
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
from gluetool.log import ContextAdapter, log_xml
from gluetool.result import Error, Ok, Result
from typing_extensions import TypedDict

from .. import Failure, SerializableContainer, log_dict_yaml, process_output_to_str
from ..cache import get_cached_set, refresh_cached_set
from ..context import CACHE
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..environment import And, Constraint, ConstraintBase, Environment, FlavorBoot, Operator, Or
from ..knobs import Knob
from ..metrics import PoolMetrics, PoolResourcesMetrics, ResourceType
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, CLIErrorCauses, CLIOutput, GuestLogUpdateProgress, HookImageInfoMapper, \
    PoolCapabilities, PoolData, PoolDriver, PoolImageInfo, PoolImageSSHInfo, PoolResourcesIDs, ProvisioningProgress, \
    ProvisioningState, SerializedPoolResourcesIDs, WatchdogState, create_tempfile, guest_log_updater, run_cli_tool, \
    run_remote

NodeRefType = Any


KNOB_RESERVATION_DURATION: Knob[int] = Knob(
    'beaker.reservation.duration',
    'A time, in seconds, for which the guest would be initially reserved.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_DURATION',
    cast_from_str=int,
    default=86400
)

KNOB_RESERVATION_EXTENSION: Knob[int] = Knob(
    'beaker.reservation.extension',
    'A time, in seconds, to extend the guest reservation every tick of a watchdog.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_EXTENSION',
    cast_from_str=int,
    default=8 * 60 * 60
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'beaker.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_BEAKER_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-beaker.yaml'
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'beaker.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_BEAKER_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}'
)

KNOB_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'beaker.guest-watchdog.ssh.connect-timeout',
    'Guest watchdog SSH timeout.',
    per_pool=True,
    has_db=True,
    envvar='ARTEMIS_BEAKER_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15
)


class BkrErrorCauses(CLIErrorCauses):
    NONE = 'none'
    NO_DISTRO_MATCHES_RECIPE = 'no-distro-matches-recipe'


CLI_ERROR_PATTERNS = {
    BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE: re.compile(r'^Exception: .+:No distro tree matches Recipe:')
}


def bkr_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> BkrErrorCauses:
    if output.exit_code == 0:
        return BkrErrorCauses.NONE

    stderr = process_output_to_str(output, stream='stderr')

    if stderr is None:
        return BkrErrorCauses.NONE

    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if not pattern.match(stderr):
            continue

        return cause

    return BkrErrorCauses.NONE


@dataclasses.dataclass
class BeakerPoolData(PoolData):
    job_id: str


@dataclasses.dataclass
class BeakerPoolResourcesIDs(PoolResourcesIDs):
    job_id: Optional[str] = None


@dataclasses.dataclass(repr=False)
class AvoidGroupHostnames(SerializableContainer):
    groupname: str
    hostnames: List[str] = dataclasses.field(default_factory=list)


class ConstraintTranslationConfigType(TypedDict):
    operator: str
    value: str
    element: str


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


def _translate_constraint_by_config(
    constraint: Constraint,
    translations: List[ConstraintTranslationConfigType]
) -> Result[bs4.BeautifulSoup, Failure]:
    for translation in translations:
        if translation['operator'] != constraint.operator.value or translation['value'] != constraint.value:
            continue

        try:
            return Ok(bs4.BeautifulSoup(translation['element'], 'xml'))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse XML',
                exc,
                source=translation['element']
            ))

    return Error(Failure(
        'contraint not supported by driver',
        constraint=repr(constraint),
        constraint_name=constraint.name
    ))


def constraint_to_beaker_filter(
    constraint: ConstraintBase,
    pool: 'BeakerDriver'
) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert a given constraint to XML tree representing Beaker filter compatible with Beaker's ``hostRequires``
    element.
    """

    if isinstance(constraint, And):
        grouping_and = _new_tag('and')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(child_constraint, pool)

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            grouping_and.append(r_child_element.unwrap())

        return Ok(grouping_and)

    if isinstance(constraint, Or):
        grouping_or = _new_tag('or')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(child_constraint, pool)

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            grouping_or.append(r_child_element.unwrap())

        return Ok(grouping_or)

    constraint = cast(Constraint, constraint)
    constraint_name = constraint.expand_name()

    if constraint_name.property == 'boot':
        if constraint_name.child_property == 'method':
            return _translate_constraint_by_config(
                constraint,
                pool.pool_config
                    .get('hw-constraints', {})
                    .get('boot', {})
                    .get('method', {})
                    .get('translations', [])
            )

    if constraint_name.property == 'cpu':
        cpu = _new_tag('cpu')

        if constraint_name.child_property == 'cores':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            cores = _new_tag('cores', op=op, value=value)

            cpu.append(cores)

        elif constraint_name.child_property == 'family':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            family = _new_tag('family', op=op, value=value)

            cpu.append(family)

        elif constraint_name.child_property == 'model':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            model = _new_tag('model', op=op, value=value)

            cpu.append(model)

        elif constraint_name.child_property == 'model_name':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            model_name = _new_tag('model_name', op=op, value=value)

            cpu.append(model_name)

        else:
            return Error(Failure(
                'contraint not supported by driver',
                constraint=repr(constraint)
            ))

        return Ok(cpu)

    if constraint_name.property == 'disk':
        if constraint_name.child_property in ('is_expansion', 'min_size', 'max_size', 'length', 'expanded_length'):
            return Ok(_new_tag('or'))

        disk = _new_tag('disk')

        if constraint_name.child_property == 'size':
            # `disk.size` is represented as quantity, for Beaker XML we need to convert to bytes, integer.
            op, value = operator_to_beaker_op(
                constraint.operator,
                str(int(cast(pint.Quantity, constraint.value).to('B').magnitude))
            )

            size = _new_tag('size', op=op, value=value)

            disk.append(size)

        else:
            return Error(Failure(
                'contraint not supported by driver',
                constraint=repr(constraint),
                constraint_name=constraint.name
            ))

        return Ok(disk)

    if constraint_name.property == 'arch':
        op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

        system = _new_tag('system')
        arch = _new_tag('arch', op=op, value=value)

        system.append(arch)

        return Ok(system)

    if constraint_name.property == 'memory':
        # `memory` is represented as quantity, for Beaker XML we need to convert to mibibytes, integer.
        op, value = operator_to_beaker_op(
            constraint.operator,
            str(int(cast(pint.Quantity, constraint.value).to('MiB').magnitude))
        )

        system = _new_tag('system')
        memory = _new_tag('memory', op=op, value=value)

        system.append(memory)

        return Ok(system)

    if constraint_name.property == 'hostname':
        op, value = operator_to_beaker_op(
            constraint.operator,
            str(constraint.value)
        )

        hostname = _new_tag('hostname', op=op, value=value)

        return Ok(hostname)

    if constraint_name.property == 'virtualization':
        if constraint_name.child_property == 'is_virtualized':
            return _translate_constraint_by_config(
                constraint,
                pool.pool_config
                    .get('hw-constraints', {})
                    .get('virtualization', {})
                    .get('is_virtualized', {})
                    .get('translations', [])
            )

        if constraint_name.child_property == 'hypervisor':
            return _translate_constraint_by_config(
                constraint,
                pool.pool_config
                    .get('hw-constraints', {})
                    .get('virtualization', {})
                    .get('hypervisor', {})
                    .get('translations', [])
            )

    return Error(Failure(
        'contraint not supported by driver',
        constraint=repr(constraint),
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


def environment_to_beaker_filter(
    environment: Environment,
    pool: 'BeakerDriver'
) -> Result[bs4.BeautifulSoup, Failure]:
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
        r_beaker_filter = constraint_to_beaker_filter(Constraint.from_arch(environment.hw.arch), pool)

    else:
        r_beaker_filter = constraint_to_beaker_filter(And([
            Constraint.from_arch(environment.hw.arch),
            constraints
        ]), pool)

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


def hostnames_to_beaker_filter(avoid_hostnames: List[str]) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert given lists of hostnames to Beaker XML tree representing Beaker filter compatible with Beaker's
    ``hostRequires`` element.

    For each ``hostname`` from ``avoid_hostnames`` list, a following element is created:

    .. code-block:: xml

       <hostname op="!=" value="$hostname"/>

    :param avoid_hostnames: list of Beaker hostnames to filter out when provisioning.
    :returns: a Beaker filter representing hostnamesto avoid.
    """

    # This is a container for all per-tag hostname elements. When called with an empty list, this would result
    # in an empty <and/> element being returned - but that's OK, _prune_beaker_filter() can deal with such
    # elements, and it simplifies handling of return values, no pesky `if is None` tests.
    container = _new_tag('and')

    for hostname in avoid_hostnames:
        container.append(_new_tag('hostname', op='!=', value=hostname))

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
    pool: 'BeakerDriver',
    avoid_groups: List[str],
    avoid_hostnames: List[str]
) -> Result[Optional[bs4.BeautifulSoup], Failure]:
    """
    From given inputs, create a Beaker filter.

    :param environment: environment as a source of constraints.
    :param avoid_groups: list of Beaker groups to filter out when provisioning.
    :param avoid_hostnames: list of Beaker hostnames to filter out when provisioning.
    :returns: a Beaker filter taking all given inputs into account.
    """

    beaker_filters: List[bs4.BeautifulSoup] = []

    if environment.has_hw_constraints:
        r_beaker_filter = environment_to_beaker_filter(environment, pool)

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filters.append(r_beaker_filter.unwrap())

    if avoid_groups:
        r_beaker_filter = groups_to_beaker_filter(avoid_groups)

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filters.append(r_beaker_filter.unwrap())

    if avoid_hostnames:
        r_beaker_filter = hostnames_to_beaker_filter(avoid_hostnames)

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
        # Using reservesys task instead of --reserve, because reservesys adds extendtesttime.sh
        # script we can use to extend existing reservation.
        '--task', '/distribution/reservesys',
        '--taskparam', f'RESERVETIME={str(KNOB_RESERVATION_DURATION.value)}'
    ])


class BeakerDriver(PoolDriver):
    drivername = 'beaker'

    pool_data_class = BeakerPoolData

    #: Template for a cache key holding avoid groups hostnames.
    POOL_AVOID_GROUPS_HOSTNAMES_CACHE_KEY = 'pool.{}.avoid-groups.hostnames'

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super().__init__(logger, poolname, pool_config)

        # Prepare `bkr` command with options we can already deduce.
        self._bkr_command = [
            'bkr'
        ]

        if self.pool_config.get('username') and self.pool_config.get('password'):
            self._bkr_command += [
                '--username', self.pool_config['username'],
                '--password', self.pool_config['password']
            ]

        self.avoid_groups_hostnames_cache_key = self.POOL_AVOID_GROUPS_HOSTNAMES_CACHE_KEY.format(self.poolname)  # noqa: FS002,E501

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = True
        capabilities.supported_guest_logs = [
            ('console', GuestLogContentType.URL),
            ('console.log', GuestLogContentType.URL),
            ('sys.log', GuestLogContentType.URL),
        ]

        return Ok(capabilities)

    @property
    def image_info_mapper(self) -> HookImageInfoMapper[PoolImageInfo]:
        return HookImageInfoMapper(self, 'BEAKER_ENVIRONMENT_TO_IMAGE')

    @property
    def avoid_groups(self) -> Result[List[str], Failure]:
        return Ok(self.pool_config.get('avoid-groups', []))

    @property
    def avoid_hostnames(self) -> Result[List[str], Failure]:
        r_avoid_hostnames = self.get_avoid_groups_hostnames()

        if r_avoid_hostnames.is_error:
            return Error(r_avoid_hostnames.unwrap_error())

        return Ok(sum(
            (group.hostnames for group in r_avoid_hostnames.unwrap().values()),
            self.pool_config.get('avoid-hostnames', [])
        ))

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
            commandname=commandname,
            cause_extractor=bkr_error_cause_extractor
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

        PoolMetrics.inc_error(self.poolname, BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE.value)

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
        resource_ids = BeakerPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.job_id is not None:
            r_output = self._run_bkr(logger, ['job-cancel', resource_ids.job_id], commandname='bkr.job-cancel')

            if r_output.is_error:
                return Error(Failure.from_failure(
                    'failed to cancel job',
                    r_output.unwrap_error()
                ))

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
            arch=None,
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

        r_avoid_hostnames = self.avoid_hostnames

        if r_avoid_hostnames.is_error:
            return Error(r_avoid_hostnames.unwrap_error())

        r_avoid_groups = self.avoid_groups

        if r_avoid_groups.is_error:
            return Error(r_avoid_groups.unwrap_error())

        r_beaker_filter = create_beaker_filter(
            guest_request.environment,
            self,
            r_avoid_groups.unwrap(),
            r_avoid_hostnames.unwrap()
        )

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
            return Error(Failure.from_failure(
                'failed to create job',
                r_workflow_simple.unwrap_error()
            ))

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
            return Error(Failure.from_failure(
                'failed to submit job',
                r_job_submit.unwrap_error()
            ))

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
            return Error(Failure.from_failure(
                'failed to fetch job results',
                r_results.unwrap_error()
            ))

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

    def guest_watchdog(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[WatchdogState, Failure]:
        """
        Perform any periodic tasks the driver might need to apply while the request is in use.

        :param logger: logger to use for logging.
        :param guest_request: guest request to provision for.
        """

        from ..tasks import _get_master_key

        r_master_key = _get_master_key()

        if r_master_key.is_error:
            return Error(r_master_key.unwrap_error())

        r_ssh_timeout = KNOB_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT.get_value(session=session, pool=self)

        if r_ssh_timeout.is_error:
            return Error(r_ssh_timeout.unwrap_error())

        r_output = run_remote(
            logger,
            guest_request,
            ['extendtesttime.sh', str(math.ceil(KNOB_RESERVATION_EXTENSION.value / 3600))],
            key=r_master_key.unwrap(),
            ssh_timeout=r_ssh_timeout.unwrap(),
            poolname=self.poolname,
            commandname='bkr.extend',
            cause_extractor=bkr_error_cause_extractor
        )

        if r_output.is_error:
            return Error(Failure.from_failure(
                'failed to extend guest reservation',
                r_output.unwrap_error()
            ))

        return Ok(WatchdogState.CONTINUE)

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
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap() is False:
            return r_answer

        r_distro = self.image_info_mapper.map_or_none(logger, guest_request)
        if r_distro.is_error:
            return Error(r_distro.unwrap_error())

        distro = r_distro.unwrap()

        if distro is None:
            return Ok(False)

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

        r_filter = constraint_to_beaker_filter(constraints, self)

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

            if failure.command_output \
               and bkr_error_cause_extractor(failure.command_output) == BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE:
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
        r_resources = super().fetch_pool_resources_metrics(logger)

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
                return Error(Failure.from_failure(
                    'failed to fetch system list',
                    r_query_instances.unwrap_error()
                ))

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

    def _fetch_avoid_group_hostnames(self, logger: ContextAdapter, groupname: str) -> Result[List[str], Failure]:
        r_list = self._run_bkr(
            logger,
            [
                'system-list',
                '--xml-filter', f'<and><group op="=" value="{groupname}"/></and>'
            ],
            commandname='bkr.system-list-owned-by-group'
        )

        if r_list.is_error:
            return Error(Failure.from_failure(
                'failed to fetch systems owned by a group',
                r_list.unwrap_error().update(groupname=groupname)
            ))

        return Ok([
            hostname.strip() for hostname in r_list.unwrap().stdout.splitlines()
        ])

    def refresh_avoid_groups_hostnames(self, logger: ContextAdapter) -> Result[None, Failure]:
        groups: List[AvoidGroupHostnames] = []

        r_avoid_groups = self.avoid_groups

        if r_avoid_groups.is_error:
            return Error(r_avoid_groups.unwrap_error())

        for groupname in r_avoid_groups.unwrap():
            r_list = self._fetch_avoid_group_hostnames(logger, groupname)

            if r_list.is_error:
                return Error(r_list.unwrap_error())

            groups.append(AvoidGroupHostnames(
                groupname=groupname,
                hostnames=r_list.unwrap()
            ))

        r_refresh = refresh_cached_set(
            CACHE.get(),
            self.avoid_groups_hostnames_cache_key,
            {
                h.groupname: h
                for h in groups
            }
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        return Ok(None)

    def get_avoid_groups_hostnames(self) -> Result[Dict[str, AvoidGroupHostnames], Failure]:
        return get_cached_set(CACHE.get(), self.avoid_groups_hostnames_cache_key, AvoidGroupHostnames)

    def _get_beaker_machine_log_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        beaker_logname: str
    ) -> Result[Optional[str], Failure]:
        """
        Extract location (URL) of Beaker machine log.

        :param logger: logger to use for logging.
        :param guest_request: a request whose logs to look for.
        :param beaker_logname: a name of the log as known to Beaker (e.g. ``console.log``).
        :returns: log URL, ``None`` when no such log was found, or a :py:class:`Failure` describing an error.
        """

        r_job_results = self._get_job_results(logger, BeakerPoolData.unserialize(guest_request).job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        logs = r_job_results.unwrap().select(f'recipe > logs > log[name="{beaker_logname}"]')

        if not logs:
            return Ok(None)

        return Ok(logs[0]['href'])

    def _update_guest_log_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog,
        beaker_logname: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_url = self._get_beaker_machine_log_url(logger, guest_request, beaker_logname)

        if r_url.is_error:
            return Error(r_url.unwrap_error())

        url = r_url.unwrap()

        if url is None:
            return Ok(GuestLogUpdateProgress(state=GuestLogState.PENDING))

        return Ok(GuestLogUpdateProgress(state=GuestLogState.COMPLETE, url=url))

    # Since Beaker provides named logs, unlike other drivers, there are updaters for various log names.
    # To satisfy the "standard" logging expectations, use some of those for common logs like console/url
    # while keeping their Beaker-native names available at the same time.
    @guest_log_updater('beaker', 'console', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_url(logger, guest_request, guest_log, 'console.log')

    @guest_log_updater('beaker', 'console.log', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_log_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_url(logger, guest_request, guest_log, 'console.log')

    @guest_log_updater('beaker', 'sys.log', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_sys_log_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_url(logger, guest_request, guest_log, 'sys.log')


PoolDriver._drivers_registry['beaker'] = BeakerDriver
