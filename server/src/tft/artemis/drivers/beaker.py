# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import os
import re
import shlex
import stat
from re import Pattern
from typing import Any, Callable, Optional, cast

import bs4
import gluetool.log
import gluetool.utils
import requests
import requests.exceptions
import sqlalchemy.orm.session
from gluetool.log import ContextAdapter, log_blob, log_table, log_xml
from gluetool.result import Error, Ok, Result
from gluetool.utils import ProcessOutput
from returns.pipeline import is_successful
from returns.result import Result as _Result, Success as _Ok
from tmt.hardware import Operator
from typing_extensions import TypedDict

from .. import (
    Failure,
    SerializableContainer,
    log_dict_yaml,
    process_output_to_str,
    render_template,
    template_environment,
)
from ..cache import get_cached_mapping, refresh_cached_mapping
from ..context import CACHE
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..environment import (
    And,
    CompoundConstraint,
    Constraint,
    ConstraintBase,
    Environment,
    Flavor,
    FlavorBoot,
    Kickstart,
    Or,
    SizeType,
)
from ..knobs import KNOB_DISABLE_CERT_VERIFICATION, KNOB_HTTP_TIMEOUT, Knob
from ..metrics import PoolMetrics, PoolResourcesMetrics, PoolResourcesUsage, ResourceType
from . import (
    CanAcquire,
    CLIOutput,
    GuestLogUpdateProgress,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolErrorCauses,
    PoolImageInfo,
    PoolImageSSHInfo,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
    WatchdogState,
    create_tempfile,
    guest_log_updater,
    run_cli_tool,
    run_remote,
)

NodeRefType = Any


KNOB_RESERVATION_DURATION: Knob[int] = Knob(
    'beaker.reservation.duration',
    'A time, in seconds, for which the guest would be initially reserved.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_DURATION',
    cast_from_str=int,
    default=86400,
)

KNOB_RESERVATION_EXTENSION_COMMAND_TEMPLATE: Knob[str] = Knob(
    'beaker.reservation.extension.command-template',
    'A template for a command to run to extend Beaker reservation.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_EXTENSION_COMMAND_TEMPLATE',
    cast_from_str=str,
    default=(
        '{% set extension_cmd = "echo %s | extendtesttime.sh" % ((EXTENSION_TIME / 3600) | int | string) %}'  # noqa: FS003,E501
        '{% if POOL_DATA.is_bootc %}podman exec beaker-harness /bin/bash -c "{{ extension_cmd }}"{% else %}'  # noqa: FS003,E501
        '{{ extension_cmd }}{% endif %}'  # noqa: FS003
    ),
)

KNOB_RESERVATION_EXTENSION_TIME: Knob[int] = Knob(
    'beaker.reservation.extension.time',
    'A time, in seconds, to extend the guest reservation every tick of a watchdog.',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_EXTENSION_TIME',
    cast_from_str=int,
    default=8 * 60 * 60,
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH: Knob[str] = Knob(
    'beaker.mapping.environment-to-image.pattern-map.filepath',
    'Path to a pattern map file with environment to image mapping.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_ENVIRONMENT_TO_IMAGE_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-image-map-beaker.yaml',
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE: Knob[str] = Knob(
    'beaker.mapping.environment-to-image.pattern-map.needle',
    'A pattern for needle to match in environment to image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_ENVIRONMENT_TO_IMAGE_MAPPING_NEEDLE',
    cast_from_str=str,
    default='{{ os.compose }}',
)

KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_PATTERN: Knob[str] = Knob(
    'beaker.mapping.environment-to-image.pattern',
    'A pattern for extracting distro and other components from the right side of the image mapping file.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_ENVIRONMENT_TO_IMAGE_MAPPING_PATTERN',
    cast_from_str=str,
    default=(
        r'^(?P<distro>[^;]+)'
        r'(?:;variant=(?P<variant>[a-zA-Z]*);?)?'
        r'(?:;bootc_image=(?P<bootc_image>[a-zA-Z0-9._\-:/]*);?)?$'
    ),
)


KNOB_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT: Knob[int] = Knob(
    'beaker.guest-watchdog.ssh.connect-timeout',
    'Guest watchdog SSH timeout.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_BEAKER_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT',
    cast_from_str=int,
    default=15,
)

KNOB_JOB_WHITEBOARD_TEMPLATE: Knob[str] = Knob(
    'beaker.job.whiteboard.template',
    'A template for Beaker job whiteboard.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_JOB_WHITEBOARD_TEMPLATE',
    cast_from_str=str,
    default='[artemis] [{{ DEPLOYMENT }}] {{ GUESTNAME }}',
)

KNOB_INSTALLATION_TIMEOUT: Knob[int] = Knob(
    'beaker.installation-timeout',
    'Installation timeout for the guest.',
    has_db=True,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_INSTALLATION_TIMEOUT',
    cast_from_str=int,
    default=1800,
)

KNOB_BKR_CREATE_COMMAND_TEMPLATE: Knob[str] = Knob(
    'beaker.command.create.template',
    'A template for the ``bkr`` subcommand that, when executed, would create a Beaker job XML.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_BKR_CREATE_COMMAND_TEMPLATE',
    cast_from_str=str,
    default="""
        workflow-simple \
            --dry-run \
            --prettyxml \
            --distro {{ IMAGE.id | shell_quote }} \
            --arch {{ GUEST_REQUEST.environment.hw.arch | shell_quote }} \
            {#
              # Using reservesys task instead of --reserve, because reservesys adds extendtesttime.sh
              # script we can use to extend existing reservation.
            #}
            --task /distribution/reservesys \
            --taskparam RESERVETIME={{ RESERVATION_DURATION }} \
            {% if IMAGE.variant %}
            --variant {{ IMAGE.variant | shell_quote }} \
            {% endif %}
            {% for name, value in TAGS | items %}
            --taskparam ARTEMIS_TAG_{{ name | shell_quote }}={{ value | shell_quote }} \
            {% endfor %}
            {#
              Override kickstart template for bootc installation.
            #}
            {% if KICKSTART_FILEPATH %}
            --kickstart {{ KICKSTART_FILEPATH | shell_quote }} \
            {% endif %}
            {% if KICKSTART_META %}
            --ks-meta {{ KICKSTART_META | shell_quote }} \
            {% endif %}
            {% for option in KICKSTART_OPTIONS %}
            {{ option | shell_quote }} \
            {% endfor %}
            {% if INSTALLATION_METHOD %}
            --method {{ INSTALLATION_METHOD | shell_quote }} \
            {% endif %}
            {% if not PANIC_WATCHDOG_ENABLED %}
            --ignore-panic \
            {% endif %}
            --whiteboard {{ WHITEBOARD | shell_quote }}
        """,
)

KNOB_BKR_COMMAND_TERMINATION_TIMEOUT: Knob[int] = Knob(
    'beaker.command-timeout.termination',
    """
    Timeout for all `bkr` commands executed by the driver. After this many seconds, `bkr` command will be sent
    `SIGTERM`.
    """,
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_BKR_TIMEOUT_TERMINATION',
    cast_from_str=int,
    default=120,
)

KNOB_KICKSTART_TEMPLATE_BOOTC_FILEPATH: Knob[str] = Knob(
    'beaker.kickstart.template-bootc.filepath',
    'Path to the kickstart template used for bootc installation.',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_KICKSTART_TEMPLATE_BOOTC_FILEPATH',
    cast_from_str=str,
    default='beaker-bootc-kickstart.ks',
)

KNOB_KICKSTART_METADATA_TEMPLATE: Knob[str] = Knob(
    'beaker.kickstart.metadata.template',
    'A template for Beaker .',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_BEAKER_KICKSTART_METADATA_TEMPLATE',
    cast_from_str=str,
    default=(
        '{% if DISTRO.bootc_image %}ostree_container_url={{ DISTRO.bootc_image }} disable_debug_repos '  # noqa: FS003
        'contained_harness no_ks_template{% endif %}'  # noqa: FS003
    ),
)


class BkrErrorCauses(PoolErrorCauses):
    NONE = 'none'
    RESOURCE_METRICS_REFRESH_FAILED = 'resource-metrics-refresh-failed'
    FLAVOR_INFO_REFRESH_FAILED = 'flavor-info-refresh-failed'
    IMAGE_INFO_REFRESH_FAILED = 'image-info-refresh-failed'
    NO_DISTRO_MATCHES_RECIPE = 'no-distro-matches-recipe'
    NO_SYSTEM_MATCHES_RECIPE = 'no-system-matches-recipe'

    JOB_FAILED = 'job-failed'
    JOB_ABORTED = 'job-aborted'
    JOB_CANCELLED = 'job-cancelled'
    JOB_RESERVED_WITH_WARNING = 'job-reserved-with-warning'
    JOB_INSTALLATION_TIMEOUT = 'job-installation-timeout'
    JOB_INSTALLATION_KICKSTART_ERROR = 'job-installation-kickstart-error'


CLI_ERROR_PATTERNS = {
    BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE: re.compile(r'^Exception: .+:No distro tree matches Recipe:'),
    BkrErrorCauses.NO_SYSTEM_MATCHES_RECIPE: re.compile(r'^Recipe ID \d+ does not match any systems'),
}


INSTALLATION_ERROR_PATTERNS = {
    BkrErrorCauses.JOB_INSTALLATION_KICKSTART_ERROR: re.compile(
        r'^The following problem occurred on line \d+ of the kickstart file:'
    ),
}


def error_cause_extractor(text: str) -> BkrErrorCauses:
    for cause, pattern in CLI_ERROR_PATTERNS.items():
        if not pattern.match(text):
            continue

        return cause

    return BkrErrorCauses.NONE


def bkr_error_cause_extractor(output: gluetool.utils.ProcessOutput) -> BkrErrorCauses:
    if output.exit_code == 0:
        return BkrErrorCauses.NONE

    stderr = process_output_to_str(output, stream='stderr')
    stderr = stderr.strip() if stderr is not None else None

    if stderr is None:
        return BkrErrorCauses.NONE

    return error_cause_extractor(stderr)


@dataclasses.dataclass
class BeakerPoolData(PoolData):
    job_id: Optional[str] = None
    is_bootc: Optional[bool] = None


@dataclasses.dataclass
class BeakerPoolResourcesIDs(PoolResourcesIDs):
    job_id: Optional[str] = None


@dataclasses.dataclass(repr=False)
class AvoidGroupHostnames(SerializableContainer):
    groupname: str
    hostnames: list[str] = dataclasses.field(default_factory=list)


class ConstraintTranslationConfigType(TypedDict):
    operator: str
    value: str
    element: str


@dataclasses.dataclass
class BeakerPool:
    poolname: str
    system_type: Optional[str] = None


@dataclasses.dataclass
class JobTaskResult:
    taskname: str
    task_result: str
    task_status: str

    phasename: Optional[str] = None
    phase_result: Optional[str] = None

    message: Optional[str] = None


def parse_job_task_results(
    logger: gluetool.log.ContextAdapter, job_results: bs4.BeautifulSoup
) -> Result[list[JobTaskResult], Failure]:
    """
    Parse job results and return tasks and their results.

    :param bs4.BeautifulSoup job_results: Job results in xml format.
    :rtype: result.Result[Tuple[str, str], Failure]
    :returns: a list of :py:class:`JobTaskResult` instances, each describing one phase of job's tasks.
    """

    results: list[JobTaskResult] = []

    for task_element in job_results.find_all('task'):
        if list(task_element.find_all('result')):
            for task_result_element in task_element.find_all('result'):
                results.append(
                    JobTaskResult(
                        taskname=task_element['name'],
                        task_result=task_element['result'],
                        task_status=task_element['status'],
                        phasename=task_result_element['path'],
                        phase_result=task_result_element['result'],
                        message=task_result_element.string or None,
                    )
                )

        else:
            results.append(
                JobTaskResult(
                    taskname=task_element['name'],
                    task_result=task_element['result'],
                    task_status=task_element['status'],
                )
            )

    return Ok(results)


#: Mapping of operators to their Beaker representation. :py:attr:`Operator.MATCH` is missing on purpose: it is
#: intercepted in :py:func:`operator_to_beaker_op`.
OPERATOR_SIGN_TO_OPERATOR = {
    Operator.EQ: '==',
    Operator.NEQ: '!=',
    Operator.GT: '>',
    Operator.GTE: '>=',
    Operator.LT: '<',
    Operator.LTE: '<=',
}


def _new_tag(tag_name: str, **attrs: str) -> bs4.BeautifulSoup:
    return bs4.BeautifulSoup('', 'xml').new_tag(tag_name, **attrs)


def operator_to_beaker_op(operator: Operator, value: str) -> tuple[str, str]:
    """
    Convert constraint operator to Beaker "op".
    """

    if operator in OPERATOR_SIGN_TO_OPERATOR:
        return OPERATOR_SIGN_TO_OPERATOR[operator], value

    # MATCH has special handling - convert the pattern to a wildcard form - and that may be weird :/
    return 'like', value.replace('.*', '%').replace('.+', '%')


def _translate_constraint_by_config(
    constraint: Constraint, guest_request: GuestRequest, translations: list[ConstraintTranslationConfigType]
) -> Result[bs4.BeautifulSoup, Failure]:
    for translation in translations:
        if translation['operator'] != constraint.operator.value:
            continue

        if isinstance(translation['value'], str):
            if not re.match(translation['value'], str(constraint.value)):
                continue

        elif translation['value'] != constraint.value:
            continue

        r_rendered_raw_element = render_template(
            translation['element'], CONSTRAINT=constraint, **template_environment(guest_request=guest_request)
        )

        if not is_successful(r_rendered_raw_element):
            return Error(
                Failure.from_failure(
                    'failed to render constraint XML',
                    r_rendered_raw_element.failure(),
                    constraint=repr(constraint),
                    constraint_name=constraint.name,
                )
            )

        try:
            return Ok(bs4.BeautifulSoup(r_rendered_raw_element.unwrap(), 'xml'))

        except Exception as exc:
            return Error(Failure.from_exc('failed to parse XML', exc, source=translation['element']))

    return Error(
        Failure('constraint not supported by driver', constraint=repr(constraint), constraint_name=constraint.name)
    )


def constraint_to_beaker_filter(
    constraint: ConstraintBase,
    guest_request: GuestRequest,
    pool: 'BeakerDriver',
    constraint_parents: Optional[list[ConstraintBase]] = None,
    constraint_siblings: Optional[list[ConstraintBase]] = None,
) -> Result[Optional[bs4.BeautifulSoup], Failure]:
    """
    Convert a given constraint to XML tree representing Beaker filter compatible with Beaker's ``hostRequires``
    element.
    """

    constraint_parents = constraint_parents or []
    constraint_siblings = constraint_siblings or []

    if isinstance(constraint, And):
        grouping_and = _new_tag('and')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(
                child_constraint,
                guest_request,
                pool,
                constraint_parents=[*constraint_parents, constraint],
                constraint_siblings=constraint.constraints,
            )

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            child_element = r_child_element.unwrap()

            if child_element is not None:
                grouping_and.append(child_element)

        return Ok(grouping_and)

    if isinstance(constraint, Or):
        grouping_or = _new_tag('or')

        for child_constraint in constraint.constraints:
            r_child_element = constraint_to_beaker_filter(
                child_constraint,
                guest_request,
                pool,
                constraint_parents=[*constraint_parents, constraint],
                constraint_siblings=constraint.constraints,
            )

            if r_child_element.is_error:
                return Error(r_child_element.unwrap_error())

            child_element = r_child_element.unwrap()

            if child_element is not None:
                grouping_or.append(child_element)

        return Ok(grouping_or)

    constraint = cast(Constraint, constraint)

    constraint_name = constraint.expand_name()

    if constraint_name.property == 'boot':  # noqa: SIM102
        if constraint_name.child_property == 'method':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {}).get('boot', {}).get('method', {}).get('translations', []),
            )

    if constraint_name.property == 'compatible':  # noqa: SIM102
        if constraint_name.child_property == 'distro':
            system = _new_tag('system')

            r_config_constraint = _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {})
                .get('compatible', {})
                .get('distro', {})
                .get('translations', []),
            )

            if r_config_constraint.is_error:
                return Error(r_config_constraint.unwrap_error())

            system.append(r_config_constraint.unwrap())

            return Ok(system)

    if constraint_name.property == 'cpu':
        cpu = _new_tag('cpu')

        if constraint_name.child_property == 'processors':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            processors = _new_tag('processors', op=op, value=value)

            cpu.append(processors)

        elif constraint_name.child_property == 'cores':
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

        elif constraint_name.child_property == 'stepping':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            stepping = _new_tag('stepping', op=op, value=value)

            cpu.append(stepping)

        elif constraint_name.child_property == 'flag':
            op, value = operator_to_beaker_op(
                Operator.EQ if constraint.operator is Operator.CONTAINS else Operator.NEQ, str(constraint.value)
            )

            flag = _new_tag('flag', op=op, value=value)

            cpu.append(flag)

        elif constraint_name.child_property == 'vendor_name':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            vendor_name = _new_tag('vendor', op=op, value=value)

            cpu.append(vendor_name)

        else:
            return Error(Failure('constraint not supported by driver', constraint=repr(constraint)))

        return Ok(cpu)

    if constraint_name.property == 'disk':
        if constraint_name.child_property in ('is_expansion', 'min_size', 'max_size', 'length', 'expanded_length'):
            return Ok(_new_tag('or'))

        disk = _new_tag('disk')

        if constraint_name.child_property == 'size':
            # `disk.size` is represented as quantity, for Beaker XML we need to convert to bytes, integer.
            op, value = operator_to_beaker_op(
                constraint.operator, str(int(cast(SizeType, constraint.value).to('B').magnitude))
            )

            size = _new_tag('size', op=op, value=value)

            disk.append(size)

        elif constraint_name.child_property == 'model_name':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            model = _new_tag('model', op=op, value=value)

            disk.append(model)

        else:
            return Error(
                Failure(
                    'constraint not supported by driver', constraint=repr(constraint), constraint_name=constraint.name
                )
            )

        # 4th parent is a group collecting all `disk` entries
        if len(constraint_parents) >= 4:
            parent = constraint_parents[-4]

            # This should not happen unless environment parsing changes.
            if not isinstance(parent, And):
                return Error(
                    Failure(
                        'failed to find proper parent of disk constraint',
                        constraint=repr(constraint),
                        constraint_name=constraint.name,
                    )
                )

            group = _new_tag('and')

            nr_disks = _new_tag(
                'key_value',
                key='NR_DISKS',
                op=OPERATOR_SIGN_TO_OPERATOR[Operator.GTE],
                value=str(len(parent.constraints)),
            )

            group.append(disk)
            group.append(nr_disks)

            return Ok(group)

        else:
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
            constraint.operator, str(int(cast(SizeType, constraint.value).to('MiB').magnitude))
        )

        system = _new_tag('system')
        memory = _new_tag('memory', op=op, value=value)

        system.append(memory)

        return Ok(system)

    if constraint_name.property == 'hostname':
        op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

        hostname = _new_tag('hostname', op=op, value=value)
        if constraint.operator == Operator.NOTMATCH:
            group = _new_tag('not')
            group.append(hostname)
            return Ok(group)

        return Ok(hostname)

    if constraint_name.property == 'tpm':
        op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

        return Ok(_new_tag('key_value', key='TPM', op=op, value=str(constraint.value)))

    if constraint_name.property == 'virtualization':
        if constraint_name.child_property == 'is_supported':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {})
                .get('virtualization', {})
                .get('is_supported', {})
                .get('translations', []),
            )

        if constraint_name.child_property == 'is_virtualized':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {})
                .get('virtualization', {})
                .get('is_virtualized', {})
                .get('translations', []),
            )

        if constraint_name.child_property == 'hypervisor':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {})
                .get('virtualization', {})
                .get('hypervisor', {})
                .get('translations', []),
            )

    if constraint_name.property == 'network':
        if constraint_name.child_property in ('is_expansion', 'length', 'expanded_length'):
            return Ok(_new_tag('or'))

        if constraint_name.child_property == 'type' and constraint.value != 'eth':
            return Error(
                Failure(
                    'only eth networks are supported for beaker constraints',
                    constraint=repr(constraint_siblings),
                    constraint_name=constraint.name,
                )
            )

        # 3rd parent is a group collecting all `network` entries
        if len(constraint_parents) >= 3:
            parent = constraint_parents[-3]

            # This should not happen unless environment parsing changes.
            if not isinstance(parent, And):
                return Error(
                    Failure(
                        'failed to find proper parent of network constraint',
                        constraint=repr(constraint),
                        constraint_name=constraint.name,
                    )
                )

            return Ok(
                _new_tag(
                    'key_value',
                    key='NR_ETH',
                    op=OPERATOR_SIGN_TO_OPERATOR[Operator.GTE],
                    value=str(len(parent.constraints)),
                )
            )

        return Error(
            Failure('constraint not supported by driver', constraint=repr(constraint), constraint_name=constraint.name)
        )

    if constraint_name.property == 'system':  # noqa: SIM102
        if constraint_name.child_property == 'numa_nodes':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            system = _new_tag('system')
            numanodes = _new_tag('numanodes', op=op, value=value)

            system.append(numanodes)

            return Ok(system)

        if constraint_name.child_property == 'model_name':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            system = _new_tag('system')
            model = _new_tag('model', op=op, value=value)

            system.append(model)

            return Ok(system)

    if constraint_name.property == 'iommu':
        if constraint_name.child_property == 'is_supported':
            op, value = operator_to_beaker_op(constraint.operator, '')

            return Ok(_new_tag('key_value', key='VIRT_IOMMU', op=op, value='1' if constraint.value else '0'))

        if constraint_name.child_property == 'model_name':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {})
                .get('iommu', {})
                .get('model_name', {})
                .get('translations', []),
            )

    if constraint_name.property == 'zcrypt':  # noqa: SIM102
        if constraint_name.child_property == 'adapter':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {}).get('zcrypt', {}).get('adapter', {}).get('translations', []),
            )

        if constraint_name.child_property == 'mode':
            return _translate_constraint_by_config(
                constraint,
                guest_request,
                pool.pool_config.get('hw-constraints', {}).get('zcrypt', {}).get('mode', {}).get('translations', []),
            )

    if constraint_name.property == 'beaker':  # noqa: SIM102
        if constraint_name.child_property == 'pool':
            op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

            pool_container = _new_tag('pool', value=value)
            if constraint.operator == Operator.NEQ:
                group = _new_tag('not')
                group.append(pool_container)
                return Ok(group)
            return Ok(pool_container)

        if constraint_name.child_property == 'panic_watchdog':
            # Not a beaker HW contstraint. Affects attribute of the <watchdog/> tag.
            return Ok(None)

    if constraint_name.property == 'device' and constraint_name.child_property == 'driver':
        op, value = operator_to_beaker_op(constraint.operator, str(constraint.value))

        return Ok(_new_tag('key_value', key='MODULE', op=op, value=value))

    return Error(
        Failure('constraint not supported by driver', constraint=repr(constraint), constraint_name=constraint.name)
    )


def _prune_beaker_filter(tree: bs4.BeautifulSoup) -> Result[bs4.BeautifulSoup, Failure]:
    def _remove_duplicates(tag_name: str, key: str) -> int:
        changes = 0

        for el in tree.find_all(tag_name, attrs={'key': key}):
            if el.parent is None:
                continue

            siblings = [
                sibling
                for sibling in el.parent.find_all(
                    tag_name, attrs={'key': key, 'op': el.attrs['op'], 'value': el.attrs['value']}, resursive=False
                )
                if sibling is not el
            ]

            for sibling in siblings:
                sibling.extract()

                changes += 1

        return changes

    # Conversion process produces empty `and` and `or` tags, thanks to how Beaker deals with disks without flavors.
    # The following code is a crude attempt to get rid of some of them (there may be some left, empty `or` in `and`
    # in `or`) would keep the last `or` since we run just two swipes. But that's good enough for now.
    def _remove_empty(tag_name: str) -> int:
        changes = 0

        for el in tree.find_all(tag_name):
            if len(el.contents) == 0:
                el.extract()

                changes += 1

        return changes

    def _remove_singles(tag_name: str) -> int:
        changes = 0

        for el in tree.find_all(tag_name):
            if len(el.contents) == 1:
                el.replace_with(el.contents[0])

                changes += 1

        return changes

    for _ in range(5):
        changes = (
            _remove_empty('or')
            + _remove_empty('and')
            + _remove_empty('system')
            + _remove_singles('or')
            + _remove_singles('and')
            + _remove_duplicates('key_value', 'NR_ETH')
            + _remove_duplicates('key_value', 'NR_DISKS')
        )

        if changes == 0:
            break

    return Ok(tree)


def environment_to_beaker_filter(
    environment: Environment,
    guest_request: GuestRequest,
    pool: 'BeakerDriver',
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
        r_beaker_filter = constraint_to_beaker_filter(Constraint.from_arch(environment.hw.arch), guest_request, pool)

    else:
        r_beaker_filter = constraint_to_beaker_filter(
            And([Constraint.from_arch(environment.hw.arch), constraints]), guest_request, pool
        )

    if r_beaker_filter.is_error:
        return r_beaker_filter

    beaker_filter = r_beaker_filter.unwrap()

    if beaker_filter is None:
        return Error(
            Failure(
                'Failed to parse constraints into a beaker filter.',
                constraints=constraints,
                beaker_filter=beaker_filter,
            )
        )

    return _prune_beaker_filter(beaker_filter)


def groups_to_beaker_filter(avoid_groups: list[str]) -> Result[bs4.BeautifulSoup, Failure]:
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


def hostnames_to_beaker_filter(avoid_hostnames: list[str]) -> Result[bs4.BeautifulSoup, Failure]:
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


def beaker_pools_to_beaker_filter(pools: list[BeakerPool]) -> Result[bs4.BeautifulSoup, Failure]:
    """
    Convert given lists of beaker pools to Beaker XML tree representing Beaker filter compatible with Beaker's
    ``hostRequires`` element.

    For each ``pool`` and optional ``system-type``, a following element is created:

    .. code-block:: xml

       <and>
         <pool value="$pool"/>
         <system_type op="=" value="$system_type"/>
       </and>

    :param avoid_hostnames: list of Beaker pools to limit provisioning to.
    :returns: a Beaker filter representing Beaker pool limitation.
    """

    # This is a container for all per-tag hostname elements. When called with an empty list, this would result
    # in an empty <and/> element being returned - but that's OK, _prune_beaker_filter() can deal with such
    # elements, and it simplifies handling of return values, no pesky `if is None` tests.
    container = _new_tag('or')

    for pool in pools:
        if pool.system_type:
            pool_container = _new_tag('and')

            pool_container.append(_new_tag('pool', value=pool.poolname))
            pool_container.append(_new_tag('system_type', op='=', value=pool.system_type))

            container.append(pool_container)

        else:
            container.append(_new_tag('pool', value=pool.poolname))

    return Ok(container)


def merge_beaker_filters(filters: list[bs4.BeautifulSoup]) -> Result[bs4.BeautifulSoup, Failure]:
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
    guest_request: GuestRequest,
    pool: 'BeakerDriver',
    avoid_groups: list[str],
    avoid_hostnames: list[str],
) -> Result[Optional[bs4.BeautifulSoup], Failure]:
    """
    From given inputs, create a Beaker filter.

    :param environment: environment as a source of constraints.
    :param avoid_groups: list of Beaker groups to filter out when provisioning.
    :param avoid_hostnames: list of Beaker hostnames to filter out when provisioning.
    :returns: a Beaker filter taking all given inputs into account.
    """

    beaker_filters: list[bs4.BeautifulSoup] = []

    if environment.has_hw_constraints:
        r_beaker_filter = environment_to_beaker_filter(environment, guest_request, pool)

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

    r_beaker_pools = pool.beaker_pools

    if r_beaker_pools.is_error:
        return Error(r_beaker_pools.unwrap_error())

    if r_beaker_pools.unwrap():
        r_beaker_filter = beaker_pools_to_beaker_filter(r_beaker_pools.unwrap())

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filters.append(r_beaker_filter.unwrap())

    if not beaker_filters:
        return Ok(None)

    r_beaker_filter = merge_beaker_filters(beaker_filters)

    if r_beaker_filter.is_error:
        return Error(r_beaker_filter.unwrap_error())

    return _prune_beaker_filter(r_beaker_filter.unwrap())


@dataclasses.dataclass(repr=False)
class BeakerPoolImageInfo(PoolImageInfo):
    variant: Optional[str] = 'Server'
    bootc_image: Optional[str] = None


class BeakerDriver(PoolDriver):
    drivername = 'beaker'

    image_info_class = BeakerPoolImageInfo
    pool_data_class = BeakerPoolData

    _image_map_hook_name = 'BEAKER_ENVIRONMENT_TO_IMAGE'

    #: Template for a cache key holding avoid groups hostnames.
    POOL_AVOID_GROUPS_HOSTNAMES_CACHE_KEY = 'pool.{}.avoid-groups.hostnames'

    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str, pool_config: dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)

        self.avoid_groups_hostnames_cache_key = self.POOL_AVOID_GROUPS_HOSTNAMES_CACHE_KEY.format(self.poolname)  # noqa: FS002,E501

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> _Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = True
        capabilities.supports_native_kickstart = True
        capabilities.supported_guest_logs = [
            ('console:dump', GuestLogContentType.URL),
            ('console:dump', GuestLogContentType.BLOB),
            ('sys.log:dump', GuestLogContentType.URL),
        ]

        return _Ok(capabilities)

    @property
    def avoid_groups(self) -> Result[list[str], Failure]:
        return Ok(self.pool_config.get('avoid-groups', []))

    @property
    def avoid_hostnames(self) -> Result[list[str], Failure]:
        r_avoid_hostnames = self.get_avoid_groups_hostnames()

        if r_avoid_hostnames.is_error:
            return Error(r_avoid_hostnames.unwrap_error())

        return Ok(
            sum(
                (group.hostnames for group in r_avoid_hostnames.unwrap().values()),
                self.pool_config.get('avoid-hostnames', []),
            )
        )

    @property
    def beaker_pools(self) -> Result[list[BeakerPool], Failure]:
        pools: list[BeakerPool] = []

        for entry in self.pool_config.get('pools', []):
            if isinstance(entry, str):
                pools.append(BeakerPool(poolname=entry))

            elif isinstance(entry, dict):
                pools.append(BeakerPool(poolname=entry['poolname'], system_type=entry.get('system-type')))

            else:
                return Error(Failure('unsupported beaker pool', beaker_pool=entry))

        return Ok(pools)

    @property
    def console_failure_patterns(self) -> Result[Optional[list[Pattern[str]]], Failure]:
        r_patterns = self.pool_config.get('console-failure-patterns', [])
        patterns = []
        for pattern in r_patterns:
            try:
                re.compile(pattern)
            except Exception:
                return Error(
                    Failure(
                        'failed to re.compile the pattern',
                        pattern=pattern,
                    )
                )
            patterns.append(pattern)

        return Ok(patterns)

    @property
    def failed_avc_patterns(self) -> Result[list[Pattern[str]], Failure]:
        patterns = self.pool_config.get('failed-avc-result-patterns')

        if not patterns:
            return Ok([])

        compiled_patterns: list[Pattern[str]] = []

        for pattern in patterns:
            try:
                compiled_patterns.append(re.compile(pattern))

            except Exception as exc:
                return Error(Failure.from_exc('failed to compile task result pattern', exc, pattern=pattern))

        return Ok(compiled_patterns)

    @property
    def ignore_avc_on_compose_pattern(self) -> Result[Optional[Pattern[str]], Failure]:
        pattern = self.pool_config.get('ignore-avc-on-compose-pattern')

        if pattern is None:
            return Ok(None)

        try:
            return Ok(re.compile(pattern))

        except Exception as exc:
            return Error(Failure.from_exc('failed to compile ignore-avc-on-compose pattern', exc, pattern=pattern))

    @property
    def installation_method_map(self) -> Result[list[tuple[Pattern[str], str]], Failure]:
        patterns_in: dict[str, str] = self.pool_config.get('installation-method-map', {})
        patterns_out: list[tuple[Pattern[str], str]] = []

        for pattern, method in patterns_in.items():
            try:
                patterns_out.append((re.compile(pattern), method))

            except Exception:
                return Error(Failure('failed to compile installation method pattern', pattern=pattern, method=method))

        return Ok(patterns_out)

    def _run_bkr(
        self, logger: gluetool.log.ContextAdapter, options: list[str], commandname: Optional[str] = None
    ) -> Result[CLIOutput, Failure]:
        """
        Run bkr command with additional options

        :param gluetool.log.ContextAdapter logger: logger to use for logging.
        :param List(str) options: options for the command
        :returns: either a valid result, :py:class:`CLIOutput` instance, or an error with a :py:class:`Failure`
            describing the problem.
        """

        r_timeout = KNOB_BKR_COMMAND_TERMINATION_TIMEOUT.get_value(entityname=self.poolname)

        if r_timeout.is_error:
            return Error(r_timeout.unwrap_error())

        bkr_command: list[str] = [
            'bkr',
            # Subcommand is the first item of `options`...
            options[0],
        ]

        if self.pool_config.get('username') and self.pool_config.get('password'):
            bkr_command += ['--username', self.pool_config['username'], '--password', self.pool_config['password']]

        # ... and the rest are its options.
        bkr_command += options[1:]

        r_run = run_cli_tool(
            logger,
            bkr_command,
            json_output=False,
            command_scrubber=lambda cmd: ['bkr', *options],
            poolname=self.poolname,
            commandname=commandname,
            cause_extractor=bkr_error_cause_extractor,
            deadline=datetime.timedelta(seconds=r_timeout.unwrap()),
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        return Ok(r_run.unwrap())

    def _handle_no_distro_matches_recipe_error(
        self, failure: Failure, guest_request: GuestRequest, pool_data: Optional[BeakerPoolData] = None
    ) -> Result[ProvisioningProgress, Failure]:
        # TODO: it would be cleaner to use some "empty" pool data but there are types guarding the pool data
        # from ever to be optional. But since we return CANCEL anyway, it should be safe until we find a better
        # way.
        pool_data = pool_data or BeakerPoolData(job_id='never-to-be-used')

        failure.recoverable = False

        PoolMetrics.inc_error(self.poolname, BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE)

        return Ok(ProvisioningProgress(state=ProvisioningState.CANCEL, pool_data=pool_data, pool_failures=[failure]))

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        resource_ids = BeakerPoolResourcesIDs.unserialize_from_json(raw_resource_ids)

        if resource_ids.job_id is not None:
            r_output = self._run_bkr(logger, ['job-cancel', resource_ids.job_id], commandname='bkr.job-cancel')

            if r_output.is_error:
                return Error(Failure.from_failure('failed to cancel job', r_output.unwrap_error()))

            self.inc_costs(logger, ResourceType.VIRTUAL_MACHINE, resource_ids.ctime)

        return Ok(ReleasePoolResourcesState.RELEASED)

    def image_name_to_image_info(
        self, logger: gluetool.log.ContextAdapter, imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        # TODO: is it true that `name` is equal to `id` in Beaker? Is really each `name` we get from
        # the `compose` => `image name` mapping really the same as "ID" of the distro? I believe this
        # is indeed correct, but needs checking.
        #
        # The thing is: this could be true even for OpenStack and AWS, if user would use `compose` => `image ID` map.
        # We want the right-hand side to be human-readable and easy to follow, therefore OpenStack and AWS have this
        # extra level of dereference.

        r_pattern = KNOB_ENVIRONMENT_TO_IMAGE_MAPPING_PATTERN.get_value(entityname=self.poolname)

        if r_pattern.is_error:
            return Error(Failure.from_failure('failed to lookup image pattern', r_pattern.unwrap_error()))

        pattern = r_pattern.unwrap()

        match = re.match(pattern, imagename)

        if not match:
            return Error(
                Failure('failed to extract components from image mapping', pattern=pattern, imagename=imagename)
            )

        groups = match.groupdict()

        try:
            image = BeakerPoolImageInfo(
                name=groups['distro'],
                id=groups['distro'],
                arch=None,
                boot=FlavorBoot(),
                ssh=PoolImageSSHInfo(),
                supports_kickstart=groups['bootc_image'] is None,
                # beaker images don't have a concept of creation date
                created_at=None,
            )

            if groups['variant'] is not None:
                image.variant = groups['variant']

            if groups['bootc_image'] is not None:
                image.bootc_image = groups['bootc_image']

            return Ok(image)

        except Exception as exc:
            return Error(
                Failure.from_exc(
                    'failed to extract components from image mapping',
                    exc,
                    pattern=pattern,
                    imagename=imagename,
                    groups=groups,
                )
            )

    def _create_bkr_kickstart_options(
        self,
        kickstart: Kickstart,
    ) -> list[str]:
        options = []

        if kickstart.kernel_options is not None:
            options += ['--kernel-options', kickstart.kernel_options]

        if kickstart.kernel_options_post is not None:
            options += ['--kernel-options-post', kickstart.kernel_options_post]

        if kickstart.metadata is not None:
            options += ['--ks-meta', kickstart.metadata]

        if kickstart.script is not None:
            options += ['--ks-append', kickstart.script]

        if kickstart.pre_install is not None:
            options += ['--ks-append', kickstart.pre_install]

        if kickstart.post_install is not None:
            options += ['--ks-append', kickstart.post_install]

        return options

    def _create_wow_options(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        distro: BeakerPoolImageInfo,
    ) -> Result[list[str], Failure]:
        # Job whiteboard
        r_whiteboard_template = KNOB_JOB_WHITEBOARD_TEMPLATE.get_value(entityname=self.poolname)

        if r_whiteboard_template.is_error:
            return Error(r_whiteboard_template.unwrap_error())

        r_whiteboard = render_template(
            r_whiteboard_template.unwrap(), **template_environment(guest_request=guest_request)
        )

        if not is_successful(r_whiteboard):
            return Error(r_whiteboard.failure())

        # Tags to expose in the job
        r_tags = self.get_guest_tags(logger, session, guest_request)

        if r_tags.is_error:
            return Error(r_tags.unwrap_error())

        # Custom installation method
        r_installation_method_map = self.installation_method_map

        if r_installation_method_map.is_error:
            return Error(r_installation_method_map.unwrap_error())

        installation_method_needle = ':'.join(
            [guest_request.environment.os.compose, guest_request.environment.hw.arch, distro.id, distro.variant or '']
        )

        installation_methods = [
            installation_method
            for pattern, installation_method in r_installation_method_map.unwrap()
            if pattern.match(installation_method_needle)
        ]

        # Custom kickstart filepath
        if distro.bootc_image:
            # Override kickstart template for bootc installation
            r_kickstart_filepath = KNOB_KICKSTART_TEMPLATE_BOOTC_FILEPATH.get_value(entityname=self.poolname)

            if r_kickstart_filepath.is_error:
                return Error(r_kickstart_filepath.unwrap_error())

            kickstart_filepath: Optional[str] = os.path.abspath(r_kickstart_filepath.unwrap())

        else:
            kickstart_filepath = None

        # Custom kickstart meta
        r_ks_meta_template = KNOB_KICKSTART_METADATA_TEMPLATE.get_value(entityname=self.poolname)

        if r_ks_meta_template.is_error:
            return Error(r_ks_meta_template.unwrap_error())

        r_ks_meta = render_template(
            r_ks_meta_template.unwrap(), DISTRO=distro, **template_environment(guest_request=guest_request)
        )

        if not is_successful(r_ks_meta):
            return Error(r_ks_meta.failure())

        ks_meta = r_ks_meta.unwrap()

        if guest_request.environment.has_ks_specification or ks_meta:
            guest_request.environment.kickstart.metadata = ' '.join(
                meta for meta in [ks_meta, guest_request.environment.kickstart.metadata] if meta
            )

            kickstart_options = self._create_bkr_kickstart_options(guest_request.environment.kickstart)

        else:
            kickstart_options = []

        # Beaker watchdog
        def _requires_panic_watchdog(constraint: ConstraintBase) -> bool:
            if isinstance(constraint, Constraint):
                return constraint.name == 'beaker.panic_watchdog' and constraint.value is True

            if isinstance(constraint, CompoundConstraint):
                return any(_requires_panic_watchdog(child) for child in constraint.constraints)

            return False

        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()
        panic_watchdog_enabled = False

        if constraints:
            panic_watchdog_enabled = _requires_panic_watchdog(constraints)

        # Putting it all together
        r_command_template = KNOB_BKR_CREATE_COMMAND_TEMPLATE.get_value(entityname=self.poolname)

        if r_command_template.is_error:
            return Error(r_command_template.unwrap_error())

        r_command_rendered = render_template(
            r_command_template.unwrap(),
            IMAGE=distro.serialize(),
            RESERVATION_DURATION=KNOB_RESERVATION_DURATION.value,
            KICKSTART_FILEPATH=kickstart_filepath,
            KICKSTART_META=r_ks_meta.unwrap(),
            KICKSTART_OPTIONS=kickstart_options,
            INSTALLATION_METHOD=installation_methods[0] if installation_methods else None,
            PANIC_WATCHDOG_ENABLED=panic_watchdog_enabled,
            TAGS=r_tags.unwrap(),
            WHITEBOARD=r_whiteboard.unwrap(),
            **template_environment(guest_request),
        )

        if not is_successful(r_command_rendered):
            return Error(r_command_rendered.failure())

        log_blob(logger.debug, 'wow options', r_command_rendered.unwrap())

        try:
            return Ok(shlex.split(r_command_rendered.unwrap()))

        except Exception as exc:
            return Error(
                Failure.from_exc('failed to parse Beaker command', exc, rendered_command=r_command_rendered.unwrap())
            )

    def _create_job_xml(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[tuple[bs4.BeautifulSoup, bool], Failure]:
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
            guest_request.environment, guest_request, self, r_avoid_groups.unwrap(), r_avoid_hostnames.unwrap()
        )

        if r_beaker_filter.is_error:
            return Error(r_beaker_filter.unwrap_error())

        beaker_filter = r_beaker_filter.unwrap()

        r_distros: Result[list[BeakerPoolImageInfo], Failure] = self._guest_request_to_image(
            logger, session, guest_request
        )

        if r_distros.is_error:
            return Error(r_distros.unwrap_error())

        distros = r_distros.unwrap()

        distro = distros[0]

        is_bootc = distro.bootc_image is not None

        r_wow_options = self._create_wow_options(logger, session, guest_request, distro)

        if r_wow_options.is_error:
            return Error(r_wow_options.unwrap_error())

        self.log_acquisition_attempt(logger, session, guest_request, image=distro)

        r_workflow_simple = self._run_bkr(logger, r_wow_options.unwrap(), commandname='bkr.workflow-simple')
        if r_workflow_simple.is_error:
            return Error(Failure.from_failure('failed to create job', r_workflow_simple.unwrap_error()))

        bkr_output = r_workflow_simple.unwrap()

        try:
            job_xml = bs4.BeautifulSoup(bkr_output.stdout, 'xml')

        except Exception as exc:
            return Error(Failure.from_exc('failed to parse job XML', exc, command_output=bkr_output.process_output))

        if beaker_filter is None:
            return Ok((job_xml, is_bootc))

        log_xml(logger.debug, 'job', job_xml)
        log_xml(logger.debug, 'filter', beaker_filter)

        host_requires = job_xml.find_all('hostRequires')

        if len(job_xml.find_all('hostRequires')) != 1:
            return Error(Failure('job XML is missing hostRequires element', job=job_xml.prettify()))

        next(iter(host_requires)).append(beaker_filter)

        log_xml(logger.debug, 'job with filter', job_xml)

        return Ok((job_xml, is_bootc))

    def _submit_job(self, logger: gluetool.log.ContextAdapter, job: bs4.BeautifulSoup) -> Result[str, Failure]:
        """
        Submit a Beaker job.

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param xml job: A job to submit.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        log_xml(self.logger.debug, 'job to submit', job)

        with create_tempfile(file_contents=job.prettify(), prefix='beaker-job-', suffix='.xml') as job_filepath:
            # Temporary file has limited permissions, but we'd like to make the file inspectable.
            os.chmod(job_filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            r_job_submit = self._run_bkr(logger, ['job-submit', job_filepath], commandname='bkr.job-submit')

        if r_job_submit.is_error:
            return Error(Failure.from_failure('failed to submit job', r_job_submit.unwrap_error(), job=job.prettify()))

        bkr_output = r_job_submit.unwrap()

        # Parse job id from output
        try:
            # Submitted: ['J:1806666']  # noqa: ERA001
            first_job_index = bkr_output.stdout.index("'") + 1
            last_job_index = len(bkr_output.stdout) - bkr_output.stdout[::-1].index("'") - 1

            # J:1806666  # noqa: ERA001
            job_id = bkr_output.stdout[first_job_index:last_job_index]

        except Exception as exc:
            return Error(
                Failure.from_exc(
                    'cannot convert job-submit output to job ID', exc, command_output=bkr_output.process_output
                )
            )

        logger.info(f'Job submitted: {job_id}')

        return Ok(job_id)

    def _create_job(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[tuple[str, bool], Failure]:
        r_job_xml = self._create_job_xml(logger, session, guest_request)

        if r_job_xml.is_error:
            return Error(r_job_xml.unwrap_error())

        job_xml, is_bootc = r_job_xml.unwrap()

        r_job_id = self._submit_job(logger, job_xml)

        if r_job_id.is_error:
            return Error(r_job_id.unwrap_error())

        return Ok((r_job_id.unwrap(), is_bootc))

    def _get_job_results(self, logger: gluetool.log.ContextAdapter, job_id: str) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Run 'bkr job-results' comand and return job results.

        :param str job_id: Job id that will be rescheduled.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job results, or specification of error.
        """

        r_results = self._run_bkr(logger, ['job-results', job_id], commandname='bkr.job-results')

        if r_results.is_error:
            return Error(Failure.from_failure('failed to fetch job results', r_results.unwrap_error()))

        bkr_output = r_results.unwrap()

        try:
            return Ok(bs4.BeautifulSoup(bkr_output.stdout, 'xml'))

        except Exception as exc:
            return Error(
                Failure.from_exc('failed to parse job results XML', exc, command_output=bkr_output.process_output)
            )

    def _parse_recipe_install_start(
        self, logger: gluetool.log.ContextAdapter, job_results: bs4.BeautifulSoup
    ) -> Result[Optional[datetime.datetime], Failure]:
        """
        Parse job results and return guest installation start time.

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with guest address, or specification of error.
        """

        install = job_results.find('installation')

        if not install:
            return Error(
                Failure('installation element was not found in job results', job_results=job_results.prettify())
            )

        install_start = install.get('install_started', None)

        if install_start is None:
            return Ok(None)

        try:
            return Ok(datetime.datetime.fromisoformat(install_start))
        except ValueError as exc:
            return Error(Failure.from_exc('parsing installation start time failed', exc, date=install_start))

    def _parse_job_status(
        self, logger: gluetool.log.ContextAdapter, job_results: bs4.BeautifulSoup
    ) -> Result[tuple[str, str, Optional[str]], Failure]:
        """
        Parse job results and return its result and status.

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[Tuple[str, str], Failure]
        :returns: a tuple with two items, job result and status, or specification of error.
        """

        if not job_results.find('job') or len(job_results.find_all('job')) != 1:
            return Error(Failure('job results XML has unknown structure', job_results=job_results.prettify()))

        job = job_results.find('job')

        if not job['result']:
            return Error(
                Failure('job results XML does not contain result attribute', job_results=job_results.prettify())
            )

        if not job['status']:
            return Error(
                Failure('job results XML does not contain status attribute', job_results=job_results.prettify())
            )

        return Ok((job['result'].lower(), job['status'].lower(), job_results.find('recipe').attrs.get('system')))

    def _parse_guest_address(
        self, logger: gluetool.log.ContextAdapter, job_results: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Parse job results and return guest address

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with guest address, or specification of error.
        """

        if not job_results.find('recipe')['system']:
            return Error(Failure('System element was not found in job results', job_results=job_results.prettify()))

        return Ok(job_results.find('recipe')['system'])

    def _analyze_beaker_logs(
        self, log_urls: list[str], patterns: list[Pattern[str]]
    ) -> Result[Optional[list[str]], Failure]:
        failures = []
        for url in log_urls:
            try:
                response = requests.get(
                    url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
                )
                response.raise_for_status()

            except requests.exceptions.RequestException as exc:
                return Error(Failure.from_exc('failed to fetch Beaker log URL', exc, url=url))

            for pattern in patterns:
                if not any(pattern.search(line.decode('utf-8', 'ignore')) for line in response.iter_lines()):
                    continue
                failures.append(f'The pattern found in console log: {pattern}')

        return Ok(failures)

    def _handle_job_update_successfully_completed(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        pool_data: BeakerPoolData,
        job_results: bs4.BeautifulSoup,
        job_task_results: list[JobTaskResult],
        job_result: str,
        job_status: str,
        job_failed: Optional[BkrErrorCauses],
        system: Optional[str],
        failure_details: dict[str, Any],
    ) -> Result[Optional[ProvisioningProgress], Failure]:
        if job_result != 'pass':
            return Ok(None)

        r_guest_address = self._parse_guest_address(logger, job_results)

        if r_guest_address.is_error:
            return Error(r_guest_address.unwrap_error().update(**failure_details))

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                address=r_guest_address.unwrap(),
            )
        )

    def _handle_job_update_new(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        pool_data: BeakerPoolData,
        job_results: bs4.BeautifulSoup,
        job_task_results: list[JobTaskResult],
        job_result: str,
        job_status: str,
        job_failed: Optional[BkrErrorCauses],
        system: Optional[str],
        failure_details: dict[str, Any],
    ) -> Result[Optional[ProvisioningProgress], Failure]:
        if job_result != 'new':
            return Ok(None)

        r_console_log = self._get_beaker_machine_log_url(logger, guest_request, 'console.log')

        if r_console_log.is_error:
            return Error(r_console_log.unwrap_error().update(**failure_details))

        # fetch console log, grab patterns
        r_failure_patterns = self.console_failure_patterns

        if r_failure_patterns.is_error:
            return Error(r_failure_patterns.unwrap_error().update(**failure_details))

        console_log = r_console_log.unwrap()
        failure_patterns = r_failure_patterns.unwrap()

        if console_log and failure_patterns:
            r_is_failed = self._analyze_beaker_logs([console_log], failure_patterns)

            if r_is_failed.is_error:
                return Error(r_is_failed.unwrap_error().update(**failure_details))

            failures = r_is_failed.unwrap()

            if failures:
                return Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                        pool_failures=[Failure('beaker job failed', failures=failures, **failure_details)],
                    )
                )

        # Check how long the guest has been in installing state
        if job_status == 'installing':
            now = datetime.datetime.utcnow()
            r_install_started = self._parse_recipe_install_start(logger, job_results)

            if r_install_started.is_error:
                return Error(r_install_started.unwrap_error().update(**failure_details))

            r_install_timeout = KNOB_INSTALLATION_TIMEOUT.get_value(entityname=self.poolname, session=session)

            if r_install_timeout.is_error:
                return Error(r_install_timeout.unwrap_error().update(**failure_details))

            install_started = r_install_started.unwrap()

            # We need the check for None as the installation might not have started yet but the state is already
            # marked as installing and there is not installation start time.
            if install_started is not None and (now - install_started).total_seconds() > r_install_timeout.unwrap():
                PoolMetrics.inc_aborts(
                    self.poolname,
                    system,
                    guest_request.environment.os.compose,
                    guest_request.environment.hw.arch,
                    BkrErrorCauses.JOB_INSTALLATION_TIMEOUT,
                )

                return Ok(
                    ProvisioningProgress(
                        state=ProvisioningState.CANCEL,
                        pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                        pool_failures=[Failure('installation did not finish in time', **failure_details)],
                    )
                )

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
            )
        )

    def _handle_job_update_failed_avc_denials(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        pool_data: BeakerPoolData,
        job_results: bs4.BeautifulSoup,
        job_task_results: list[JobTaskResult],
        job_result: str,
        job_status: str,
        job_failed: Optional[BkrErrorCauses],
        system: Optional[str],
        failure_details: dict[str, Any],
    ) -> Result[Optional[ProvisioningProgress], Failure]:
        if job_failed is None:
            return Ok(None)

        r_failed_avc_patterns = self.failed_avc_patterns

        if r_failed_avc_patterns.is_error:
            return Error(r_failed_avc_patterns.unwrap_error().update(**failure_details))

        matchable_job_task_results: list[str] = [
            f'{result.taskname}:{result.task_result}:{result.task_status}:{result.phasename or ""}:{result.phase_result or ""}:{result.message or ""}'  # noqa: E501
            for result in job_task_results
        ]

        log_dict_yaml(logger.info, 'matchable job task results', matchable_job_task_results)

        fail_reason_avc_in_install = all(
            any(pattern.match(result) for result in matchable_job_task_results)
            for pattern in r_failed_avc_patterns.unwrap()
        )

        if not fail_reason_avc_in_install:
            return Ok(None)

        logger.warning('detected AVC denials during installation')

        r_ignore_avc_on_compose_pattern = self.ignore_avc_on_compose_pattern

        if r_ignore_avc_on_compose_pattern.is_error:
            return Error(r_ignore_avc_on_compose_pattern.unwrap_error().update(**failure_details))

        ignore_avc_on_compose_pattern = r_ignore_avc_on_compose_pattern.unwrap()

        if not ignore_avc_on_compose_pattern or not ignore_avc_on_compose_pattern.match(
            guest_request.environment.os.compose
        ):
            return Ok(None)

        r_guest_address = self._parse_guest_address(logger, job_results)

        if r_guest_address.is_error:
            return Error(r_guest_address.unwrap_error().update(**failure_details))

        logger.info('ignoring AVC denials during installation')

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                pool_failures=[Failure('AVC denials during installation', **failure_details)],
                address=r_guest_address.unwrap(),
            )
        )

    def _handle_job_update_installation_error(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        pool_data: BeakerPoolData,
        job_results: bs4.BeautifulSoup,
        job_task_results: list[JobTaskResult],
        job_result: str,
        job_status: str,
        job_failed: Optional[BkrErrorCauses],
        system: Optional[str],
        failure_details: dict[str, Any],
    ) -> Result[Optional[ProvisioningProgress], Failure]:
        if job_failed is None or job_failed != BkrErrorCauses.JOB_FAILED:
            return Ok(None)

        # For some reason the installation error cause is hidden under the first task
        for task in job_results.find_all('task'):
            for result in task.find_all('result'):
                # Each result should only ever contain 1 result
                # Asserting on data from outside source is not a great idea
                assert len(result.contents) == 1

                for cause, pattern in INSTALLATION_ERROR_PATTERNS.items():
                    if pattern.match(result.contents[0]):
                        PoolMetrics.inc_aborts(
                            self.poolname,
                            system,
                            guest_request.environment.os.compose,
                            guest_request.environment.hw.arch,
                            cause,
                        )

                        return Ok(
                            ProvisioningProgress(
                                state=ProvisioningState.FAILED,
                                pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                                pool_failures=[Failure('beaker job failed', cause=cause.value, **failure_details)],
                            )
                        )

        return Ok(None)

    def _handle_job_update_failed(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        pool_data: BeakerPoolData,
        job_results: bs4.BeautifulSoup,
        job_task_results: list[JobTaskResult],
        job_result: str,
        job_status: str,
        job_failed: Optional[BkrErrorCauses],
        system: Optional[str],
        failure_details: dict[str, Any],
    ) -> Result[Optional[ProvisioningProgress], Failure]:
        if job_failed is None:
            return Ok(None)

        PoolMetrics.inc_aborts(
            self.poolname, system, guest_request.environment.os.compose, guest_request.environment.hw.arch, job_failed
        )

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.CANCEL,
                pool_data=guest_request.pool_data.mine(self, BeakerPoolData),
                pool_failures=[Failure('beaker job failed', cause=job_failed.value, **failure_details)],
            )
        )

    _JOB_UPDATE_HANDLERS: tuple[
        Callable[
            [
                'BeakerDriver',
                gluetool.log.ContextAdapter,
                sqlalchemy.orm.session.Session,
                GuestRequest,
                BeakerPoolData,
                bs4.BeautifulSoup,
                list[JobTaskResult],
                str,
                str,
                Optional[BkrErrorCauses],
                Optional[str],
                dict[str, Any],
            ],
            Result[Optional[ProvisioningProgress], Failure],
        ],
        ...,
    ] = (
        _handle_job_update_successfully_completed,
        _handle_job_update_new,
        _handle_job_update_failed_avc_denials,
        _handle_job_update_installation_error,
        # This one should be last, as it reports anything that failed and was not claimed by a previous handler.
        _handle_job_update_failed,
    )

    def update_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.

        :param BeakerGuest guest: Guest that will be updated.
        :rtype: Result[BeakerGuest, Failure]
        :returns: :py:class:`result.Result` with guest, or specification of error.
        """

        pool_data = guest_request.pool_data.mine(self, BeakerPoolData)

        if not pool_data.job_id:
            return Error(Failure('cannot update Beaker job without job ID'))

        r_job_results = self._get_job_results(logger, pool_data.job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        job_results = r_job_results.unwrap()

        r_job_status = self._parse_job_status(logger, job_results)

        if r_job_status.is_error:
            return Error(r_job_status.unwrap_error())

        job_result, job_status, system = r_job_status.unwrap()

        r_job_task_results = parse_job_task_results(logger, job_results)

        if r_job_task_results.is_error:
            return Error(r_job_task_results.unwrap_error())

        job_task_results = r_job_task_results.unwrap()

        log_table(
            logger.info,
            f'current job status {guest_request.pool_data.mine(self, BeakerPoolData).job_id}:{job_result}:{job_status}',
            [['Task', 'Result', 'Status', 'Phase', 'Phase result', 'Message']]
            + [[item or '' for item in dataclasses.astuple(job_task_result)] for job_task_result in job_task_results],
            headers='firstrow',
            tablefmt='psql',
        )

        job_failed: Optional[BkrErrorCauses] = None

        if job_result == 'fail':
            job_failed = BkrErrorCauses.JOB_FAILED

        elif job_status == 'aborted':
            job_failed = BkrErrorCauses.JOB_ABORTED

        elif job_status == 'cancelled':
            job_failed = BkrErrorCauses.JOB_CANCELLED

        elif job_status == 'reserved' and job_result == 'warn':
            job_failed = BkrErrorCauses.JOB_RESERVED_WITH_WARNING

        if any(
            error_cause_extractor(result.message) == BkrErrorCauses.NO_SYSTEM_MATCHES_RECIPE
            for result in job_task_results
            if result.message
        ):
            logger.warning('no system matches recipe')

            job_failed = BkrErrorCauses.NO_SYSTEM_MATCHES_RECIPE

        failure_details: dict[str, Any] = {
            'job_result': job_result,
            'job_status': job_status,
            'job_results': job_results.prettify(),
            'job_failed': job_failed.value if job_failed else None,
            'system': system,
        }

        for handler in self._JOB_UPDATE_HANDLERS:
            r_handler_outcome = handler(
                self,
                logger,
                session,
                guest_request,
                pool_data,
                job_results,
                job_task_results,
                job_result,
                job_status,
                job_failed,
                system,
                failure_details,
            )

            if r_handler_outcome.is_error:
                return Error(r_handler_outcome.unwrap_error().update(**failure_details))

            provisioning_progress = r_handler_outcome.unwrap()

            if provisioning_progress is not None:
                return Ok(provisioning_progress)

        return Error(Failure('unknown status', **failure_details))

    def guest_watchdog(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
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

        r_ssh_timeout = KNOB_GUEST_WATCHDOG_SSH_CONNECT_TIMEOUT.get_value(session=session, entityname=self.poolname)

        if r_ssh_timeout.is_error:
            return Error(r_ssh_timeout.unwrap_error())

        pool_data = guest_request.pool_data.mine(self, BeakerPoolData)

        r_command = render_template(
            KNOB_RESERVATION_EXTENSION_COMMAND_TEMPLATE.value,
            EXTENSION_TIME=KNOB_RESERVATION_EXTENSION_TIME.value,
            POOL_DATA=pool_data,
            **template_environment(guest_request=guest_request),
        )

        if not is_successful(r_command):
            return Error(r_command.failure())

        r_output = run_remote(
            logger,
            guest_request,
            ['sh', '-c', r_command.unwrap()],
            key=r_master_key.unwrap(),
            ssh_timeout=r_ssh_timeout.unwrap(),
            ssh_options=self.ssh_options,
            poolname=self.poolname,
            commandname='bkr.extend',
            cause_extractor=bkr_error_cause_extractor,
        )

        if r_output.is_error:
            return Error(Failure.from_failure('failed to extend guest reservation', r_output.unwrap_error()))

        return Ok(WatchdogState.CONTINUE)

    def can_acquire(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        # First, check the parent class, maybe its tests already have the answer.
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        r_distros: Result[list[BeakerPoolImageInfo], Failure] = self._guest_request_to_image_or_none(
            logger, session, guest_request
        )
        if r_distros.is_error:
            return Error(r_distros.unwrap_error())

        distros = r_distros.unwrap()

        if not distros:
            return Ok(CanAcquire.cannot('compose not supported'))

        distros = [
            distro
            for distro in distros
            if distro.supports_kickstart or not guest_request.environment.has_ks_specification
        ]

        if not distros:
            return Ok(CanAcquire.cannot('compose does not support custom kickstart'))

        # Parent implementation does not care, but we still might: support for HW constraints is still
        # far from being complete and fully tested, therefore we should check whether we are able to
        # convert the constraints - if there are any - to a Beaker XML filter.

        if not guest_request.environment.has_hw_constraints:
            return Ok(CanAcquire())

        r_constraints = guest_request.environment.get_hw_constraints()

        if r_constraints.is_error:
            return Error(r_constraints.unwrap_error())

        constraints = r_constraints.unwrap()

        # since `has_hw_constraints` was positive, there should be constraints...
        assert constraints is not None

        # TODO: copy helpers from tmt for this kind of filtering
        supported_constraints: list[str] = [
            'boot.method',
            'beaker.pool',
            'compatible.distro',
            'cpu.processors',
            'cpu.cores',
            'cpu.family',
            'cpu.model',
            'cpu.model_name',
            'cpu.stepping',
            'cpu.flag',
            'cpu.vendor_name',
            'device.driver',
            'disk[].size',
            'disk[].model_name',
            # Special internal constraints
            'disk[].is_expansion',
            'disk[].min_size',
            'disk[].max_size',
            'disk.length',
            'disk.expanded_length',
            'arch',
            'memory',
            'hostname',
            'iommu.is_supported',
            'iommu.model_name',
            'tpm.version',
            'virtualization.is_supported',
            'virtualization.is_virtualized',
            'virtualization.hypervisor',
            'network[].type',
            # Special internal constraints
            'network[].is_expansion',
            'network[].min_size',
            'network[].max_size',
            'network.length',
            'network.expanded_length',
            'system.numa_nodes',
            'system.model_name',
            'zcrypt.adapter',
            'zcrypt.mode',
        ]

        for span in constraints.spans(logger):
            for constraint in span:
                if constraint.expand_name().spec_name not in supported_constraints:
                    return Ok(
                        CanAcquire.cannot(f'HW requirement {constraint.expand_name().spec_name} is not supported')
                    )

        r_filter = constraint_to_beaker_filter(constraints, guest_request, self)

        if r_filter.is_error:
            return Error(r_filter.unwrap_error())

        return Ok(CanAcquire())

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        r_create_job = self._create_job(logger, session, guest_request)

        if r_create_job.is_error:
            failure = r_create_job.unwrap_error()

            if (
                failure.command_output
                and bkr_error_cause_extractor(failure.command_output) == BkrErrorCauses.NO_DISTRO_MATCHES_RECIPE
            ):
                return self._handle_no_distro_matches_recipe_error(failure, guest_request)

            return Error(r_create_job.unwrap_error())

        job_id, is_bootc = r_create_job.unwrap()

        # The returned guest doesn't have address. The address will be added by executing `update_guest()`
        # after. The reason of this solution is slow beaker system provisioning. It can take hours and
        # we can't use a thread for so large amount of time.

        return Ok(
            ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=BeakerPoolData(job_id=job_id, is_bootc=is_bootc),
            )
        )

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, BeakerPoolData)

        if not pool_data:
            return Ok(None)

        return self.dispatch_resource_cleanup(
            logger, session, BeakerPoolResourcesIDs(job_id=pool_data.job_id), guest_request=guest_request
        )

    def fetch_pool_resources_metrics(
        self, logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        # Resource usage - instances and flavors
        def _fetch_instances(logger: gluetool.log.ContextAdapter) -> Result[list[str], Failure]:
            r_query_instances = self._run_bkr(logger, ['system-list', '--mine'], commandname='bkr.system-list')

            if r_query_instances.is_error:
                failure = r_query_instances.unwrap_error()
                command_output = cast(Optional[ProcessOutput], failure.details.get('command_output', None))

                if (
                    command_output
                    and command_output.stderr
                    and 'nothing matches' in command_output.stderr.strip().lower()
                ):
                    # This is a a valid result, meaning "0 machines". Setting our "raw output" to a corresponding value
                    # instead of adding some special flag. Empty list has 0 items, 0 machines...

                    return Ok([])

                return Error(Failure.from_failure('failed to fetch system list', r_query_instances.unwrap_error()))

            return Ok(r_query_instances.unwrap().stdout.splitlines())

        def _update_instance_usage(
            logger: gluetool.log.ContextAdapter, usage: PoolResourcesUsage, raw_instance: str, flavor: Optional[Flavor]
        ) -> Result[None, Failure]:
            assert usage.instances is not None  # narrow type

            usage.instances += 1

            # For the actual numbers of cores, memory and other metrics, we'd have to query each and every machine from
            # the list above. Is it worth it? At this moment it's not. But it can be done. Leaving them unspecified for
            # now.

            return Ok(None)

        r_instances_usage = self.do_fetch_pool_resources_metrics_flavor_usage(
            logger, resources.usage, _fetch_instances, None, _update_instance_usage
        )

        if r_instances_usage.is_error:
            return Error(r_instances_usage.unwrap_error())

        return Ok(resources)

    def _fetch_avoid_group_hostnames(self, logger: ContextAdapter, groupname: str) -> Result[list[str], Failure]:
        r_list = self._run_bkr(
            logger, ['system-list', '--pool', f'{groupname}'], commandname='bkr.system-list-owned-by-group'
        )

        if r_list.is_error:
            failure = r_list.unwrap_error()
            if failure.command_output:
                stderr = process_output_to_str(failure.command_output, stream='stderr')

                if stderr and stderr.strip() == 'Nothing Matches':
                    return Error(
                        Failure.from_failure(
                            'The Beaker pool does not exist or is empty',
                            r_list.unwrap_error().update(groupname=groupname),
                        )
                    )
            return Error(
                Failure.from_failure(
                    'failed to fetch systems owned by a group', r_list.unwrap_error().update(groupname=groupname)
                )
            )

        return Ok([hostname.strip() for hostname in r_list.unwrap().stdout.splitlines()])

    def refresh_avoid_groups_hostnames(self, logger: ContextAdapter) -> Result[None, Failure]:
        groups: list[AvoidGroupHostnames] = []

        r_avoid_groups = self.avoid_groups

        if r_avoid_groups.is_error:
            return Error(r_avoid_groups.unwrap_error())

        for groupname in r_avoid_groups.unwrap():
            r_list = self._fetch_avoid_group_hostnames(logger, groupname)

            if r_list.is_error:
                return Error(r_list.unwrap_error())

            groups.append(AvoidGroupHostnames(groupname=groupname, hostnames=r_list.unwrap()))

        r_refresh = refresh_cached_mapping(
            CACHE.get(), self.avoid_groups_hostnames_cache_key, {h.groupname: h for h in groups}
        )

        if r_refresh.is_error:
            return Error(r_refresh.unwrap_error())

        return Ok(None)

    def get_avoid_groups_hostnames(self) -> Result[dict[str, AvoidGroupHostnames], Failure]:
        return get_cached_mapping(CACHE.get(), self.avoid_groups_hostnames_cache_key, AvoidGroupHostnames)

    def _get_beaker_machine_log_url(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, beaker_logname: str
    ) -> Result[Optional[str], Failure]:
        """
        Extract location (URL) of Beaker machine log.

        :param logger: logger to use for logging.
        :param guest_request: a request whose logs to look for.
        :param beaker_logname: a name of the log as known to Beaker (e.g. ``console.log``).
        :returns: log URL, ``None`` when no such log was found, or a :py:class:`Failure` describing an error.
        """

        pool_data = guest_request.pool_data.mine(self, BeakerPoolData)

        if not pool_data.job_id:
            return Ok(None)

        r_job_results = self._get_job_results(logger, pool_data.job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        logs = r_job_results.unwrap().select(f'recipe > logs > log[name="{beaker_logname}"]')

        if not logs:
            return Ok(None)

        return Ok(logs[0]['href'])

    def _update_guest_log_url(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog, beaker_logname: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_url = self._get_beaker_machine_log_url(logger, guest_request, beaker_logname)

        if r_url.is_error:
            return Error(r_url.unwrap_error())

        url = r_url.unwrap()

        if url is None:
            return Ok(GuestLogUpdateProgress(state=GuestLogState.PENDING))

        return Ok(GuestLogUpdateProgress(state=GuestLogState.COMPLETE, url=url))

    def _update_guest_log_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog, beaker_logname: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_update = self._update_guest_log_url(logger, guest_request, guest_log, beaker_logname)

        if r_update.is_error:
            return r_update

        progress = r_update.unwrap()

        if progress.state != GuestLogState.COMPLETE:
            return r_update

        assert progress.url is not None

        try:
            response = requests.get(
                progress.url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()

        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to fetch Beaker log URL', exc, url=progress.url))

        return Ok(GuestLogUpdateProgress.from_unabridged(logger, guest_log, response.text))

    def _update_guest_installation_log_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog, beaker_logname: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        r_update = self._update_guest_log_blob(logger, guest_request, guest_log, beaker_logname)

        if r_update.is_error:
            return r_update

        pool_data = guest_request.pool_data.mine(self, BeakerPoolData)

        if not pool_data.job_id:
            return r_update

        r_job_results = self._get_job_results(logger, pool_data.job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        r_job_status = self._parse_job_status(logger, r_job_results.unwrap())

        if r_job_status.is_error:
            return Error(r_job_status.unwrap_error())

        _, job_status, _ = r_job_status.unwrap()

        # If the job state is `running`, the installation succeeded and no updates to installation logs can be
        # expected anymore.
        if job_status == 'running':
            update = r_update.unwrap()
            update.state = GuestLogState.COMPLETE
            r_update = Ok(update)

        return r_update

    # Since Beaker provides named logs, unlike other drivers, there are updaters for various log names.
    # To satisfy the "standard" logging expectations, use some of those for common logs like console/url
    # while keeping their Beaker-native names available at the same time.
    @guest_log_updater('beaker', 'console:dump', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_console_dump_url(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_url(logger, guest_request, guest_log, 'console.log')

    @guest_log_updater('beaker', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_blob(logger, guest_request, guest_log, 'console.log')

    @guest_log_updater('beaker', 'sys.log:dump', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_sys_log_url(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_url(logger, guest_request, guest_log, 'sys.log')

    @guest_log_updater('beaker', 'anaconda.log:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_anaconda_log_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_installation_log_blob(logger, guest_request, guest_log, 'anaconda.log')

    @guest_log_updater('beaker', 'storage.log:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_storage_log_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_installation_log_blob(logger, guest_request, guest_log, 'storage.log')

    @guest_log_updater('beaker', 'program.log:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_program_log_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_installation_log_blob(logger, guest_request, guest_log, 'program.log')

    @guest_log_updater('beaker', 'packaging.log:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_packaging_log_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_installation_log_blob(logger, guest_request, guest_log, 'packaging.log')

    @guest_log_updater('beaker', 'ks.cfg:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_ks_cfg_dump_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_installation_log_blob(logger, guest_request, guest_log, 'ks.cfg')

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        assert guest_request.address is not None

        r_output = self._run_bkr(
            logger, ['system-power', '--action=reboot', guest_request.address], commandname='bkr.system-reboot'
        )

        if r_output.is_error:
            return Error(Failure.from_failure('failed to trigger instance reboot', r_output.unwrap_error()))

        return Ok(None)


PoolDriver._drivers_registry['beaker'] = BeakerDriver
