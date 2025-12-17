# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import threading

from gluetool.result import Error, Ok, Result

from .. import __VERSION__, Failure, JSONSchemaType, get_logger, load_packaged_validation_schema

DEFAULT_GUEST_REQUEST_OWNER = 'artemis'

DEFAULT_SSH_PORT = 22
DEFAULT_SSH_USERNAME = 'root'

DEFAULT_EVENTS_PAGE = 1
DEFAULT_EVENTS_PAGE_SIZE = 20
DEFAULT_EVENTS_SORT_FIELD = 'updated'
DEFAULT_EVENTS_SORT_ORDER = 'desc'

# Will be filled with the actual schema during API server bootstrap.
ENVIRONMENT_SCHEMAS: dict[str, JSONSchemaType] = {}

#: API milestones: describes milestone API version and optionally also compatible
#: API versions. Based on this list, routers for proper endpoints will be added to the application with appropriate
#: redirects if specified.
API_MILESTONES: list[tuple[str, list[str]]] = [
    # NEW: beaker.panic-watchdog HW requirement
    # NEW: iommu HW requirements
    # NEW: system.model-name HW requirement
    # NEW: device HW requirements
    (
        'v0.0.83',
        [
            # For lazy clients who don't care about the version, our most current API version should add
            # `/current` redirected to itself.
            'current',
            # For clients that did not switch to versioned API yet, keep top-level endpoints.
            # TODO: this one's supposed to disappear once everyone switches to versioned API endpoints
            'toplevel',
        ],
    ),
    # NEW: guest reboot
    # NEW: cpu.stepping HW requirement
    ('v0.0.74', []),
    # NEW: beaker HW requirement
    ('v0.0.73', []),
    # NEW: allow passing security group rules for guest creation
    ('v0.0.72', []),
    # NEW: guest log API adds multiple blobs
    # NEW: dropped boot.method enum
    ('v0.0.70', []),
    # NEW: zcrypt HW requirement
    # NEW: disk.model-name HW requirement
    ('v0.0.69', []),
    # NEW: fixed virtualization.hypervisor enum
    ('v0.0.67', []),
    # NEW: fixed virtualization.hypervisor enum
    ('v0.0.58', []),
    # NEW: added user defined watchdog delays
    # NEW: guest shelf management
    # NEW: preprovisioning
    ('v0.0.56', []),
    # NEW: no change, fixes issues with validation
    ('v0.0.55', []),
    # NEW: added Kickstart specification
    ('v0.0.53', []),
    # NEW: added compatible HW constraint
    ('v0.0.48', []),
    # NEW: added missing cpu.processors constraint
    ('v0.0.47', []),
    # NEW: added new CPU constraints
    ('v0.0.46', []),
    # NEW: added hostname HW constraint
    ('v0.0.38', []),
    # NEW: virtualization HW constraint
    ('v0.0.37', []),
    # NEW: current worker tasks
    # NEW: boot.method HW constraint
    ('v0.0.32', []),
    # NEW: trigger pool info refresh
    # NEW: HW requirement changes - added `network`
    ('v0.0.28', []),
    # NEW: HW requirement changes - refactored `disk`
    ('v0.0.27', []),
    # NEW: allow log-types to be specified in guest request
    ('v0.0.26', []),
    # NEW: allow skipping verify-ssh steps
    ('v0.0.24', []),
    # NEW: user management
    ('v0.0.21', []),
    # NEW: guest logs
    ('v0.0.20', []),
    # NEW: environment.hw opens
    ('v0.0.19', []),
    # NEW: /guest/$GUESTNAME/console/url
    ('v0.0.18', []),
    ('v0.0.17', []),
]

CURRENT_MILESTONE_VERSION = API_MILESTONES[0][0]

#: Protects our metrics tree when updating & rendering to user.
METRICS_LOCK = threading.Lock()

# Type checking this call is hard, mypy complains about unexpected keyword arguments, and refactoring
# didn't help at all, just yielded another kind of errors.
OPENAPI_METADATA = {'title': 'Artemis API', 'description': 'Artemis provisioning system API.', 'version': __VERSION__}


def get_environment_schemas() -> Result[dict[str, JSONSchemaType], Failure]:
    global ENVIRONMENT_SCHEMAS
    if not ENVIRONMENT_SCHEMAS:
        logger = get_logger()
        environment_schemas = {}
        for milestone_version, compatible_versions in API_MILESTONES:
            # Preload environment schema.
            r_schema = load_packaged_validation_schema(f'environment-{milestone_version}.yml')
            if r_schema.is_error:
                return Error(r_schema.unwrap_error())

            environment_schemas[milestone_version] = r_schema.unwrap()
            # Create the base API endpoints of this version.
            logger.info(f'API: /{milestone_version}')

            for compatible_version in compatible_versions:
                # If this version is the "current" version, make its environment schema available under `current` key.
                if compatible_version == 'current':
                    environment_schemas['current'] = environment_schemas[milestone_version]

        ENVIRONMENT_SCHEMAS.update(environment_schemas)

    return Ok(ENVIRONMENT_SCHEMAS)


def get_redirects(version: str) -> list[str]:
    _, redirects = next(
        (
            (milestone_version, redirects)
            for milestone_version, redirects in API_MILESTONES
            if milestone_version == version
        ),
        (None, []),
    )
    return redirects
