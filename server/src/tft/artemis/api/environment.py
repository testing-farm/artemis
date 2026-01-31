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
]

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
