# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import threading
from typing import Dict, List, Tuple

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
ENVIRONMENT_SCHEMAS: Dict[str, JSONSchemaType] = {}

#: API milestones: describes milestone API version and optionally also compatible
#: API versions. Based on this list, routers for proper endpoints will be added to the application with appropriate
#: redirects if specified.
API_MILESTONES: List[Tuple[str, List[str]]] = [
    # NEW: allow passing security group rules for guest creation
    ('v0.0.72', [
        # For lazy clients who don't care about the version, our most current API version should add
        # `/current` redirected to itself.
        'current',

        # For clients that did not switch to versioned API yet, keep top-level endpoints.
        # TODO: this one's supposed to disappear once everyone switches to versioned API endpoints
        'toplevel'
    ]),

    # NEW: guest log API adds multiple blobs
    # NEW: dropped boot.method enum
    ('v0.0.70', [])
]

CURRENT_MILESTONE_VERSION = API_MILESTONES[0][0]

#: Protects our metrics tree when updating & rendering to user.
METRICS_LOCK = threading.Lock()

# Type checking this call is hard, mypy complains about unexpected keyword arguments, and refactoring
# didn't help at all, just yielded another kind of errors.
OPENAPI_METADATA = {
    'title': 'Artemis API',
    'description': 'Artemis provisioning system API.',
    'version': __VERSION__
}


def get_environment_schemas() -> Result[Dict[str, JSONSchemaType], Failure]:
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


# NOTE(ivasilev) type ignore because of https://github.com/python/mypy/issues/11929
def get_redirects(version: str) -> List[str]:
    _, redirects = next(((milestone_version, redirects) for milestone_version, redirects in API_MILESTONES
                         if milestone_version == version), (None, []))
    return redirects  # type: ignore[return-value]
