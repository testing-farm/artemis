# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Naming of backend resources.

Every resource Artemis creates in a backend for a guest request - an instance, a security group, a resource group -
needs a name. A :py:class:`NamingStrategy` describes how the name of a particular kind of resource is rendered,
sanitized to satisfy the backend's rules, and matched against names of resources found in the backend.

Each driver defines its naming strategies, together with :py:class:`StringSanitizer` instances describing the rules
its backend imposes on names.
"""

import dataclasses
import enum
import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Optional, Protocol, TypeVar

from returns.result import Failure as _Error, Result as _Result, Success as _Ok

from .. import Failure, render_template
from ..knobs import KNOB_DEPLOYMENT, KNOB_DEPLOYMENT_ENVIRONMENT, Knob
from .sanitizers import NOOP_SANITIZER, StringSanitizer

if TYPE_CHECKING:
    from ..db import GuestRequest


KNOB_RESOURCE_NAME_TEMPLATE: Knob[str] = Knob(
    'artemis.mapping.resource-name.template',
    """
    A pattern for names of backend resources created for a guest request. Used for every resource type whose own
    name template knob is left empty.
    """,
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_RESOURCE_NAME_TEMPLATE',
    cast_from_str=str,
    default='artemis-{{ GUESTNAME }}',
)


class LookupMethod(enum.Enum):
    """
    How resources belonging to a guest request are recognized among resources reported by the backend.
    """

    #: The backend reports candidates, and only those with the expected name - optionally followed by a numeric
    #: postfix - belong to the guest request.
    NAME = 'name'

    #: The backend reports only resources belonging to the guest request, e.g. by filtering on a tag. Names are
    #: not checked.
    BACKEND = 'backend'


class NamedResource(Protocol):
    @property
    def name(self) -> str: ...


NamedResourceT = TypeVar('NamedResourceT', bound=NamedResource)


@dataclasses.dataclass(frozen=True)
class NamingStrategy:
    """
    Describes how names of a resource type are created and recognized.
    """

    #: Resource type, e.g. ``instance`` or ``security_group``. Available to name templates as ``RESOURCE_TYPE``.
    resource_type: str

    #: Knob providing the name template for this resource type. When it is not set, or its value is empty,
    #: :py:data:`KNOB_RESOURCE_NAME_TEMPLATE` is used instead.
    template_knob: Optional[Knob[str]] = None

    #: Backend rules for the name.
    sanitizer: StringSanitizer = NOOP_SANITIZER

    #: How resources belonging to a guest request are recognized.
    lookup: LookupMethod = LookupMethod.NAME

    #: If set, ``TAGS`` available to the template include the guest label tag. The label is derived from the
    #: instance name, therefore the instance naming strategy must leave this unset.
    tags_include_label: bool = True

    def get_template(self, poolname: str) -> _Result[str, Failure]:
        if self.template_knob is not None:
            r_template = self.template_knob.get_value(entityname=poolname)

            if r_template.is_error:
                return _Error(
                    Failure.from_failure(
                        'could not get resource name template',
                        r_template.unwrap_error(),
                        resource_type=self.resource_type,
                    )
                )

            template = r_template.unwrap()

            if template:
                return _Ok(template)

        r_template = KNOB_RESOURCE_NAME_TEMPLATE.get_value(entityname=poolname)

        if r_template.is_error:
            return _Error(
                Failure.from_failure(
                    'could not get resource name template', r_template.unwrap_error(), resource_type=self.resource_type
                )
            )

        return _Ok(r_template.unwrap())

    def render(
        self,
        template: str,
        poolname: str,
        guest_request: 'GuestRequest',
        *,
        tags: Optional[Mapping[str, str]] = None,
    ) -> _Result[str, Failure]:
        """
        Render and sanitize a resource name.

        :param template: name template, as provided by :py:meth:`get_template`.
        :param poolname: name of the pool the resource belongs to.
        :param guest_request: guest request the resource belongs to.
        :param tags: guest tags, available to the template as ``TAGS``.
        """

        return (
            render_template(
                template,
                GUESTNAME=guest_request.guestname,
                ENVIRONMENT=guest_request.environment,
                DEPLOYMENT=KNOB_DEPLOYMENT.value,
                DEPLOYMENT_ENVIRONMENT=KNOB_DEPLOYMENT_ENVIRONMENT.value,
                POOLNAME=poolname,
                RESOURCE_TYPE=self.resource_type,
                TAGS=tags or {},
            )
            .map(self.sanitizer)
            .alt(
                lambda failure: Failure.from_failure(
                    'could not render resource name template', failure, resource_type=self.resource_type
                )
            )
        )

    def with_postfix(self, name: str, postfix: int) -> str:
        """
        Create an alternative name, when the expected one is already taken.

        The postfix is appended to the name. When the result would be too long, the name is shortened to make room
        for the postfix. Names that need no postfix therefore use the whole length limit.
        """

        suffix = f'-{postfix}'

        if self.sanitizer.max_length is not None:
            name = name[: self.sanitizer.max_length - len(suffix)]

        return f'{name}{suffix}'

    def matches(self, expected_name: str, name: str) -> bool:
        """
        Check whether a name belongs to a resource named after the expected name.

        The name must be either equal to the expected name, or be one of its alternatives created by
        :py:meth:`with_postfix`.
        """

        if name == expected_name:
            return True

        match = re.fullmatch(r'.*-(\d+)', name)

        return match is not None and self.with_postfix(expected_name, int(match.group(1))) == name

    def select(self, expected_name: str, resources: list[NamedResourceT]) -> list[NamedResourceT]:
        """
        Pick resources belonging to a guest request from resources reported by the backend.
        """

        if self.lookup == LookupMethod.BACKEND:
            return resources

        return [resource for resource in resources if self.matches(expected_name, resource.name)]
