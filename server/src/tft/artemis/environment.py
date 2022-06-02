# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Guest environment specification and handling.

Each guest request carries an environment specification, and Artemis will provision a VM satisfying the given request.
This specification includes both software requirements - compose - and hardware requirements - architecture, memory
size, etc.
"""

import dataclasses
import enum
import itertools
import operator
import re
from typing import Any, Callable, ClassVar, Dict, Iterable, Iterator, List, NamedTuple, Optional, Sequence, Type, \
    TypeVar, Union, cast

import gluetool.log
import gluetool.utils
import pint
from gluetool.result import Error, Ok, Result
from pint import Quantity
from typing_extensions import Literal

from . import Failure, SerializableContainer

#: Unit registry, used and shared by all code.
UNITS = pint.UnitRegistry()

#
# Parsing of HW requirements of the environment
#
# From the given specification - which is represented as Python mappings and lists, following the TMT specification
# outlined at https://tmt.readthedocs.io/en/latest/spec/plans.html#hardware - we create a tree of `Constraint`
# instances. The `Constraint` classes have some usefull methods that allow us then evaluate flavors, whether they do
# or do not match the required HW.
#
# In the Python data structures, constraints are stored in mappings where keys are names of constraints, and values
# bundle together operator, value and optional unit. Our parsing expands the mapping value into the distinct fields we
# then track.

#: Special type variable, used in `Constraint.from_specification` - we bound this return value to always be a subclass
#: of `Constraint` class, instead of just any class in general.
T = TypeVar('T', bound='Constraint')

S = TypeVar('S')

#: Regular expression to match and split the value part of the key:value mapping. This value bundles together the
#: operator, the actual value of the constraint, and units.
VALUE_PATTERN = re.compile(r'^(?P<operator>==|!=|=~|=|>=|>|<=|<|contains)?\s*(?P<value>.+?)\s*$')

PROPERTY_PATTERN = re.compile(r'(?P<property_name>[a-z_]+)(?:\[(?P<index>[+-]?\d+)\])?')
PROPERTY_EXPAND_PATTERN = re.compile(
    r'(?P<property_name>[a-z_+]+)(?:\[(?P<index>[+-]?\d+)\])?(?:\.(?P<child_property_name>[a-z_]+))?'
)

#: Type of the operator callable. The operators accept two arguments, and returns result of their comparison.
OperatorHandlerType = Callable[[Any, Any], bool]

#: mypy does not support cyclic definition, it would be much easier to just define this:
#:
#:   SpecType = Dict[str, Union[int, float, str, 'SpecType', List['SpecType']]]
#:
#: Instead of resorting to ``Any``, we'll keep the type tracked by giving it its own name.
#:
#: See https://github.com/python/mypy/issues/731 for details.
SpecType = Any

ConstraintValueType = Union[int, Quantity, str, bool]
# Almost like the ConstraintValueType, but this one can be measured and may have units.
MeasurableConstraintValueType = Union[int, Quantity]


# A type variable representing types based on our common container of flavor properties.
U = TypeVar('U', bound='_FlavorSubsystemContainer')

# A type variable representing types based on our container of item sequences.
# TODO: now this one is actually bounded to a generic type, and mypy/typing do not support TypeVar bound to
# a generic type. See https://github.com/python/typing/issues/548. We'd need to declare item type of items
# inside _FlavorSequenceContainer, e.g. with the following code:
#
# V = TypeVar('V', bound='_FlavorSequenceContainer[U]')
V = TypeVar('V', bound='_FlavorSequenceContainer')  # type: ignore[type-arg]  # Missing type parameters for generic type
W = TypeVar('W', bound='FlavorDisk')


class ConstraintNameComponents(NamedTuple):
    """
    Components of a constraint name.
    """

    property: str
    property_index: Optional[int]
    child_property: Optional[str]


class _FlavorSubsystemContainer(SerializableContainer):
    """
    A base class for all containers used in flavor description.

    The class is based on serializable container class, to enable serialization of containers from the beginning.
    Some child classes may need to provide their own implementation, but by default, the base functionality is
    perfectly fine.
    """

    # Nice trick: when a member is of `ClassVar` type, it is not treated as a dataclass field but rather a class
    # variable. See https://docs.python.org/3.7/library/dataclasses.html#class-variables. And we want this member
    # to be a class variables, child classes wouldn't need custom `__init__()` to set it.

    #: A prefix to add before all field names when formatting fields. If unset, no prefix is added.
    CONTAINER_PREFIX: ClassVar[Optional[str]] = None

    #: A list of properties that exist but are not backed by any attribute or value.
    VIRTUAL_PROPERTIES: List[str] = []

    # Similar to dataclasses.replace(), but that one isn't recursive, and we have to clone some complex fields.
    def clone(self: U) -> U:
        clone = dataclasses.replace(self)

        for field_spec in dataclasses.fields(self):
            field = getattr(self, field_spec.name)

            if isinstance(field, _FlavorSubsystemContainer):
                setattr(clone, field_spec.name, field.clone())

        return clone


class _FlavorSequenceContainer(_FlavorSubsystemContainer, Sequence[U]):
    """
    A base class for all containers used in flavor description that represent a sequence of items.

    The class merges together a flavor subsystem container base class, to include common functionality like
    serialization and formatting, and a generic sequence where the actual class is supplied by child clases.
    Items are expected to be based on our flavor subsystem container base class, therefore the generic item
    type is bound to this class.

    .. note::

       This container is supposed to be immutable. Methods allowing changes are not implemented. But, items
       are still mutable, as long as their classes are not frozen
       (https://docs.python.org/3.7/library/dataclasses.html#frozen-instances).
    """

    #: A class of one of the items.
    ITEM_CLASS: Type[U]

    #: A label to use when rendering item fields.
    ITEM_LABEL: str

    def __init__(self, items: Optional[List[U]] = None) -> None:
        """
        Create a container with a given items.

        :param items: initial set of items.
        """

        self.items: List[U] = items or []

    def __getitem__(self, index: int) -> U:  # type: ignore[override]  # does not match the superclass but that's fine
        """
        Return item on the requested position.

        :param index: index in the container.
        :returns: item.
        """

        return self.items[index]

    def __len__(self) -> int:
        """
        Return number of items tracked in this container.

        :returns: number of items.
        """

        return len(self.items)

    def clone(self: V) -> V:
        return self.__class__([
            item.clone() for item in self.items
        ])

    def serialize(self) -> List[Dict[str, Any]]:  # type: ignore[override]  # expected
        """
        Return Python built-in types representing the content of this container.

        :returns: serialized form of container items.
        """

        return [
            item.serialize() for item in self.items
        ]

    @classmethod
    def unserialize(cls: Type[V], serialized: List[Dict[str, Any]]) -> V:  # type: ignore[override]
        """
        Create container instance representing the content described with Python built-in types.

        :param serialized: serialized form of container items.
        :returns: unserialized container.
        """

        return cls([
            cls.ITEM_CLASS.unserialize(serialized_item)
            for serialized_item in serialized
        ])


#
# A flavor represents a type of guest a driver is able to deliver. It groups together various HW properties, and
# the mapping of these flavors to actual objects the driver can provision is in the driver's scope.
#
# Note: some cloud services do use the term "flavor", to describe the very same concept. We hijack it for our use,
# because we use the same concept, and other terms - e.g. "instance type" - are not as good looking.
#
# Flavor implementation closely follow the TMT specification for HW requirements. Until we find a solid reason,
# this arrangement allows trivial matching between requirements and available flavors.
#
# See https://tmt.readthedocs.io/en/stable/spec/plans.html#hardware for the specification.
#
# A flavor container example:
#
#  name: t2.small-with-big-disk
#  id: t2.small
#  arch: x86_64
#  memory: 4 GiB
#
#  boot:
#      method: bios
#
#  cpu:
#      processors: 1
#      cores: 2
#      family: 6
#      family_name: Haswell
#      model: E
#      model_name: i5-8400
#
#  disk:
#      - size: 40 GiB
#      - size: 120 GiB
#
# network:
#      - type: eth
#      - type: eth


FlavorBootMethodType = Union[Literal['bios'], Literal['uefi']]


@dataclasses.dataclass(repr=False)
class FlavorBoot(_FlavorSubsystemContainer):
    """
    Represents HW properties related to flavor boot process.
    """

    CONTAINER_PREFIX = 'boot'

    # TODO: trying an enum here - see virtualization.type for a enum-like field not implemented with enum, but rather
    # with the use of Literal type. Let's see which one would serve us better.
    #: Supported boot methods.
    #:
    #: .. note::
    #:
    #:    Plural is correct here, internally we hold the list of supported boot methods, because some flavors (and
    #:    images) can support more than one.
    method: List[FlavorBootMethodType] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(repr=False)
class FlavorCpu(_FlavorSubsystemContainer):
    """
    Represents HW properties related to CPU and CPU cores of a flavor.

    .. note::

       The relation between CPU and CPU cores is now intentionally ignored. We pretend the topology is trivial,
       all processors are the same, all processors have the same number of cores.
    """

    CONTAINER_PREFIX = 'cpu'

    #: Total number of CPUs.
    processors: Optional[int] = None

    #: Total number of CPU cores. To get number of cores per CPU, divide :py:attr:`processors` by this field.
    cores: Optional[int] = None

    #: CPU family number.
    family: Optional[int] = None

    #: CPU family name.
    family_name: Optional[str] = None

    #: CPU model number.
    model: Optional[int] = None

    #: CPU model name.
    model_name: Optional[str] = None


@dataclasses.dataclass(repr=False)
class FlavorDisk(_FlavorSubsystemContainer):
    """
    Represents a HW properties related to persistent storage a flavor, one disk in particular.

    .. note::

       We stay clear from any rigid definition of "disk", because we deal with different environments.
       Let's say, at this moment, a disk is a block storage device under `/dev` and it can hold raw data
       as well as file systems.

    .. note::

       As of now, only the very basic topology is supported, tracking only the total "disk" size. More complex
       setups will be supported in the future.
    """

    CONTAINER_PREFIX = 'disk'

    #: Total size of the disk storage, in bytes.
    size: Optional[Quantity] = None

    # TODO: move to properties of whole Disks container, or use class inheritance - we can't now because `FlavorDisks`
    # can load just one type of items.
    is_expansion: bool = False

    # `items`, ot `disks` - we want to generalize this, keep using generic naming.
    max_additional_items: int = 0
    min_size: Optional[Quantity] = None
    max_size: Optional[Quantity] = None

    def serialize(self) -> Dict[str, Any]:
        """
        Return Python built-in types representing the content of this container.

        :returns: serialized form of flavor properties.
        """

        serialized = super().serialize()

        if self.size is not None:
            serialized['size'] = str(self.size)

        if self.min_size is not None:
            serialized['min_size'] = str(self.min_size)

        if self.max_size is not None:
            serialized['max_size'] = str(self.max_size)

        return serialized

    @classmethod
    def unserialize(cls: Type[W], serialized: Dict[str, Any]) -> W:
        """
        Create container instance representing the content described with Python built-in types.

        :param serialized: serialized form of flavor properties.
        :returns: disk properties of a flavor.
        """

        disk = super().unserialize(serialized)

        if disk.size is not None:
            disk.size = UNITS(disk.size)

        if disk.min_size is not None:
            disk.min_size = UNITS(disk.min_size)

        if disk.max_size is not None:
            disk.max_size = UNITS(disk.max_size)

        return disk


# Note: the HW requirement is called `disk`, and holds a list of mappings. We have a `FlavorDisk` to track
# each of those mappings, but we need a class for their container, with methods for (un)serialization. Therefore
# the container class is called `FlavorDisks`, but in the flavor dataclass it's a type of `disk` property because
# that's how the HW requirement is called.
class FlavorDisks(_FlavorSequenceContainer[FlavorDisk]):
    """
    Represents a HW properties related to persistent storage a flavor.

    .. note::

       As of now, only the very basic topology is supported, tracking only the total "disk" size. More complex
       setups will be supported in the future.
    """

    ITEM_CLASS = FlavorDisk
    ITEM_LABEL = 'disk'

    # Special attributes - we cannot call `len()` in conditions constraits generate, and sequences don't have
    # any attribute we could inspect. And we also need to take expanion into account. Hence adding our own.
    #
    # TODO: and we want to move this into base class!
    @property
    def length(self) -> int:
        """
        Return "real" length of this container.

        :returns: number of stored items.
        """

        return len(self.items)

    @property
    def expanded_length(self) -> int:
        """
        Return "expanded" length of this container.

        It is computed as the number of static items plus the amount of additional items allowed by expansion.

        :returns: number of allowed items.
        """

        if not self.items:
            return 0

        expansion = self.items[-1]

        if expansion.is_expansion is False:
            return len(self.items)

        # Dropping 1 item from `len()` result, to compensate for the fact expansion item should not be counter
        # among the "real" items, it is instead replaced by N additional items.
        return len(self.items) - 1 + expansion.max_additional_items


@dataclasses.dataclass(repr=False)
class FlavorNetwork(_FlavorSubsystemContainer):
    """
    Represents a HW properties related to a network interface of a flavor, one interface in particular.

    .. note::

       As of now, only the very basic topology is supported, tracking only the type of the device. More complex
       setups will be supported in the future.
    """

    CONTAINER_PREFIX = 'network'

    # TODO: do we want an enum here?
    #: Type of the device.
    type: Optional[str] = None


# Note: the HW requirement is called `network`, and holds a list of mappings. We have a `FlavorNetwork` to track
# each of those mappings, but we need a class for their container, with methods for (un)serialization. Therefore
# the container class is called `FlavorNetworks`, but in the flavor dataclass it's a type of `network` property because
# that's how the HW requirement is called.
class FlavorNetworks(_FlavorSequenceContainer[FlavorNetwork]):
    """
    Represents a HW properties related to network interfaces of a flavor.

    .. note::

       As of now, only the very basic topology is supported, tracking only the type of the device. More complex
       setups will be supported in the future.
    """

    ITEM_CLASS = FlavorNetwork
    ITEM_LABEL = 'network'


@dataclasses.dataclass(repr=False)
class FlavorVirtualization(_FlavorSubsystemContainer):
    """
    Represents HW properties related to virtualization properties of a flavor.
    """

    CONTAINER_PREFIX = 'virtualization'

    #: If set, the flavor allows running VMs in a nested manner.
    is_supported: Optional[bool] = None

    #: If set, the flavors itself represents a virtual machine rather than a baremetal machine.
    is_virtualized: Optional[bool] = None

    #: When flavors represents a virtual machine, this field carries a hypervisor name.
    hypervisor: Optional[str] = None


@dataclasses.dataclass(repr=False)
class Flavor(_FlavorSubsystemContainer):
    """
    Represents various properties of a flavor.
    """

    VIRTUAL_PROPERTIES = ['hostname']

    #: Human-readable name of the flavor.
    name: str

    #: ID of the flavor as known to flavor's driver.
    id: str

    #: HW architecture of the flavor.
    arch: Optional[str] = None

    #: Boot properties.
    boot: FlavorBoot = dataclasses.field(default_factory=FlavorBoot)

    #: CPU properties.
    cpu: FlavorCpu = dataclasses.field(default_factory=FlavorCpu)

    #: Disk/storage properties.
    disk: FlavorDisks = dataclasses.field(default_factory=FlavorDisks)

    #: RAM size, in bytes.
    memory: Optional[Quantity] = None

    #: Network interfaces.
    network: FlavorNetworks = dataclasses.field(default_factory=FlavorNetworks)

    #: Virtualization properties.
    virtualization: FlavorVirtualization = dataclasses.field(default_factory=FlavorVirtualization)

    def serialize(self) -> Dict[str, Any]:
        """
        Return Python built-in types representing the content of this container.

        :returns: serialized form of flavor properties.
        """

        serialized = super().serialize()

        if self.memory is not None:
            serialized['memory'] = str(self.memory)

        return serialized

    def serialize_scrubbed(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON while scrubbing sensitive information.

        :returns: serialized form of flavor properties.
        """

        serialized = self.serialize()

        del serialized['id']

        return serialized

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'Flavor':
        """
        Create container instance representing the content described with Python built-in types.

        :param serialized: serialized form of flavor properties.
        :returns: flavor instance.
        """

        flavor = super().unserialize(serialized)

        if flavor.memory is not None:
            flavor.memory = UNITS(flavor.memory)

        return flavor


class Operator(enum.Enum):
    """
    Binary operators available for comparison of constraints and flavor properties.
    """

    EQ = '=='
    NEQ = '!='
    GT = '>'
    GTE = '>='
    LT = '<'
    LTE = '<='
    MATCH = '=~'
    CONTAINS = 'contains'
    NOTCONTAINS = 'not contains'


def match(text: str, pattern: str) -> bool:
    """
    Match a text against a given regular expression.

    :param text: string to examine.
    :param pattern: regular expression.
    :returns: ``True`` if pattern matches the string.
    """

    return re.match(pattern, text) is not None


def notcontains(haystack: List[str], needle: str) -> bool:
    """
    Find out whether an item is in the given list.

    .. note::

       Opposite of :py:func:`operator.contains`.

    :param haystack: container to examine.
    :param needle: item to look for in ``haystack``.
    :returns: ``True`` if ``needle`` is in ``haystack``.
    """

    return needle not in haystack


OPERATOR_SIGN_TO_OPERATOR = {
    '=': Operator.EQ,
    '==': Operator.EQ,
    '!=': Operator.NEQ,
    '>': Operator.GT,
    '>=': Operator.GTE,
    '<': Operator.LT,
    '<=': Operator.LTE,
    '=~': Operator.MATCH,
    'contains': Operator.CONTAINS,
    'not contains': Operator.NOTCONTAINS
}


OPERATOR_TO_HANDLER: Dict[Operator, OperatorHandlerType] = {
    Operator.EQ: operator.eq,
    Operator.NEQ: operator.ne,
    Operator.GT: operator.gt,
    Operator.GTE: operator.ge,
    Operator.LT: operator.lt,
    Operator.LTE: operator.le,
    Operator.MATCH: match,
    Operator.CONTAINS: operator.contains,
    Operator.NOTCONTAINS: notcontains
}


# NOTE: this is an exception in the way Artemis handles errors and their propagation. Since constraint parsing
# involves great deal of recursion and sequences, propagating errors in the form of `Result` instances would
# introduce a large amount of spaghetti code. The exception is used to interupt this possibly deep chain of calls,
# without the burden of huge boilerplate of code. It is intercepted on the border between the constraint parser
# and the rest of the code, and converted to proper `Failure`.
class ParseError(Exception):
    """
    Raised when HW constraint parsing fails.
    """

    def __init__(self, constraint_name: str, raw_value: str, message: Optional[str] = None) -> None:
        """
        Raise when HW constraint parsing fails.

        :param constraint_name: name of the constraint that caused issues.
        :param raw_value: original raw value.
        :param message: optional error message.
        """

        super().__init__(message or 'failed to parse a constraint')

        self.constraint_name = constraint_name
        self.raw_value = raw_value


class ConstraintBase(SerializableContainer):
    """
    Base class for all classes representing one or more constraints.
    """

    def uses_constraint(self, logger: gluetool.log.ContextAdapter, constraint_name: str) -> Result[bool, Failure]:
        """
        Inspect constraint whether it or its children use a constraint of a given name.

        :param logger: logger to use for logging.
        :param constraint_name: constraint name to look for.
        :raises NotImplementedError: method is left for child classes to implement.
        """

        raise NotImplementedError()

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> Result[bool, Failure]:
        """
        Inspect the given flavor, and decide whether it fits the limits imposed by this constraint.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: ``True`` if the given flavor satisfies the constraint.
        """

        return Ok(False)

    def prune_on_flavor(
        self,
        logger: gluetool.log.ContextAdapter,
        flavor: Flavor
    ) -> Result[Optional['ConstraintBase'], Failure]:
        """
        Decide whether to keep this constraint or not, given the flavor.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: constraint when the constraint evaluates to ``True``, ``None`` otherwise.
        """

        r = self.eval_flavor(logger, flavor)

        if r.is_error:
            return Error(r.unwrap_error())

        return Ok(self if r.unwrap() else None)

    def spans(
        self,
        logger: gluetool.log.ContextAdapter,
        members: Optional[List['ConstraintBase']] = None
    ) -> Iterator[List['ConstraintBase']]:
        """
        Generate all distinct spans covered by this constraint.

        For a trivial constraint, there is only one span, and that's the constraint itself. In the case of compound
        constraints, the set of spans would be bigger, depending on the constraint's ``reducer``.

        :param logger: logger to use for logging.
        :param members: if specified, each span generated by this method is prepended with this list.
        :yields: iterator over all spans.
        """

        yield (members or []) + [self]


ReducerType = Callable[[Iterable[Result[bool, Failure]]], Result[bool, Failure]]


def _reduce_any(values: Iterable[Result[bool, Failure]]) -> Result[bool, Failure]:
    for value in values:
        if value.is_error:
            return value

        if value.unwrap() is True:
            return Ok(True)

    return Ok(False)


def _reduce_all(values: Iterable[Result[bool, Failure]]) -> Result[bool, Failure]:
    for value in values:
        if value.is_error:
            return value

        if value.unwrap() is not True:
            return Ok(False)

    return Ok(True)


class CompoundConstraint(ConstraintBase):
    """
    Base class for all *compound* constraints, constraints imposed to more than one dimension.
    """

    def __init__(
        self,
        reducer: ReducerType = _reduce_any,
        constraints: Optional[List[ConstraintBase]] = None
    ) -> None:
        """
        Construct a compound constraint, constraint imposed to more than one dimension.

        :param reducer: a callable reducing a list of results from child constraints into the final answer.
        :param constraints: child contraints.
        """

        self.reducer = reducer
        self.constraints = constraints or []

    def serialize(self) -> Dict[str, Any]:
        """
        Return Python built-in types representing the content of this container.

        Works in a recursive manner, every container member that's a subclass of :py:class:`SerializableContainer`
        is processed as well.

        See :py:meth:`unserialize` for the reversal operation.

        :returns: serialized form of this constraint.
        """

        return {
            self.__class__.__name__.lower(): [
                constraint.serialize() for constraint in self.constraints
            ]
        }

    @classmethod
    def unserialize(cls: Type[S], serialized: Dict[str, Any]) -> S:
        """
        Create container instance representing the content described with Python built-in types.

        Every container member whose type is a subclass of :py:class:`SerializableContainer` is restored as well.

        See :py:meth:`serialize` for the reversal operation.

        :param serialized: serialized form of the container.
        :raises NotImplementedError: this method is left intentionally not implemented.
        """

        raise NotImplementedError()

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> Result[bool, Failure]:
        """
        Compare given flavor against the constraint.

        The constraint will evaluate its subconstraints, and merge their results into one final answer.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: ``True`` if the given flavor satisfies the constraint.
        """

        return self.reducer(
            constraint.eval_flavor(logger, flavor)
            for constraint in self.constraints
        )

    def uses_constraint(self, logger: gluetool.log.ContextAdapter, constraint_name: str) -> Result[bool, Failure]:
        """
        Inspect constraint whether it or its children use a constraint of a given name.

        :param logger: logger to use for logging.
        :param constraint_name: constraint name to look for.
        :returns: ``True`` if the given constraint or its children use given constraint name.
        """

        # Using "any" on purpose: we cannot use the reducer belonging to this constraint,
        # because that one may yield result based on validity of all child constraints.
        # But we want to answer the question "is *any* of child constraints using the given
        # constraint?", not "are all using it?".
        return _reduce_any(
            constraint.uses_constraint(logger, constraint_name)
            for constraint in self.constraints
        )

    def prune_on_flavor(
        self,
        logger: gluetool.log.ContextAdapter,
        flavor: Flavor
    ) -> Result[Optional[ConstraintBase], Failure]:
        """
        Decide whether to keep this constraint or not, given the flavor.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: constraint when the constraint evaluates to ``True``, ``None`` otherwise.
        """

        r = self.eval_flavor(logger, flavor)

        if r.is_error:
            return Error(r.unwrap_error())

        if r.unwrap() is not True:
            return Ok(None)

        pruned_constraints: List[ConstraintBase] = []

        for constraint in self.constraints:
            r_pruned = constraint.prune_on_flavor(logger, flavor)

            if r_pruned.is_error:
                return r_pruned

            pruned_constraint = r_pruned.unwrap()

            if pruned_constraint is None:
                continue

            pruned_constraints.append(pruned_constraint)

        return Ok(self.__class__(constraints=pruned_constraints))

    def spans(
        self,
        logger: gluetool.log.ContextAdapter,
        members: Optional[List[ConstraintBase]] = None
    ) -> Iterator[List[ConstraintBase]]:
        """
        Generate all distinct spans covered by this constraint.

        Since the ``and`` reducer demands all child constraints must be satisfied, and some of these constraints
        can also be compound constraints, we need to construct a cartesian product of spans yielded by child
        constraints to include all possible combinations.

        :param logger: logger to use for logging.
        :param members: if specified, each span generated by this method is prepended with this list.
        :raises NotImplementedError: default implementation is left undefined for compound constraints.
        """

        raise NotImplementedError()


@dataclasses.dataclass(repr=False)
class Constraint(ConstraintBase):
    """
    A constraint imposing a particular limit to one of the system properties.
    """

    #: Name of the constraint. Used for logging purposes, usually matches the name of the system property.
    name: str

    #: A binary operation to use for comparing the constraint value and the value specified by system or flavor.
    operator: Operator

    # A callable comparing the flavor value and the constraint value.
    operator_handler: OperatorHandlerType

    #: Constraint value.
    value: ConstraintValueType

    # Stored for possible inspection by more advanced processing.
    raw_value: str

    #: If set, it is a raw unit specified by the constraint.
    unit: Optional[str] = None

    #: If set, it is a "bigger" constraint, to which this constraint logically belongs as one of its aspects.
    original_constraint: Optional['Constraint'] = None

    @classmethod
    def from_specification(
        cls: Type[T],
        name: str,
        raw_value: str,
        as_quantity: bool = True,
        as_cast: Optional[Callable[[str], ConstraintValueType]] = None,
        original_constraint: Optional['Constraint'] = None
    ) -> T:
        """
        Parse raw constraint specification into our internal representation.

        :param name: name of the constraint.
        :param raw_value: raw value of the constraint.
        :param as_quantity: if set, value is treated as a quantity containing also unit, and as such the raw value is
            converted to :py:class`pint.Quantity` instance.
        :param as_cast: if specified, this callable is used to convert raw value to its final type.
        :param original_constraint: when specified, new constraint logically belongs to ``original_constraint``,
            possibly representing one of its aspects.
        :raises ParseError: when parsing fails.
        :returns: a :py:class:`Constraint` representing the given specification.
        """

        parsed_value = VALUE_PATTERN.match(raw_value)

        if not parsed_value:
            raise ParseError(constraint_name=name, raw_value=raw_value)

        groups = parsed_value.groupdict()

        if groups['operator']:
            operator = OPERATOR_SIGN_TO_OPERATOR[groups['operator']]

        else:
            operator = Operator.EQ

        raw_value = groups['value']

        if as_quantity:
            value = UNITS(raw_value)

        elif as_cast is not None:
            value = as_cast(raw_value)

        else:
            value = raw_value

        return cls(
            name=name,
            operator=operator,
            operator_handler=OPERATOR_TO_HANDLER[operator],
            value=value,
            raw_value=raw_value,
            original_constraint=original_constraint
        )

    @classmethod
    def from_arch(cls: Type[T], value: str) -> T:
        """
        Create a constraint for ``arch`` HW requirement.

        ``arch`` field holds special position: it is a HW constraint, but it's not optional, and cannot be used under
        ``and`` or ``or`` blocks. For HW constraint processing, it makes sense to create an internal constraint out
        of ``arch``, to join it with the rest of the constraints by one virtual ``and`` on top level.

        :param value: value of ``arch`` field of an environment.
        :returns: constraint instance.
        """

        return cls(
            name='arch',
            operator=Operator.EQ,
            operator_handler=OPERATOR_TO_HANDLER[Operator.EQ],
            value=value,
            raw_value=value
        )

    def serialize(self) -> str:  # type: ignore[override]
        """
        Return Python built-in types representing the content of this container.

        Works in a recursive manner, every container member that's a subclass of :py:class:`SerializableContainer`
        is processed as well.

        See :py:meth:`unserialize` for the reversal operation.

        :returns: serialized form of this constraint.
        """

        return f'{self.name} {self.operator.value} {self.value}'

    @classmethod
    def unserialize(cls: Type[S], serialized: Dict[str, Any]) -> S:
        """
        Create container instance representing the content described with Python built-in types.

        Every container member whose type is a subclass of :py:class:`SerializableContainer` is restored as well.

        See :py:meth:`serialize` for the reversal operation.

        :param serialized: serialized form of the container.
        :raises NotImplementedError: this method is left intentionally not implemented.
        """

        raise NotImplementedError()

    def expand_name(self) -> ConstraintNameComponents:
        """
        Expand constraint name into its components.

        :returns: tuple consisting of constraint name components: name, optional indices, child properties, etc.
        """

        match = PROPERTY_EXPAND_PATTERN.match(self.name)

        # Cannot happen as long as we test our pattern well...
        assert match is not None

        groups = match.groupdict()

        return ConstraintNameComponents(
            property=groups['property_name'],
            property_index=int(groups['index']) if groups['index'] is not None else None,
            child_property=groups['child_property_name']
        )

    def change_operator(self, operator: Operator) -> None:
        """
        Change operator of this constraint to a given one.

        :param operator: new operator.
        """

        self.operator = operator
        self.operator_handler = OPERATOR_TO_HANDLER[operator]

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> Result[bool, Failure]:
        """
        Compare given flavor against the constraint.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: ``True`` if the given flavor satisfies the constraint.
        """

        flavor_property = cast(Any, flavor)
        property_path = self.name.split('.')

        while property_path:
            property_path_step = PROPERTY_PATTERN.match(property_path.pop(0))

            # It should never be None - if that happens, our code creates property names that don't match the pattern,
            # and those should be fixed. We don't match user input here.
            assert property_path_step is not None

            groups = property_path_step.groupdict()

            if groups['property_name'] in getattr(flavor_property, 'VIRTUAL_PROPERTIES', []):
                flavor_property = None
                break

            try:
                flavor_property = getattr(flavor_property, groups['property_name'])

            except AttributeError:
                return Error(Failure(
                    'unknown flavor property',
                    property=groups['property_name']
                ))

            if groups.get('index') is not None:
                flavor_property_index = int(groups['index'])

                if len(flavor_property) <= flavor_property_index:
                    # There is no such index available for us to match.
                    # TODO: this will have to be refactored to handle some *optional* constraints, like flavors
                    # that don't have a third large disk, but can gain one when driver supports such an addition.
                    flavor_property = None
                    break

                else:
                    flavor_property = flavor_property[flavor_property_index]

        if flavor_property is None:
            # Hard to compare `None` with a constraint. Flavor can't provide - or doesn't feel like providing - more
            # specific value. Unless told otherwise, we should mark the evaluation as failed, and keep looking for
            # better mach.
            result = False

        else:
            result = self.operator_handler(
                flavor_property,
                self.value
            )

        logger.debug(f'eval-flavor: {flavor.name}.{self.name}: {type(flavor_property).__name__}({flavor_property}) {self.operator.value} {type(self.value).__name__}({self.value}): {result}')  # noqa: E501

        return Ok(result)

    def uses_constraint(self, logger: gluetool.log.ContextAdapter, constraint_name: str) -> Result[bool, Failure]:
        """
        Inspect constraint whether it or its children use a constraint of a given name.

        :param logger: logger to use for logging.
        :param constraint_name: constraint name to look for.
        :returns: ``True`` if the given constraint or its children use given constraint name.
        """

        return Ok(self.expand_name().property == constraint_name)


@dataclasses.dataclass(repr=False)
class And(CompoundConstraint):
    """
    Represents constraints that are grouped in ``and`` fashion.
    """

    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        """
        Hold constraints that are grouped in ``and`` fashion.

        :param constraints: list of constraints to group.
        """

        super().__init__(_reduce_all, constraints=constraints)

    def spans(
        self,
        logger: gluetool.log.ContextAdapter,
        members: Optional[List[ConstraintBase]] = None
    ) -> Iterator[List[ConstraintBase]]:
        """
        Generate all distinct spans covered by this constraint.

        Since the ``and`` reducer demands all child constraints must be satisfied, and some of these constraints
        can also be compound constraints, we need to construct a cartesian product of spans yielded by child
        constraints to include all possible combinations.

        :param logger: logger to use for logging.
        :param members: if specified, each span generated by this method is prepended with this list.
        :yields: all possible spans.
        """

        members = members or []

        # List of non-compound constraints - we just slap these into every combination we generate
        simple_constraints = [
            constraint
            for constraint in self.constraints
            if not isinstance(constraint, CompoundConstraint)
        ]

        # Compound constraints - these we will ask to generate their spans, and we produce cartesian
        # product from the output.
        compound_constraints = [
            constraint
            for constraint in self.constraints
            if isinstance(constraint, CompoundConstraint)
        ]

        for compounds in itertools.product(*[constraint.spans(logger) for constraint in compound_constraints]):
            # Note that `product` returns an item for each iterable, and those items are lists, because
            # that's what `spans()` returns. Use `sum` to linearize the list of lists.
            yield members + sum(compounds, []) + simple_constraints


@dataclasses.dataclass(repr=False)
class Or(CompoundConstraint):
    """
    Represents constraints that are grouped in ``or`` fashion.
    """

    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        """
        Hold constraints that are grouped in ``or`` fashion.

        :param constraints: list of constraints to group.
        """

        super().__init__(_reduce_any, constraints=constraints)

    def spans(
        self,
        logger: gluetool.log.ContextAdapter,
        members: Optional[List[ConstraintBase]] = None
    ) -> Iterator[List[ConstraintBase]]:
        """
        Generate all distinct spans covered by this constraint.

        Since the ``any`` reducer allows any child constraints to be satisfied for the whole group to evaluate
        as ``True``, it is trivial to generate spans - each child constraint shall provide its own "branch",
        and there is no need for products or joins of any kind.

        :param logger: logger to use for logging.
        :param members: if specified, each span generated by this method is prepended with this list.
        :yields: all possible spans.
        """

        members = members or []

        for constraint in self.constraints:
            for span in constraint.spans(logger):
                yield members + span


def _parse_boot(spec: SpecType) -> ConstraintBase:
    """
    Parse a boot-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    if 'method' in spec:
        constraint = Constraint.from_specification('boot.method', spec["method"], as_quantity=False)

        if constraint.operator == Operator.EQ:
            constraint.change_operator(Operator.CONTAINS)

        elif constraint.operator == Operator.NEQ:
            constraint.change_operator(Operator.NOTCONTAINS)

        group.constraints += [constraint]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_virtualization(spec: SpecType) -> ConstraintBase:
    """
    Parse a virtualization-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    if 'is-virtualized' in spec:
        group.constraints += [
            Constraint.from_specification(
                'virtualization.is_virtualized',
                str(spec['is-virtualized']),
                as_quantity=False,
                as_cast=gluetool.utils.normalize_bool_option
            )
        ]

    if 'is-supported' in spec:
        group.constraints += [
            Constraint.from_specification(
                'virtualization.is_supported',
                str(spec['is-supported']),
                as_quantity=False,
                as_cast=gluetool.utils.normalize_bool_option
            )
        ]

    if 'hypervisor' in spec:
        group.constraints += [
            Constraint.from_specification(
                'virtualization.hypervisor',
                spec['hypervisor'],
                as_quantity=False
            )
        ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_cpu(spec: SpecType) -> ConstraintBase:
    """
    Parse a cpu-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    group.constraints += [
        Constraint.from_specification(f'cpu.{constraint_name}', str(spec[constraint_name]))
        for constraint_name in ('processors', 'cores', 'model', 'family')
        if constraint_name in spec
    ]

    group.constraints += [
        Constraint.from_specification(
            f'cpu.{constraint_name.replace("-", "_")}',
            str(spec[constraint_name]),
            as_quantity=False
        )
        for constraint_name in ('model-name',)
        if constraint_name in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_disk(spec: SpecType, disk_index: int) -> ConstraintBase:
    """
    Parse a disk-related constraints.

    :param spec: raw constraint block specification.
    :param disk_index: index of this disk among its peers in specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    # Constructing a tree of conditions:
    #
    # (size is enough) || (last disk is expansion && has enough spare disks && min/max size is enough)
    def _parse_size_spec(spec: SpecType) -> None:
        # Our "expansion" branch consists of several conditions that must be satisfied: we need to check
        # expansion is allowed first, then make sure the disk we're trying to match with the flavor fits
        # into what this expansion can handle, and then we can deal with min/max sizes supported by the
        # expansion.
        direct_group = And()
        expansion_group = And()

        if 'size' in spec:
            size = spec['size']

        # The old-style constraint when `space` existed. Remove once v0.0.26 is gone.
        else:
            size = spec['space']

        constraint_name = f'disk[{disk_index}].size'
        original_constraint = Constraint.from_specification(constraint_name, str(size))

        direct_group.constraints += [original_constraint]

        expansion_group.constraints += [
            Constraint.from_specification(
                'disk.length',
                '> 0',
                as_quantity=False,
                as_cast=int,
                original_constraint=original_constraint
            ),
            Constraint.from_specification(
                'disk[-1].is_expansion',
                'True',
                as_quantity=False,
                as_cast=bool,
                original_constraint=original_constraint
            ),
            Constraint.from_specification(
                'disk.expanded_length',
                f'> {disk_index}',
                as_quantity=False,
                as_cast=int,
                original_constraint=original_constraint
            )
        ]

        if original_constraint.operator in (Operator.EQ, Operator.GTE, Operator.LTE, Operator.GT, Operator.LT):
            expansion_group.constraints += [
                Constraint.from_specification(
                    'disk[-1].min_size',
                    f'<= {original_constraint.raw_value}',
                    original_constraint=original_constraint
                ),
                Constraint.from_specification(
                    'disk[-1].max_size',
                    f'>= {original_constraint.raw_value}',
                    original_constraint=original_constraint
                )
            ]

        else:
            raise ParseError(
                message='operator not supported',
                constraint_name=constraint_name,
                raw_value=str(size)
            )

        group.constraints += [
            Or([
                direct_group,
                expansion_group
            ])
        ]

    # group.constraints += [
    #     Constraint.from_specification(f'disk[{disk_index}].{constraint_name}', str(spec[constraint_name]))
    #     for constraint_name in ()
    #     if constraint_name in spec
    # ]

    if 'size' in spec or 'space' in spec:
        _parse_size_spec(spec)

    return group


def _parse_disks(spec: SpecType) -> ConstraintBase:
    """
    Parse a storage-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    # The old-style constraint when `disk` was a mapping. Remove once v0.0.26 is gone.
    if isinstance(spec, dict):
        return _parse_disk(spec, 0)

    group = And()

    group.constraints += [
        _parse_disk(disk_spec, disk_index)
        for disk_index, disk_spec in enumerate(spec)
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_network(spec: SpecType, network_index: int) -> ConstraintBase:
    """
    Parse a network-related constraints.

    :param spec: raw constraint block specification.
    :param network_index: index of this network among its peers in specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    group.constraints += [
        Constraint.from_specification(
            f'network[{network_index}].{constraint_name}',
            str(spec[constraint_name]),
            as_quantity=False
        )
        for constraint_name in ('type',)
        if constraint_name in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_networks(spec: SpecType) -> ConstraintBase:
    """
    Parse a network-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    group.constraints += [
        _parse_network(network_spec, network_index)
        for network_index, network_spec in enumerate(spec)
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_generic_spec(spec: SpecType) -> ConstraintBase:
    """
    Parse actual constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    if 'arch' in spec:
        group.constraints += [Constraint.from_specification('arch', spec['arch'], as_quantity=False)]

    if 'boot' in spec:
        group.constraints += [_parse_boot(spec['boot'])]

    if 'cpu' in spec:
        group.constraints += [_parse_cpu(spec['cpu'])]

    if 'memory' in spec:
        group.constraints += [Constraint.from_specification('memory', str(spec['memory']))]

    if 'disk' in spec:
        group.constraints += [_parse_disks(spec['disk'])]

    if 'network' in spec:
        group.constraints += [_parse_networks(spec['network'])]

    if 'hostname' in spec:
        group.constraints += [Constraint.from_specification('hostname', spec['hostname'], as_quantity=False)]

    if 'virtualization' in spec:
        group.constraints += [_parse_virtualization(spec['virtualization'])]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_and(spec: SpecType) -> ConstraintBase:
    """
    Parse an ``and`` clause holding one or more subblocks or constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    group.constraints += [
        _parse_block(member)
        for member in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_or(spec: SpecType) -> ConstraintBase:
    """
    Parse an ``or`` clause holding one or more subblocks or constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = Or()

    group.constraints += [
        _parse_block(member)
        for member in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_block(spec: SpecType) -> ConstraintBase:
    """
    Parse a generic block of HW constraints - may contain ``and`` and ``or`` subblocks and actual constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    if 'and' in spec:
        return _parse_and(spec['and'])

    elif 'or' in spec:
        return _parse_or(spec['or'])

    else:
        return _parse_generic_spec(spec)


def constraints_from_environment_requirements(spec: SpecType) -> Result[ConstraintBase, 'Failure']:
    """
    Convert raw specification of HW constraints to our internal representation.

    :param spec: raw constraints specification as stored in an environment.
    :returns: root of HW constraints tree.
    """

    from . import safe_call

    r_constraints = safe_call(_parse_block, spec)

    if r_constraints.is_error:
        r_constraints.unwrap_error().update(constraints_spec=spec)

    return r_constraints


@dataclasses.dataclass(repr=False)
class HWRequirements(SerializableContainer):
    """
    Represents HQ requirements of the environment.
    """

    #: Requested architecture.
    arch: str

    #: Additional HW constraints.
    constraints: Optional[SpecType] = None


@dataclasses.dataclass(repr=False)
class OsRequirements(SerializableContainer):
    """
    Represents OS requirements of the environment.
    """

    #: Compose ID/name.
    compose: str


@dataclasses.dataclass(repr=False)
class Environment(SerializableContainer):
    """
    Represents an environment and its dimensions.

    Derived from https://gitlab.com/testing-farm/eunomia but limited to fields that affect
    the provisioning: for example, environment variables nor repositories would have no
    effect on the provisioning process, therefore are omitted.
    """

    hw: HWRequirements
    os: OsRequirements
    pool: Optional[str] = None
    snapshots: bool = False

    #: If set, the request limits the instance to be either a spot instance, or a regular one. If left unset,
    #: the request does not care, and any kind of instance can be used.
    spot_instance: Optional[bool] = None

    @property
    def has_hw_constraints(self) -> bool:
        """
        Check whether the environment contains any HW constraints.

        :returns: ``True`` if environment contains HW constraints, ``False`` otherwise.
        """

        return self.hw.constraints is not None

    def get_hw_constraints(self) -> Result[Optional[ConstraintBase], 'Failure']:
        """
        Extract HW constraints from the environment.

        :returns: HW constraints when the environment contains any, ``None`` otherwise.
        """

        if self.hw.constraints is None:
            return Ok(None)

        return cast(
            Result[Optional[ConstraintBase], 'Failure'],
            constraints_from_environment_requirements(self.hw.constraints)
        )
