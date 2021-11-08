"""
Guest environment specification and handling.

Each guest request carries an environment specification, and Artemis will provision a VM satisfying the given request.
This specification includes both software requirements - compose - and hardware requirements - architecture, memory
size, etc.
"""

import dataclasses
import enum
import itertools
import json
import operator
import re
from typing import Any, Callable, ClassVar, Dict, Iterator, List, Optional, Sequence, Type, TypeVar, Union, cast

import gluetool.log
import pint
from gluetool.result import Ok, Result
from pint import Quantity

from . import Failure, SerializableContainer, format_dict_yaml

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
VALUE_PATTERN = re.compile(r'^(?P<operator>==|!=|=~|=|>=|>|<=|<)?\s*(?P<value>.+?)\s*$')

PROPERTY_PATTERN = re.compile(r'(?P<property_name>[a-z_]+)(?:\[(?P<index>\d+)\])?')

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

ConstraintValueType = Union[int, Quantity, str]
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

    def __repr__(self) -> str:
        """
        Return text representation of subsystem properties.

        :returns: human-readable rendering of subsystem properties.
        """

        return format_dict_yaml(self.serialize_to_json())

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

    def serialize_to_json(self) -> List[Dict[str, Any]]:  # type: ignore[override]  # expected
        """
        Serialize container to JSON.

        :returns: serialized form of container items.
        """

        return [
            item.serialize_to_json() for item in self.items
        ]

    @classmethod
    def unserialize_from_json(cls: Type[V], serialized: List[Dict[str, Any]]) -> V:  # type: ignore[override]
        """
        Unserialize items from JSON.

        :param serialized: serialized form of container items.
        :returns: unserialized container.
        """

        return cls([
            cls.ITEM_CLASS.unserialize_from_json(serialized_item)
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


@dataclasses.dataclass(repr=True)
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

    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON.

        :returns: serialized form of flavor properties.
        """

        serialized = super(FlavorDisk, self).serialize_to_json()

        if self.size is not None:
            serialized['size'] = str(self.size)

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'FlavorDisk':
        """
        Unserialize properties from JSON.

        :param serialized: serialized form of flavor properties.
        :returns: disk properties of a flavor.
        """

        disk = super(FlavorDisk, cls).unserialize_from_json(serialized)

        if disk.size is not None:
            disk.size = UNITS(disk.size)

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


@dataclasses.dataclass(repr=True)
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

    #: Human-readable name of the flavor.
    name: str

    #: ID of the flavor as known to flavor's driver.
    id: str

    #: HW architecture of the flavor.
    arch: Optional[str] = None

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

    # TODO: because of a circular dependency, we can't derive this class from SerializableContainer :/
    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON.

        :returns: serialized form of flavor properties.
        """

        serialized = super(Flavor, self).serialize_to_json()

        if self.memory is not None:
            serialized['memory'] = str(self.memory)

        return serialized

    def serialize_to_json_scrubbed(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON while scrubbing sensitive information.

        :returns: serialized form of flavor properties.
        """

        serialized = self.serialize_to_json()

        del serialized['id']

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'Flavor':
        """
        Unserialize properties from JSON.

        :param serialized: serialized form of flavor properties.
        :returns: flavor instance.
        """

        flavor = super(Flavor, cls).unserialize_from_json(serialized)

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


def match(text: str, pattern: str) -> bool:
    """
    Match a text against a given regular expression.

    :param text: string to examine.
    :param pattern: regular expression.
    :returns: ``True`` if pattern matches the string.
    """

    return re.match(pattern, text) is not None


OPERATOR_SIGN_TO_OPERATOR = {
    '=': Operator.EQ,
    '==': Operator.EQ,
    '!=': Operator.NEQ,
    '>': Operator.GT,
    '>=': Operator.GTE,
    '<': Operator.LT,
    '<=': Operator.LTE,
    '=~': Operator.MATCH
}


OPERATOR_TO_HANDLER: Dict[Operator, OperatorHandlerType] = {
    Operator.EQ: operator.eq,
    Operator.NEQ: operator.ne,
    Operator.GT: operator.gt,
    Operator.GTE: operator.ge,
    Operator.LT: operator.lt,
    Operator.LTE: operator.le,
    Operator.MATCH: match
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

    def __init__(self, constraint_name: str, raw_value: str) -> None:
        """
        Raise when HW constraint parsing fails.

        :param constraint_name: name of the constraint that caused issues.
        :param raw_value: original raw value.
        """

        super(ParseError, self).__init__('failed to parse a constraint')

        self.constraint_name = constraint_name
        self.raw_value = raw_value


class ConstraintBase:
    """
    Base class for all classes representing one or more constraints.
    """

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> bool:
        """
        Inspect the given flavor, and decide whether it fits the limits imposed by this constraint.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: ``True`` if the given flavor satisfies the constraint.
        """

        return False

    def prune_on_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> Optional['ConstraintBase']:
        """
        Decide whether to keep this constraint or not, given the flavor.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: constraint when the constraint evaluates to ``True``, ``None`` otherwise.
        """

        return self if self.eval_flavor(logger, flavor) else None

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

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.

        The output provides nicer formatting for humans to easier grasp the tree-like nature of the constraint tree.

        :param prefix: characters to prepend to each line of the formatted output.
        :returns: prettified, human-readable rendering of the constraint.
        """

        return '<not implemented>'

    def __repr__(self) -> str:
        """
        Return text representation of the constraint suitable for logging.

        :returns: human-readable rendering of the constraint.
        """

        return self.format()

    def __str__(self) -> str:
        """
        Return text representation of the constraint suitable for logging.

        :returns: human-readable rendering of the constraint.
        """

        return self.format()


class CompoundConstraint(ConstraintBase):
    """
    Base class for all *compound* constraints, constraints imposed to more than one dimension.
    """

    def __init__(
        self,
        reducer: Callable[[List[bool]], bool] = any,
        constraints: Optional[List[ConstraintBase]] = None
    ) -> None:
        """
        Construct a compound constraint, constraint imposed to more than one dimension.

        :param reducer: a callable reducing a list of results from child constraints into the final answer.
        :param constraints: child contraints.
        """

        self.reducer = reducer
        self.constraints = constraints or []

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> bool:
        """
        Compare given flavor against the constraint.

        The constraint will evaluate its subconstraints, and merge their results into one final answer.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: ``True`` if the given flavor satisfies the constraint.
        """

        return self.reducer([
            constraint.eval_flavor(logger, flavor)
            for constraint in self.constraints
        ])

    def prune_on_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> Optional[ConstraintBase]:
        """
        Decide whether to keep this constraint or not, given the flavor.

        :param logger: logger to use for logging.
        :param flavor: flavor to test.
        :returns: constraint when the constraint evaluates to ``True``, ``None`` otherwise.
        """

        if self.eval_flavor(logger, flavor) is not True:
            return None

        pruned_constraints: List[ConstraintBase] = []

        for constraint in self.constraints:
            pruned_constraint = constraint.prune_on_flavor(logger, flavor)

            if pruned_constraint is None:
                continue

            pruned_constraints.append(pruned_constraint)

        return self.__class__(constraints=pruned_constraints)

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

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.

        The output provides nicer formatting for humans to easier grasp the tree-like nature of the constraint tree.

        :param prefix: characters to prepend to each line of the formatted output.
        :returns: prettified, human-readable rendering of the constraint.
        """

        if len(self.constraints) == 1:
            return f'{prefix}{self.constraints[0].format()}'

        lines = [
            f'{prefix}{self.__class__.__name__}['
        ] + [
            constraint.format(prefix=prefix + '    ')
            for constraint in self.constraints
        ] + [
            f'{prefix}]'
        ]

        return '\n'.join(lines)


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

    @classmethod
    def from_specification(
        cls: Type[T],
        name: str,
        raw_value: str,
        as_quantity: bool = True
    ) -> T:
        """
        Parse raw constraint specification into our internal representation.

        :param name: name of the constraint.
        :param raw_value: raw value of the constraint.
        :param as_quantity: if set, value is treated as a quantity containing also unit, and as such the raw value is
            converted to :py:`pint.Quantity` instance.
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

        else:
            value = raw_value

        return cls(
            name=name,
            operator=operator,
            operator_handler=OPERATOR_TO_HANDLER[operator],
            value=value,
            raw_value=raw_value
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

    def __repr__(self) -> str:
        """
        Return text representation of the constrain suitable for logging.

        :returns: human-readable rendering of the constraint.
        """

        return f'(FLAVOR.{self.name} {self.operator.value} {self.value})'

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> bool:
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

            flavor_property = getattr(flavor_property, groups['property_name'])

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
            result = self.operator_handler(  # type: ignore[call-arg]  # Too many arguments - mypy issue #5485
                flavor_property,
                self.value
            )

        logger.debug(f'eval-flavor: {flavor.name}.{self.name}: {type(flavor_property).__name__}({flavor_property}) {self.operator.value} {type(self.value).__name__}({self.value}): {result}')  # noqa: E501

        return result

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.

        The output provides nicer formatting for humans to easier grasp the tree-like nature of the constraint tree.

        :param prefix: characters to prepend to each line of the formatted output.
        :returns: prettified, human-readable rendering of the constraint.
        """

        return f'{prefix}(FLAVOR.{self.name} {self.operator.value} {self.value})'


@dataclasses.dataclass
class And(CompoundConstraint):
    """
    Represents constraints that are grouped in ``and`` fashion.
    """

    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        """
        Hold constraints that are grouped in ``and`` fashion.

        :param constraints: list of constraints to group.
        """

        super(And, self).__init__(all, constraints=constraints)

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


@dataclasses.dataclass
class Or(CompoundConstraint):
    """
    Represents constraints that are grouped in ``or`` fashion.
    """

    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        """
        Hold constraints that are grouped in ``or`` fashion.

        :param constraints: list of constraints to group.
        """

        super(Or, self).__init__(any, constraints=constraints)

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
        Constraint.from_specification(f'cpu.{constraint_name}', str(spec[constraint_name]), as_quantity=False)
        for constraint_name in ('model_name',)
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

    group.constraints += [
        Constraint.from_specification(f'disk[{disk_index}].{constraint_name}', str(spec[constraint_name]))
        for constraint_name in ('size',)
        if constraint_name in spec
    ]

    # The old-style constraint when `space` existed. Remove once v0.0.26 is gone.
    if 'space' in spec:
        group.constraints += [
            Constraint.from_specification(f'disk[{disk_index}].size', str(spec['space']))
        ]

    if len(group.constraints) == 1:
        return group.constraints[0]

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

    if 'cpu' in spec:
        group.constraints += [_parse_cpu(spec['cpu'])]

    if 'memory' in spec:
        group.constraints += [Constraint.from_specification('memory', str(spec['memory']))]

    if 'disk' in spec:
        group.constraints += [_parse_disks(spec['disk'])]

    if 'network' in spec:
        group.constraints += [_parse_networks(spec['network'])]

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


@dataclasses.dataclass
class HWRequirements:
    """
    Represents HQ requirements of the environment.
    """

    #: Requested architecture.
    arch: str

    #: Additional HW constraints.
    constraints: Optional[SpecType] = None


@dataclasses.dataclass
class OsRequirements:
    """
    Represents OS requirements of the environment.
    """

    #: Compose ID/name.
    compose: str


@dataclasses.dataclass(repr=False)
class Environment:
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

    def __repr__(self) -> str:
        """
        Return text representation of the environment suitable for logging.

        :returns: human-readable rendering of the environment.
        """

        return json.dumps(dataclasses.asdict(self))

    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize environment to a JSON.

        :returns: serialized environment.
        """

        return dataclasses.asdict(self)

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'Environment':
        """
        Construct an environment from its JSON serialized form.

        :param serialized: serialized environment.
        :returns: new :py:class:`Environment` instance.
        """

        env = Environment(**serialized)

        env.hw = HWRequirements(**serialized['hw'])
        env.os = OsRequirements(**serialized['os'])

        return env

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
