"""
Guest environment specification and handling.

Each guest request carries an environment specification, and Artemis will provision a VM satisfying the given request.
This specification includes both software requirements - compose - and hardware requirements - architecture, memory
size, etc.
"""

import dataclasses
import enum
import json
import operator
import re
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union, cast

import gluetool.log
import pint
from gluetool.result import Ok, Result
from pint import Quantity

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
VALUE_PATTERN = re.compile(r'^(?P<operator>==|!=|=~|=|>=|>|<=|<)?\s*(?P<value>.+?)\s*$')

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


#
# A flavor represents a type of guest a driver is able to deliver. It groups together various HW properties, and
# the mapping of these flavors to actual objects the driver can provision is in the driver's scope.
#
# Note: some cloud services do use the term "flavor", to describe the very same concept. We hijack it for our use,
# because we use the same concept, and other terms - e.g. "instance type" - are not as good looking.
#
@dataclasses.dataclass(repr=False)
class FlavorCpu(SerializableContainer):
    """
    Represents HW properties related to CPU and CPU cores of a flavor.

    .. note::

       The relation between CPU and CPU cores is now intentionally ignored. We pretend the topology is trivial,
       all processors are the same, all processors have the same number of cores.
    """

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

    def format_fields(self) -> List[str]:
        """
        Return formatted representation of flavor properties.

        :returns: list of formatted properties.
        """

        return [
            f'cpu.{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
        ]

    def __repr__(self) -> str:
        """
        Return text representation of flavor properties.

        :returns: human-readable rendering of flavor properties.
        """

        return f'<FlavorCpu: {" ".join(self.format_fields())}>'


@dataclasses.dataclass(repr=True)
class FlavorDisk(SerializableContainer):
    """
    Represents a HW properties related to persistent storage a flavor.

    .. note::

       As of now, only the very basic topology is supported, tracking only the total "disk" size. More complex
       setups will be supported in the future.
    """

    #: Total size of the disk storage, in bytes.
    space: Optional[Quantity] = None

    def format_fields(self) -> List[str]:
        """
        Return formatted representation of flavor properties.

        :returns: list of formatted properties.
        """

        return [
            f'disk.{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
        ]

    def __repr__(self) -> str:
        """
        Return text representation of flavor properties.

        :returns: human-readable rendering of flavor properties.
        """

        return f'<FlavorDisk: {" ".join(self.format_fields())}>'

    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON.

        :returns: serialized form of flavor properties.
        """

        serialized = dataclasses.asdict(self)

        if self.space is not None:
            serialized['space'] = str(self.space)

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'FlavorDisk':
        """
        Unserialize properties from JSON.

        :param serialized: serialized form of flavor properties.
        :returns: disk properties of a flavor.
        """

        disk = cls(**serialized)

        if disk.space is not None:
            disk.space = UNITS(disk.space)

        return disk


@dataclasses.dataclass(repr=False)
class Flavor(SerializableContainer):
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

    #: Disk/storage proeprties.
    disk: FlavorDisk = dataclasses.field(default_factory=FlavorDisk)

    #: RAM size, in bytes.
    memory: Optional[Quantity] = None

    def format_fields(self) -> List[str]:
        """
        Return formatted representation of flavor properties.

        :returns: list of formatted properties.
        """

        return self.cpu.format_fields() + self.disk.format_fields() + [
            f'{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
            if field.name not in ('cpu', 'disk')
        ]

    def __repr__(self) -> str:
        """
        Return text representation of flavor properties.

        :returns: human-readable rendering of flavor properties.
        """

        return f'<PoolFlavorInfo: {" ".join(self.format_fields())}>'

    # TODO: because of a circular dependency, we can't derive this class from SerializableContainer :/
    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize properties to JSON.

        :returns: serialized form of flavor properties.
        """

        serialized = dataclasses.asdict(self)

        if self.memory is not None:
            serialized['memory'] = str(self.memory)

        serialized['disk'] = self.disk.serialize_to_json()

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'Flavor':
        """
        Unserialize properties from JSON.

        :param serialized: serialized form of flavor properties.
        :returns: flavor instance.
        """

        flavor = cls(**serialized)

        if flavor.memory is not None:
            flavor.memory = UNITS(flavor.memory)

        flavor.cpu = FlavorCpu.unserialize_from_json(serialized['cpu'])
        flavor.disk = FlavorDisk.unserialize_from_json(serialized['disk'])

        return flavor

    def clone(self) -> 'Flavor':
        """
        Create a copy of this flavor.

        :returns: new instance with the very same properties.
        """

        # Similar to dataclasses.replace(), but that one isn't recursive, and we have to clone even cpu and disk info.
        clone = dataclasses.replace(self)
        clone.cpu = dataclasses.replace(self.cpu)
        clone.disk = dataclasses.replace(self.disk)

        return clone


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

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.

        The output provides nicer formatting for humans to easier grasp the tree-like nature of the constraint tree.

        :param prefix: characters to prepend to each line of the formatted output.
        :returns: prettified, human-readable rendering of the constraint.
        """

        return '<not implemented>'


class CompoundConstraint(ConstraintBase):
    """
    Base class for all *compound* constraints, constraints imposed to more than one dimension.
    """

    def __init__(
        self,
        reducer: Callable[[List[bool]], bool],
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
            flavor_property = getattr(flavor_property, property_path.pop(0))

        if flavor_property is None:
            # Hard to compare `None` with a constraint. Flavor can't provide - or doesn't feel like providing - more
            # specific value. Unless told otherwise, we should mark the evaluation as failed, and keep looking for
            # better mach.
            result = False

        else:
            result = self.operator_handler(  # type: ignore  # Too many arguments - mypy issue #5485
                flavor_property,
                self.value
            )

        logger.debug('eval-flavor: {} {} {} {} => {}'.format(
            self.name,
            flavor_property,
            self.operator.value,
            self.value,
            result
        ))

        return result

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.

        The output provides nicer formatting for humans to easier grasp the tree-like nature of the constraint tree.

        :param prefix: characters to prepend to each line of the formatted output.
        :returns: prettified, human-readable rendering of the constraint.
        """

        return f'(FLAVOR.{self.name} {self.operator.value} {self.value})'

        return f'{prefix}{repr(self)}'


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


def _parse_disk(spec: SpecType) -> ConstraintBase:
    """
    Parse a disk-related constraints.

    :param spec: raw constraint block specification.
    :returns: block representation as :py:class:`ConstraintBase` or one of its subclasses.
    """

    group = And()

    group.constraints += [
        Constraint.from_specification(f'disk.{constraint_name}', str(spec[constraint_name]))
        for constraint_name in ('space',)
        if constraint_name in spec
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
        group.constraints += [_parse_disk(spec['disk'])]

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
