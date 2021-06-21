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
    For the purpose of HW requirements, this class represents a HW properties related to CPU
    and CPU cores of a flavor.

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
        return [
            f'cpu.{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
        ]

    def __repr__(self) -> str:
        return f'<FlavorCpu: {" ".join(self.format_fields())}>'


@dataclasses.dataclass(repr=True)
class FlavorDisk(SerializableContainer):
    """
    For the purpose of HW requirements, this class represents a HW properties related to persistent storage a flavor.

    .. note::

       As of now, only the very basic topology is supported, tracking only the total "disk" size. More complex
       setups will be supported in the future.
    """

    #: Total size of the disk storage, in bytes.
    space: Optional[Quantity] = None

    def format_fields(self) -> List[str]:
        return [
            f'disk.{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
        ]

    def __repr__(self) -> str:
        return f'<FlavorDisk: {" ".join(self.format_fields())}>'

    def serialize_to_json(self) -> Dict[str, Any]:
        serialized = dataclasses.asdict(self)

        if self.space is not None:
            serialized['space'] = str(self.space)

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'FlavorDisk':
        disk = cls(**serialized)

        if disk.space is not None:
            disk.space = UNITS(disk.space)

        return disk


@dataclasses.dataclass(repr=False)
class Flavor(SerializableContainer):
    """
    For the purpose of HW requirements, this class represents a HW properties of a flavor.
    """

    name: str
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
        return self.cpu.format_fields() + self.disk.format_fields() + [
            f'{field.name}={getattr(self, field.name)}'
            for field in dataclasses.fields(self)
            if field.name not in ('cpu', 'disk')
        ]

    def __repr__(self) -> str:
        return f'<PoolFlavorInfo: {" ".join(self.format_fields())}>'

    # TODO: because of a circular dependency, we can't derive this class from SerializableContainer :/
    def serialize_to_json(self) -> Dict[str, Any]:
        serialized = dataclasses.asdict(self)

        if self.memory is not None:
            serialized['memory'] = str(self.memory)

        serialized['disk'] = self.disk.serialize_to_json()

        return serialized

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'Flavor':
        flavor = cls(**serialized)

        if flavor.memory is not None:
            flavor.memory = UNITS(flavor.memory)

        flavor.cpu = FlavorCpu.unserialize_from_json(serialized['cpu'])
        flavor.disk = FlavorDisk.unserialize_from_json(serialized['disk'])

        return flavor

    def clone(self) -> 'Flavor':
        # Similar to dataclasses.replace(), but that one isn't recursive, and we have to clone even cpu and disk info.
        clone = dataclasses.replace(self)
        clone.cpu = dataclasses.replace(self.cpu)
        clone.disk = dataclasses.replace(self.disk)

        return clone


class Operator(enum.Enum):
    EQ = '=='
    NEQ = '!='
    GT = '>'
    GTE = '>='
    LT = '<'
    LTE = '<='
    MATCH = '=~'


def match(text: str, pattern: str) -> bool:
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
    def __init__(self, constraint_name: str, raw_value: str) -> None:
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
        """

        raise NotImplementedError()

    def format(self, prefix: str = '') -> str:
        """
        Return pretty text representation of this constraint.
        """

        raise NotImplementedError()


class CompoundConstraint(ConstraintBase):
    """
    Base class for all *compound* constraints, constraints imposed to more than one dimension.
    """

    def __init__(
        self,
        reducer: Callable[[List[bool]], bool],
        constraints: Optional[List[ConstraintBase]] = None
    ) -> None:
        self.reducer = reducer
        self.constraints = constraints or []

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> bool:
        return self.reducer([
            constraint.eval_flavor(logger, flavor)
            for constraint in self.constraints
        ])

    def format(self, prefix: str = '') -> str:
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

    name: str
    operator: Operator
    value: ConstraintValueType

    # A callable comparing the flavor value and the constraint value.
    operator_handler: OperatorHandlerType

    # Stored for possible inspection by more advanced processing.
    raw_value: str
    unit: Optional[str] = None

    @classmethod
    def from_specification(
        cls: Type[T],
        name: str,
        raw_value: str,
        as_quantity: bool = True
    ) -> T:
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
        return cls(
            name='arch',
            operator=Operator.EQ,
            operator_handler=OPERATOR_TO_HANDLER[Operator.EQ],
            value=value,
            raw_value=value
        )

    def __repr__(self) -> str:
        return f'(FLAVOR.{self.name} {self.operator.value} {self.value})'

    def eval_flavor(self, logger: gluetool.log.ContextAdapter, flavor: Flavor) -> bool:
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
        return f'{prefix}{repr(self)}'


@dataclasses.dataclass
class And(CompoundConstraint):
    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        super(And, self).__init__(all, constraints=constraints)


@dataclasses.dataclass
class Or(CompoundConstraint):
    def __init__(self, constraints: Optional[List[ConstraintBase]] = None) -> None:
        super(Or, self).__init__(any, constraints=constraints)


def _parse_cpu(spec: SpecType) -> ConstraintBase:
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
    group = And()

    group.constraints += [
        _parse_block(member)
        for member in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_or(spec: SpecType) -> ConstraintBase:
    group = Or()

    group.constraints += [
        _parse_block(member)
        for member in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_block(spec: SpecType) -> ConstraintBase:
    if 'and' in spec:
        return _parse_and(spec['and'])

    elif 'or' in spec:
        return _parse_or(spec['or'])

    else:
        return _parse_generic_spec(spec)


def constraints_from_environment_requirements(spec: SpecType) -> Result[ConstraintBase, 'Failure']:
    from . import safe_call

    r_constraints = safe_call(_parse_block, spec)

    if r_constraints.is_error:
        r_constraints.unwrap_error().update(constraints_spec=spec)

    return r_constraints


@dataclasses.dataclass
class HWRequirements:
    arch: str
    constraints: Optional[SpecType] = None


@dataclasses.dataclass
class OsRequirements:
    compose: str


@dataclasses.dataclass(repr=False)
class Environment:
    """
    Represents a testing environment and its dimensions.

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
        return json.dumps(dataclasses.asdict(self))

    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize testing environment to a JSON dictionary.
        """

        return dataclasses.asdict(self)

    def serialize_to_str(self) -> str:
        """
        Serialize testing environment to a string.
        """

        return json.dumps(dataclasses.asdict(self))

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]) -> 'Environment':
        """
        Construct a testing environment from a JSON representation of fields and their values.
        """

        # COMPAT: handle serialized pre-v0.0.17 environments. Drop once v0.0.16 compatibility is removed.
        if 'arch' in serialized:
            if 'hw' in serialized:
                serialized['hw'] = serialized['arch']

            else:
                serialized['hw'] = {
                    'arch': serialized['arch']
                }

            del serialized['arch']

        env = Environment(**serialized)

        env.hw = HWRequirements(**serialized['hw'])
        env.os = OsRequirements(**serialized['os'])

        return env

    @classmethod
    def unserialize_from_str(cls, serialized: str) -> 'Environment':
        """
        Construct a testing environment from a JSON representation of fields and their values stored in a string.
        """

        return Environment.unserialize_from_json(json.loads(serialized))

    @property
    def has_hw_constraints(self) -> bool:
        return self.hw.constraints is not None

    def get_hw_constraints(self) -> Result[Optional[ConstraintBase], 'Failure']:
        if self.hw.constraints is None:
            return Ok(None)

        return cast(
            Result[Optional[ConstraintBase], 'Failure'],
            constraints_from_environment_requirements(self.hw.constraints)
        )
