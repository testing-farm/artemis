import dataclasses
import enum
import json
import operator
import re
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, cast

#
# HW requirement part of the environment
#

# Special type variable, used in `Constraint.from_specification` - we bound this return value to always be a subclass
# of `Constraint` class, instead of just any class in general.
T = TypeVar('T', bound='Constraint')

VALUE_PATTERN = re.compile(r'^(?P<operator>==|!=|=~|=|>=|>|<=|<)?\s*(?P<value>.+?)\s*(?P<unit>GB|MB|kB)?$')

OperatorHandlerType = Callable[[str, str], bool]

# mypy does not support cyclic definition, it would be much easier to just define this:
# SpecType = Dict[str, Union[int, float, str, 'SpecType', List['SpecType']]]
SpecType = Any


@dataclasses.dataclass
class FlavorCpu:
    processors: Optional[int] = None
    cores: Optional[int] = None
    model: Optional[int] = None
    model_name: Optional[str] = None
    family: Optional[int] = None


@dataclasses.dataclass
class FlavorDisk:
    space: Optional[int] = None


@dataclasses.dataclass
class Flavor:
    arch: Optional[str] = None
    cpu: FlavorCpu = dataclasses.field(default_factory=FlavorCpu)
    disk: FlavorDisk = dataclasses.field(default_factory=FlavorDisk)
    memory: Optional[int] = None


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


UNIT_MULTIPLIERS = {
    'GB': 1024 * 1024 * 1024,
    'MB': 1024 * 1024,
    'kB': 1024
}


class ConstraintBase:
    """
    Base class for all classes representing one or more constraints.
    """

    def eval_flavor(self, flavor: Flavor) -> bool:
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

    def eval_flavor(self, flavor: Flavor) -> bool:
        return self.reducer([
            constraint.eval_flavor(flavor)
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


@dataclasses.dataclass
class Constraint(ConstraintBase):
    """
    A constraint imposing a particular limit to one of the system properties.
    """

    name: str
    operator: Operator
    value: str

    # A callable comparing the flavor value and the constraint value.
    operator_handler: OperatorHandlerType
    type_cast: Callable[[str], Any]

    # Stored for possible inspection by more advanced processing.
    raw_value: str
    unit: Optional[str] = None

    @classmethod
    def from_specification(cls: Type[T], name: str, raw_value: str, type_cast: Callable[[str], Any]) -> T:
        parsed_value = VALUE_PATTERN.match(raw_value)

        if not parsed_value:
            raise Exception()

        groups = parsed_value.groupdict()

        if groups['operator']:
            operator = OPERATOR_SIGN_TO_OPERATOR[groups['operator']]

        else:
            operator = Operator.EQ

        value = groups['value']

        if groups['unit']:
            unit = groups['unit']

            if unit not in UNIT_MULTIPLIERS:
                raise Exception()

            value = str(int(value) * UNIT_MULTIPLIERS[unit])

        return cls(
            name=name,
            operator=operator,
            operator_handler=OPERATOR_TO_HANDLER[operator],
            type_cast=type_cast,
            value=value,
            unit=groups['unit'],
            raw_value=raw_value
        )

    @classmethod
    def from_arch(cls: Type[T], value: str) -> T:
        return cls(
            name='arch',
            operator=Operator.EQ,
            operator_handler=OPERATOR_TO_HANDLER[Operator.EQ],
            type_cast=str,
            value=value,
            raw_value=value
        )

    def __repr__(self) -> str:
        return f'(FLAVOR.{self.name} {self.operator.value} {self.value})'

    def eval_flavor(self, flavor: Flavor) -> bool:
        flavor_property = cast(Any, flavor)
        property_path = self.name.split('.')

        while property_path:
            flavor_property = getattr(flavor_property, property_path.pop(0))

        result = self.operator_handler(
            self.type_cast(flavor_property),
            self.type_cast(self.value)
        )

        print(f'eval: {self.name} "{flavor_property}" {self.operator.value} "{self.value}" => {result}')

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

    group.constraints = []

    group.constraints += [
        Constraint.from_specification(f'cpu.{constraint_name}', str(spec[constraint_name]), int)
        for constraint_name in ('processors', 'cores', 'model', 'family')
        if constraint_name in spec
    ]

    group.constraints += [
        Constraint.from_specification(f'cpu.{constraint_name}', str(spec[constraint_name]), str)
        for constraint_name in ('model_name',)
        if constraint_name in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_disk(spec: SpecType) -> ConstraintBase:
    group = And()

    group.constraints = [
        Constraint.from_specification(f'disk.{constraint_name}', str(spec[constraint_name]), int)
        for constraint_name in ('space',)
        if constraint_name in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_generic_spec(spec: SpecType) -> ConstraintBase:
    group = And()

    if 'cpu' in spec:
        group.constraints += [_parse_cpu(spec['cpu'])]

    if 'memory' in spec:
        group.constraints += [Constraint.from_specification('memory', spec['memory'], int)]

    if 'disk' in spec:
        group.constraints += [_parse_disk(spec['disk'])]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_and(spec: SpecType) -> ConstraintBase:
    group = And()

    group.constraints = [
        _parse_block(member)
        for member in spec
    ]

    if len(group.constraints) == 1:
        return group.constraints[0]

    return group


def _parse_or(spec: SpecType) -> ConstraintBase:
    group = Or()

    group.constraints = [
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


def constraints_from_environment_requirements(spec: SpecType) -> ConstraintBase:
    return _parse_block(spec)


@dataclasses.dataclass
class HWRequirements:
    arch: str
    hw: Optional[SpecType] = None


@dataclasses.dataclass
class OsRequirements:
    compose: str


@dataclasses.dataclass
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

    def get_environment_constraints(self) -> ConstraintBase:
        if not self.hw.hw:
            return Constraint.from_arch(self.hw.arch)

        return And(constraints=[
            Constraint.from_arch(self.hw.arch),
            constraints_from_environment_requirements(self.hw.hw)
        ])
