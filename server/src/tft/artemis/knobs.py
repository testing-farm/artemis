import json
import os

from gluetool.result import Result, Ok, Error
from sqlalchemy.orm.session import Session

from typing import TYPE_CHECKING, cast, Any, Callable, Generic, List, Optional, Tuple, TypeVar

if TYPE_CHECKING:
    from . import Failure


T = TypeVar('T')


class KnobSource(Generic[T]):
    def __init__(self, knob: 'Knob[T]') -> None:
        self.knob = knob

    def get_value(self, *args: Any) -> Result[Optional[T], 'Failure']:
        return Ok(None)

    def to_repr(self) -> List[str]:
        return []


class KnobSourceEnv(KnobSource[T]):
    def __init__(self, knob: 'Knob[T]', envvar: str, type_cast: Callable[[str], T]) -> None:
        super(KnobSourceEnv, self).__init__(knob)

        self.envvar = envvar
        self.type_cast = type_cast

    def get_value(self, *args: Any) -> Result[Optional[T], 'Failure']:
        if self.envvar not in os.environ:
            return Ok(None)

        return Ok(
            self.type_cast(os.environ[self.envvar])
        )

    def to_repr(self) -> List[str]:
        return [
            'envvar="{}"'.format(self.envvar),
            'envvar-type-cast={}'.format(self.type_cast.__name__)
        ]


class KnobSourceDefault(KnobSource[T]):
    def __init__(self, knob: 'Knob[T]', default: T) -> None:
        super(KnobSourceDefault, self).__init__(knob)

        self.default = default

    def get_value(self, *args: Any) -> Result[Optional[T], 'Failure']:
        return Ok(self.default)

    def to_repr(self) -> List[str]:
        return [
            'default="{}"'.format(self.default)
        ]


class KnobSourceDB(KnobSource[T]):
    def get_value(self, session: Session, *args) -> Result[Optional[T], 'Failure']:  # type: ignore
        from .db import Query, Knob as KnobRecord

        knob = Query.from_session(session, KnobRecord) \
            .filter(KnobRecord.knobname == self.knob.knobname) \
            .one_or_none()

        if not knob:
            return Ok(None)

        try:
            return Ok(cast(T, json.loads(knob.value)))

        except json.JSONDecodeError as exc:
            from . import Failure

            return Error(Failure.from_exc('Cannot decode knob value', exc))

    def to_repr(self) -> List[str]:
        return [
            'has-db=yes'
        ]


class Knob(Generic[T]):
    def __init__(
        self,
        knobname: str,
        has_db: bool = True,
        envvar: Optional[str] = None,
        envvar_cast: Optional[Callable[[str], T]] = None,
        default: Optional[T] = None,
    ) -> None:
        self.knobname = knobname
        self._sources: List[KnobSource[T]] = []

        if has_db:
            self._sources.append(KnobSourceDB(self))

        if envvar is not None:
            if not envvar_cast:
                raise Exception('Knob {} defined with envvar but no envvar_cast'.format(knobname))

            self._sources.append(KnobSourceEnv(self, envvar, envvar_cast))

        if default is not None:
            self._sources.append(KnobSourceDefault(self, default))

        # If the knob isn't backed by a database, it should be possible to deduce its value *now*,
        # as it depends on envvar or the default value. For such knobs, we provide a shortcut,
        # easy-to-use `value` attribute - no `Result`, no `unwrap()` - given the possible sources,
        # it should never fail to get a value from such sources.
        if not has_db:
            value, failure = self._get_value()

            # If we fail to get value from envvar/defautl sources, then something is wrong. Maybe there's
            # just the envvar source, no default one, and environment variable is not set? In any case,
            # this sounds like a serious bug.
            assert value is not None, """
Knob "{}" is badly configured: no DB, yet other sources do not provide value!
To fix, add an envvar source, or a default value.

{}

{}
""".format(knobname, repr(self), failure or '')

            self.value = value

    def __repr__(self) -> str:
        return '<Knob: {}: {}>'.format(
            self.knobname,
            ', '.join(sum([source.to_repr() for source in self._sources], []))
        )

    def _get_value(self, *args: Any) -> Tuple[Optional[T], Optional['Failure']]:
        for source in self._sources:
            r = source.get_value(*args)

            if r.is_error:
                return None, r.unwrap_error()

            value = r.unwrap()

            if value is None:
                continue

            return value, None

        return None, None

    def get_value(self, *args: Any) -> Result[T, 'Failure']:
        value, failure = self._get_value(*args)

        if value is not None:
            return Ok(value)

        if failure:
            return Error(failure)

        from . import Failure

        return Error(Failure('Cannot fetch knob value'))
