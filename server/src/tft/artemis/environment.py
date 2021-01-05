import dataclasses
import json

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from .db import EnvironmentSerializedType


@dataclasses.dataclass
class Os:
    compose: str


@dataclasses.dataclass
class Environment:
    """
    Represents a testing environment and its dimensions.

    Derived from https://gitlab.com/testing-farm/eunomia but limited to fields that affect
    the provisioning: for example, environment variables nor repositories would have no
    effect on the provisioning process, therefore are omitted.
    """

    arch: str
    os: Os
    pool: Optional[str] = None
    snapshots: bool = False

    def __repr__(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    def serialize_to_json(self) -> 'EnvironmentSerializedType':
        """
        Serialize testing environment to a JSON dictionary.
        """

        return dataclasses.asdict(self)

    @classmethod
    def unserialize_from_json(cls, serialized: 'EnvironmentSerializedType'):
        # type: (...) -> Environment
        """
        Construct a testing environment from a JSON representation of fields and their values.
        """

        env = Environment(**serialized)

        env.os = Os(
            compose=serialized['os']['compose']
        )

        return env
