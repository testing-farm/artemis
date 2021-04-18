import dataclasses
import json
from typing import Any, Dict, Optional


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

        env = Environment(**serialized)

        env.os = Os(
            compose=serialized['os']['compose']
        )

        return env

    @classmethod
    def unserialize_from_str(cls, serialized: str) -> 'Environment':
        """
        Construct a testing environment from a JSON representation of fields and their values stored in a string.
        """

        return Environment.unserialize_from_json(json.loads(serialized))
