import dataclasses
import json

from typing import Any, Dict, Optional


@dataclasses.dataclass
class BeakerCompose:
    distro: str


@dataclasses.dataclass
class OpenstackCompose:
    image: str


@dataclasses.dataclass
class AWSCompose:
    image: str


@dataclasses.dataclass
class Compose:
    id: Optional[str]
    beaker: Optional[BeakerCompose]
    openstack: Optional[OpenstackCompose]
    aws: Optional[AWSCompose]

    @property
    def is_beaker(self) -> bool:
        return self.id is None and self.beaker is not None

    @property
    def is_openstack(self) -> bool:
        return self.id is None and self.openstack is not None

    @property
    def is_aws(self) -> bool:
        return self.id is None and self.aws is not None


@dataclasses.dataclass
class Environment:
    """
    Represents a testing environment and its dimensions.

    Derived from https://gitlab.com/testing-farm/eunomia but limited to fields that affect
    the provisioning: for example, environment variables nor repositories would have no
    effect on the provisioning process, therefore are omitted.
    """

    arch: str
    compose: Compose

    def __repr__(self) -> str:
        return json.dumps(dataclasses.asdict(self))

    def serialize_to_json(self) -> Dict[str, Any]:
        """
        Serialize testing environment to a JSON dictionary.
        """

        return dataclasses.asdict(self)

    @classmethod
    def unserialize_from_json(cls, serialized: Dict[str, Any]):
        # type: (...) -> Environment
        """
        Construct a testing environment from a JSON representation of fields and their values.
        """

        env = Environment(**serialized)

        env.compose = Compose(
            id=None,
            beaker=None,
            openstack=None,
            aws=None
        )

        if 'compose' in serialized:
            if 'id' in serialized['compose']:
                env.compose.id = serialized['compose']['id']

            def _add_complex_container(field: str, klass: object) -> None:
                if field not in serialized['compose']:
                    return

                container = klass(**serialized['compose'][field])  # type: ignore
                setattr(env.compose, field, container)

            _add_complex_container('beaker', BeakerCompose)
            _add_complex_container('openstack', OpenstackCompose)
            _add_complex_container('aws', AWSCompose)

        return env
