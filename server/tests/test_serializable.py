# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import textwrap
from typing import List

import pytest
import ruamel.yaml.main

import tft.artemis


@pytest.fixture(name='YAML')
def fixture_yaml() -> ruamel.yaml.main.YAML:
    return tft.artemis.get_yaml()


@dataclasses.dataclass
class Container(tft.artemis.SerializableContainer):
    bar: int = 79
    baz: List[str] = dataclasses.field(default_factory=list)


# This container is not used in tests to create instances, we just want to make sure even subclasses of subclasses
# of SerializableContainer are properly registered.
@dataclasses.dataclass
class UnusedContainer(Container):
    pass


@dataclasses.dataclass
class NestedContainer(tft.artemis.SerializableContainer):
    bar: str


@dataclasses.dataclass
class NestingContainer(tft.artemis.SerializableContainer):
    foo: str
    child: NestedContainer


def test_json() -> None:
    foo = Container()

    serialized = foo.serialize_to_json()

    assert serialized == {'bar': 79, 'baz': []}

    bar = Container.unserialize_from_json(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_str() -> None:
    foo = Container()

    serialized = foo.serialize_to_str()

    assert serialized == '{"bar": 79, "baz": []}'  # noqa: FS003  # not an f-string

    bar = Container.unserialize_from_str(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_yaml_dumpable_registry() -> None:
    assert Container in tft.artemis._YAML_DUMPABLE_CLASSES
    assert NestedContainer in tft.artemis._YAML_DUMPABLE_CLASSES
    assert NestingContainer in tft.artemis._YAML_DUMPABLE_CLASSES
    assert UnusedContainer in tft.artemis._YAML_DUMPABLE_CLASSES


def test_nesting() -> None:
    foo = NestingContainer(
        foo='some foo value',
        child=NestedContainer(
            bar='some bar value'
        )
    )

    serialized = foo.serialize_to_json()

    assert serialized == {'foo': 'some foo value', 'child': {'bar': 'some bar value'}}

    bar = NestingContainer.unserialize_from_json(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_to_yaml(YAML: ruamel.yaml.main.YAML) -> None:
    foo = NestingContainer(
        foo='some foo value',
        child=NestedContainer(
            bar='some bar value'
        )
    )

    # Use lstrip() to get rid of the leading new-line - it's there because of the formatting of the multiline string,
    # which makes YAML easier to read. `dedent()` won't get rid of it.
    assert tft.artemis.format_dict_yaml(foo) == textwrap.dedent(
        """
        foo: some foo value
        child:
            bar: some bar value
        """
    ).lstrip()
