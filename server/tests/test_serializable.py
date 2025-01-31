# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import textwrap
from typing import List

import pytest
import ruamel.yaml.main

import tft.artemis


@pytest.fixture(name='yaml')
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


@dataclasses.dataclass(repr=False)
class NestingContainer(tft.artemis.SerializableContainer):
    foo: str
    child: NestedContainer
    baz: int


@pytest.fixture(name='nesting_container')
def fixture_nesting_container() -> NestingContainer:
    return NestingContainer(
        foo='some foo value',
        child=NestedContainer(
            bar='some bar value'
        ),
        baz=79
    )


# Use lstrip() to get rid of the leading new-line - it's there because of the formatting of the multiline string,
# which makes YAML easier to read. `dedent()` won't get rid of it.
NESTING_CONTAINER_AS_STRING = textwrap.dedent(
    """
    foo: some foo value
    child:
        bar: some bar value
    baz: 79"""
).lstrip()


def test_serialize() -> None:
    foo = Container()

    serialized = foo.serialize()

    assert serialized == {'bar': 79, 'baz': []}

    bar = Container.unserialize(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_json() -> None:
    foo = Container()

    serialized = foo.serialize_to_json()

    assert serialized == '{"bar": 79, "baz": []}'  # noqa: FS003  # not an f-string

    bar = Container.unserialize_from_json(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_yaml() -> None:
    foo = Container()

    serialized = foo.serialize_to_yaml()

    assert serialized == 'bar: 79\nbaz: []'

    bar = Container.unserialize_from_yaml(serialized)

    assert foo == bar
    assert type(foo) is type(bar)


def test_yaml_dumpable_registry() -> None:
    assert Container in tft.artemis._YAML_DUMPABLE_CLASSES
    assert NestedContainer in tft.artemis._YAML_DUMPABLE_CLASSES
    assert NestingContainer in tft.artemis._YAML_DUMPABLE_CLASSES
    assert UnusedContainer in tft.artemis._YAML_DUMPABLE_CLASSES


def test_nesting(nesting_container: NestingContainer) -> None:
    serialized = nesting_container.serialize()

    assert serialized == {'baz': 79, 'foo': 'some foo value', 'child': {'bar': 'some bar value'}}

    bar = NestingContainer.unserialize(serialized)

    assert nesting_container == bar
    assert type(nesting_container) is type(bar)


def test_to_yaml(yaml: ruamel.yaml.main.YAML, nesting_container: NestingContainer) -> None:
    assert tft.artemis.format_dict_yaml(nesting_container) == NESTING_CONTAINER_AS_STRING


def test_to_str(yaml: ruamel.yaml.main.YAML, nesting_container: NestingContainer) -> None:
    assert str(nesting_container) == NESTING_CONTAINER_AS_STRING
    assert repr(nesting_container) == NESTING_CONTAINER_AS_STRING
