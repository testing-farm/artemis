# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import textwrap
from typing import List, Optional

import bs4
import gluetool.utils
import pytest

import tft.artemis.environment


def parse_env(text: str) -> tft.artemis.environment.Environment:
    return tft.artemis.environment.Environment.unserialize_from_json(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )


def parse_hw(text: str) -> tft.artemis.environment.ConstraintBase:
    r_constraint = tft.artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    assert r_constraint.is_ok

    return r_constraint.unwrap()


@pytest.mark.parametrize(('env', 'expected'), [
    (
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose
        """,
        '<system><arch op="==" value="x86_64"/></system>'
    )
], ids=[
    'simple-arch',
])
def test_environment_to_beaker_filter(env: str, expected: str) -> None:
    environment = parse_env(env)

    r_beaker_filter = tft.artemis.drivers.beaker.environment_to_beaker_filter(environment)

    assert r_beaker_filter.is_ok

    beaker_filter = r_beaker_filter.unwrap()

    assert str(beaker_filter) == expected


@pytest.mark.parametrize(('avoid_groups', 'expected'), [
    (
        [],
        '<and/>'
    ),
    (
        ['dummy-group-1', 'dummy-group-2', 'dummy-group-3'],
        '<and><group op="!=" value="dummy-group-1"/><group op="!=" value="dummy-group-2"/><group op="!=" value="dummy-group-3"/></and>'  # noqa: E501
    )
], ids=[
    'no-avoid-group',
    'avoid-groups'
])
def test_groups_to_beaker_filter(avoid_groups: List[str], expected: str) -> None:
    r_beaker_filter = tft.artemis.drivers.beaker.groups_to_beaker_filter(avoid_groups)

    assert r_beaker_filter.is_ok

    beaker_filter = r_beaker_filter.unwrap()

    assert str(beaker_filter) == expected


@pytest.mark.parametrize(('filters', 'expected'), [
    (
        [],
        '<and/>'
    ),
    (
        [
            '<A/>',
            '<B/>',
            '<C/>',
            '<and><D/><E/></and>',
            '<or><F/><G/></or>'
        ],
        '<and><A/><B/><C/><D/><E/><or><F/><G/></or></and>'
    ),
    (
        [
            '<and><A/><B/></and>',
            '<C/>',
            '<and><D/><E/></and>',
            '<or><F/><G/></or>'
        ],
        '<and><A/><B/><C/><D/><E/><or><F/><G/></or></and>'
    ),
    (
        [
            '<or><A/><B/></or>',
            '<C/>',
            '<and><D/><E/></and>',
            '<or><F/><G/></or>'
        ],
        '<and><or><A/><B/></or><C/><D/><E/><or><F/><G/></or></and>'
    )
], ids=[
    'no-filters',
    'filters',
    'filter-with-and',
    'filter-with-or'
])
def test_merge_beaker_filters(filters: List[str], expected: str) -> None:
    r_final_filter = tft.artemis.drivers.beaker.merge_beaker_filters([
        bs4.BeautifulSoup(a_filter, 'xml').contents[0]
        for a_filter in filters
    ])

    assert r_final_filter.is_ok

    final_filter = r_final_filter.unwrap()

    assert str(final_filter) == expected


@pytest.mark.parametrize(('env', 'avoid_groups', 'expected'), [
    (
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose
        """,
        [],
        None,
    ),
    (
        """
        ---

        hw:
          arch: x86_64
          constraints:
            memory: ">= 8 GiB"

        os:
          compose: dummy-compose
        """,
        [],
        '<and><system><arch op="==" value="x86_64"/></system><system><memory op="&gt;=" value="8192"/></system></and>'
    ),
    (
        """
        ---

        hw:
          arch: x86_64
          constraints:
            memory: ">= 8 GiB"

        os:
          compose: dummy-compose
        """,
        ['dummy-group-1', 'dummy-group-2'],
        '<and><system><arch op="==" value="x86_64"/></system><system><memory op="&gt;=" value="8192"/></system><group op="!=" value="dummy-group-1"/><group op="!=" value="dummy-group-2"/></and>'  # noqa: E501
    ),
], ids=[
    'simple-arch',
    'arch-and-constraints',
    'arch-and-constraints-and-avoid-groups'
])
def test_create_beaker_filter(env: str, avoid_groups: List[str], expected: Optional[str]) -> None:
    environment = parse_env(env)

    r_filter = tft.artemis.drivers.beaker.create_beaker_filter(environment, avoid_groups)

    assert r_filter.is_ok

    filter = r_filter.unwrap()

    if filter is None:
        assert filter is expected

    else:
        assert str(filter) == expected
