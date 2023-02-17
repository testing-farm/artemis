# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import textwrap
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import bs4
import gluetool.utils
import pytest
from gluetool.log import ContextAdapter
from gluetool.result import Ok

import tft.artemis
import tft.artemis.drivers.beaker
import tft.artemis.environment

from .. import MockPatcher


def parse_spec(text: str) -> Any:
    return gluetool.utils.from_yaml(textwrap.dedent(text))


def parse_env(text: str) -> tft.artemis.environment.Environment:
    return tft.artemis.environment.Environment.unserialize(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )


def parse_hw(text: str) -> tft.artemis.environment.ConstraintBase:
    r_constraint = tft.artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    assert r_constraint.is_ok

    return r_constraint.unwrap()


@pytest.fixture(name='dummy_guest_request')
def fixture_dummy_guest_request(name: str = 'dummy_guest_request') -> MagicMock:
    return MagicMock(
        name=name,
        environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose')))


@pytest.fixture(name='pool')
def fixture_pool(logger: ContextAdapter) -> tft.artemis.drivers.beaker.BeakerDriver:
    pool_config = """
    ---

    hw-constraints:
      boot:
        method:
          translations:
            - operator: contains
              value: bios
              element: |
                <key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/>

            - operator: not contains
              value: bios
              element: |
                <key_value key="NETBOOT_METHOD" op="=" value="efigrub"/>

            - operator: contains
              value: uefi
              element: |
                <key_value key="NETBOOT_METHOD" op="=" value="efigrub"/>

            - operator: not contains
              value: uefi
              element: |
                <key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/>
      compatible:
        distro:
          translations:
            - operator: contains
              value: rhel-6
              element: |
                <compatible_with_distro arch="{{ ENVIRONMENT.hw.arch }}" osmajor="RedHatEnterpriseLinux6"/>

            - operator: contains
              value: rhel-7
              element: |
                <compatible_with_distro arch="{{ ENVIRONMENT.hw.arch }}" osmajor="RedHatEnterpriseLinux7"/>

            - operator: contains
              value: rhel-8
              element: |
                <compatible_with_distro arch="{{ ENVIRONMENT.hw.arch }}" osmajor="RedHatEnterpriseLinux8"/>

            - operator: contains
              value: rhel-9
              element: |
                <compatible_with_distro arch="{{ ENVIRONMENT.hw.arch }}" osmajor="RedHatEnterpriseLinux9"/>
      virtualization:
        is_virtualized:
          translations:
              - operator: '=='
                value: false
                element: '<system><hypervisor op="==" value="" /></system>'

              - operator: '=='
                value: true
                element: '<system><hypervisor op="!=" value="" /></system>'
        hypervisor:
          translations:
              - operator: '=='
                value: kvm
                element: '<system><hypervisor op="==" value="KVM" /></system>'

              - operator: '!='
                value: kvm
                element: '<system><hypervisor op="!=" value="KVM" /></system>'

              - operator: '=='
                value: xen
                element: '<system><hypervisor op="==" value="XEN" /></system>'

              - operator: '!='
                value: xen
                element: '<system><hypervisor op="!=" value="XEN" /></system>'

              - operator: '=='
                value: powerkvm
                element: '<system><hypervisor op="==" value="PowerKVM" /></system>'

              - operator: '!='
                value: powerkvm
                element: '<system><hypervisor op="!=" value="PowerKVM" /></system>'

              - operator: '=='
                value: powervm
                element: '<system><hypervisor op="==" value="PowerVM" /></system>'

              - operator: '!='
                value: powervm
                element: '<system><hypervisor op="!=" value="PowerVM" /></system>'

              - operator: '=='
                value: hyperv
                element: '<system><hypervisor op="==" value="HyperV" /></system>'

              - operator: '!='
                value: hyperv
                element: '<system><hypervisor op="!=" value="HyperV" /></system>'

              - operator: '=='
                value: vmware
                element: '<system><hypervisor op="==" value="VMWare" /></system>'

              - operator: '!='
                value: vmware
                element: '<system><hypervisor op="!=" value="VMWare" /></system>'
    """

    return tft.artemis.drivers.beaker.BeakerDriver(logger, 'beaker', parse_spec(pool_config))


@pytest.mark.parametrize(('env', 'expected'), [
    (
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose
        """,
        """
        <system>
         <arch op="==" value="x86_64"/>
        </system>
        """
    ),
    (
        """
        ---

        hw:
          arch: x86_64
          constraints:
            cpu:
              processors: 8

        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <cpu>
          <processors op="==" value="8"/>
         </cpu>
        </and>
        """
    ),
    (
        """
        ---
        hw:
          arch: x86_64
          constraints:
            network:
              - type: eth
              - type: eth
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="NR_ETH" value="2"/>
        </and>
        """
    ),
    (
        """
        ---
        hw:
          arch: x86_64
          constraints:
            network:
              - type: eth
              - type: nosuchinterface
        os:
          compose: dummy-compose
        """,
        "failure\n\n"
        "constraint: '[network[0].type == eth, network[1].type == nosuchinterface]'\n"
        "constraint_name: network[0].type\nmessage: only eth networks are supported for beaker constraints\n"
        "recoverable: true\n"
        "fail_guest_request: true"
    ),
    (
        """
        ---

        hw:
            arch: x86_64
            constraints:
                tpm:
                    version: "2.0"
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="TPM" op="==" value="2.0"/>
        </and>
        """
    ),
    (
        """
        ---

        hw:
            arch: x86_64
            constraints:
                tpm:
                    version: ">= 2"
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="TPM" op="&gt;=" value="2"/>
        </and>
        """
    ),
    (
        """
        ---
        hw:
          arch: x86_64
          constraints:
            compatible:
                distro:
                    - rhel-9
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <system>
          <compatible_with_distro arch="x86_64" osmajor="RedHatEnterpriseLinux9"/>
         </system>
        </and>
        """
    ),
    (
        """
        ---
        hw:
          arch: x86_64
          constraints:
            compatible:
                distro:
                    - rhel-8
                    - rhel-9
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <and>
          <system>
           <compatible_with_distro arch="x86_64" osmajor="RedHatEnterpriseLinux8"/>
          </system>
          <system>
           <compatible_with_distro arch="x86_64" osmajor="RedHatEnterpriseLinux9"/>
          </system>
         </and>
        </and>
        """
    ),
    (
        """
        ---
        hw:
          arch: x86_64
          constraints:
            boot:
              method: bios
            network:
              - type: eth
              - type: eth
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <and>
          <key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/>
          <key_value key="NR_ETH" value="2"/>
         </and>
        </and>
        """
    ),
    (
        """
        hw:
            arch: "x86_64"
            constraints:
                boot:
                    method: bios
                compatible:
                    distro:
                        - rhel-7
                        - rhel-8
                cpu:
                    # sockets: 1
                    cores: 2
                    # threads: 8
                    cores-per-thread: 2
                    # threads-per-core: 4
                    processors: 8
                    model: 62
                    model-name: "Haswell"
                    family: 6
                    # family-name: Skylake
                disk:
                    - size: 40 GiB
                    - size: 120 GiB
                memory: 8 GiB
                network:
                    - type: eth
                    - type: eth
                tpm:
                    version: "2.0"
                virtualization:
                    # is-supported: true
                    is-virtualized: false
                    hypervisor: xen
        os:
          compose: dummy-compose
        """,
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <and>
          <key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/>
          <and>
           <system>
            <compatible_with_distro arch="x86_64" osmajor="RedHatEnterpriseLinux7"/>
           </system>
           <system>
            <compatible_with_distro arch="x86_64" osmajor="RedHatEnterpriseLinux8"/>
           </system>
          </and>
          <and>
           <cpu>
            <processors op="==" value="8"/>
           </cpu>
           <cpu>
            <cores op="==" value="2"/>
           </cpu>
           <cpu>
            <model op="==" value="62"/>
           </cpu>
           <cpu>
            <family op="==" value="6"/>
           </cpu>
           <cpu>
            <model_name op="==" value="Haswell"/>
           </cpu>
          </and>
          <system>
           <memory op="==" value="8192"/>
          </system>
          <and>
           <disk>
            <size op="==" value="42949672960"/>
           </disk>
           <disk>
            <size op="==" value="128849018880"/>
           </disk>
          </and>
          <key_value key="NR_ETH" value="2"/>
          <key_value key="TPM" op="==" value="2.0"/>
          <and>
           <system>
            <hypervisor op="==" value=""/>
           </system>
           <system>
            <hypervisor op="==" value="XEN"/>
           </system>
          </and>
         </and>
        </and>
        """
    )
], ids=[
    'simple-arch',
    'cpu.processors',
    'multiple-nics',
    'multiple-nics-bad-interface',
    'tpm-2.0',
    'tpm-at-least-2',
    'compatible-single',
    'compatible-multiple',
    'multiple-nics-and-bios',
    'maximal-constraint'
])
def test_environment_to_beaker_filter(
    dummy_guest_request: MagicMock,
    pool: tft.artemis.drivers.beaker.BeakerDriver,
    env: str,
    expected: str
) -> None:
    environment = parse_env(env)

    r_beaker_filter = tft.artemis.drivers.beaker.environment_to_beaker_filter(environment, dummy_guest_request, pool)

    should_fail = expected.startswith('failure')
    if not should_fail:
        assert r_beaker_filter.is_ok
        beaker_filter = r_beaker_filter.unwrap()
    else:
        beaker_filter = r_beaker_filter.unwrap_error()

    if isinstance(beaker_filter, tft.artemis.Failure):
        assert str(beaker_filter) == expected

    else:
        assert beaker_filter.prettify() == textwrap.dedent(expected).strip()


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


@pytest.mark.parametrize(('avoid_hostnames', 'expected'), [
    (
        [],
        '<and/>'
    ),
    (
        ['dummy-hostname-1', 'dummy-hostname-2', 'dummy-hostname-3'],
        '<and><hostname op="!=" value="dummy-hostname-1"/><hostname op="!=" value="dummy-hostname-2"/><hostname op="!=" value="dummy-hostname-3"/></and>'  # noqa: E501
    )
], ids=[
    'no-hostnames',
    'with-avoid-hostnames'
])
def test_hostnames_to_beaker_filter(avoid_hostnames: List[str], expected: str) -> None:
    r_beaker_filter = tft.artemis.drivers.beaker.hostnames_to_beaker_filter(avoid_hostnames)

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


@pytest.mark.parametrize(('env', 'avoid_groups', 'avoid_hostnames', 'expected'), [
    (
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose
        """,
        [],
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
        [],
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <system>
          <memory op="&gt;=" value="8192"/>
         </system>
        </and>
        """
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
        ['dummy-hostname-1', 'dummy-hostname-2'],
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <system>
          <memory op="&gt;=" value="8192"/>
         </system>
         <group op="!=" value="dummy-group-1"/>
         <group op="!=" value="dummy-group-2"/>
         <hostname op="!=" value="dummy-hostname-1"/>
         <hostname op="!=" value="dummy-hostname-2"/>
        </and>
        """
    ),
    (
        """
        ---

        hw:
          arch: x86_64
          constraints:
            hostname: dummy.host.com

        os:
          compose: dummy-compose
        """,
        [],
        [],
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <hostname op="==" value="dummy.host.com"/>
        </and>
        """
    ),
    (
        """
        ---

        hw:
          arch: x86_64
          constraints:
            hostname: '=~ dummy..*.com'

        os:
          compose: dummy-compose
        """,
        [],
        [],
        """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <hostname op="like" value="dummy.%.com"/>
        </and>
        """
    )
], ids=[
    'simple-arch',
    'arch-and-constraints',
    'arch-and-constraints-and-avoid-groups-and-hostnames',
    'hostname',
    'hostname-match'
])
def test_create_beaker_filter(
    dummy_guest_request: MagicMock,
    pool: tft.artemis.drivers.beaker.BeakerDriver,
    env: str,
    avoid_groups: List[str],
    avoid_hostnames: List[str],
    expected: Optional[str]
) -> None:
    environment = parse_env(env)

    r_filter = tft.artemis.drivers.beaker.create_beaker_filter(
        environment,
        dummy_guest_request,
        pool,
        avoid_groups,
        avoid_hostnames
    )

    assert r_filter.is_ok

    filter = r_filter.unwrap()

    if filter is None:
        assert filter is expected

    else:
        assert expected

        assert filter.prettify() == textwrap.dedent(expected).strip()


@pytest.mark.parametrize(('pool_config', 'expected'), [
    (
        {},
        []
    ),
    (
        {
            'avoid-groups': ['dummy-group-1', 'dummy-group-2']
        },
        ['dummy-group-1', 'dummy-group-2']
    )
], ids=[
    'no-groups',
    'with-groups'
])
def test_avoid_groups(logger: ContextAdapter, pool_config: Dict[str, Any], expected: List[str]) -> None:
    pool = tft.artemis.drivers.beaker.BeakerDriver(logger, 'beaker', pool_config)

    r_avoid_groups = pool.avoid_groups

    assert r_avoid_groups.is_ok
    assert r_avoid_groups.unwrap() == expected


@pytest.mark.parametrize(('cached_data', 'expected'), [
    (
        {},
        []
    ),
    (
        {
            'group-1': tft.artemis.drivers.beaker.AvoidGroupHostnames(
                'group-1',
                ['dummy-hostname-1', 'dummy-hostname-2']
            ),
            'group-2': tft.artemis.drivers.beaker.AvoidGroupHostnames(
                'group-2',
                ['dummy-hostname-2']
            )
        },
        ['dummy-hostname-1', 'dummy-hostname-2', 'dummy-hostname-2']
    )
], ids=[
    'no-groups',
    'with-groups'
])
def test_avoid_hostnames(
    logger: ContextAdapter,
    mockpatch: MockPatcher,
    cached_data: Dict[str, tft.artemis.drivers.beaker.AvoidGroupHostnames],
    expected: List[str]
) -> None:
    pool = tft.artemis.drivers.beaker.BeakerDriver(logger, 'beaker', cached_data)
    mockpatch(pool, 'get_avoid_groups_hostnames').return_value = Ok(cached_data)

    r_avoid_hostnames = pool.avoid_hostnames

    if r_avoid_hostnames.is_error:
        r_avoid_hostnames.unwrap_error().handle(logger)

    assert r_avoid_hostnames.is_ok
    assert r_avoid_hostnames.unwrap() == expected
