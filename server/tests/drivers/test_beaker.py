# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import textwrap
from typing import Any, Optional
from unittest.mock import MagicMock

import bs4
import gluetool.utils
import pytest
import sqlalchemy.orm.session
from gluetool.log import ContextAdapter
from gluetool.result import Ok

import tft_artemis
import tft_artemis.drivers
import tft_artemis.drivers.beaker
import tft_artemis.environment

from .. import MockPatcher


def parse_spec(text: str) -> Any:
    return gluetool.utils.from_yaml(textwrap.dedent(text))


def parse_env(text: str) -> tft_artemis.environment.Environment:
    return tft_artemis.environment.Environment.unserialize(gluetool.utils.from_yaml(textwrap.dedent(text)))


def parse_hw(text: str) -> tft_artemis.environment.ConstraintBase:
    r_constraint = tft_artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    assert r_constraint.is_ok

    return r_constraint.unwrap()


@pytest.fixture(name='dummy_guest_request')
def fixture_dummy_guest_request(name: str = 'dummy_guest_request') -> MagicMock:
    environment = tft_artemis.environment.Environment(
        hw=tft_artemis.environment.HWRequirements(arch='x86_64'),
        os=tft_artemis.environment.OsRequirements(compose='dummy-compose'),
        kickstart=tft_artemis.environment.Kickstart(),
    )

    return MagicMock(
        name=name,
        guestname='dummy_guest',
        environment=environment,
        serialize=lambda: {
            'name': name,
            'guestname': 'dummy_guest',
            'environment': environment.serialize(),
        },
    )


@pytest.fixture(name='dummy_image_info')
def fixture_dummy_image_info(name: str = 'dummy-compose', variant: str = 'dummy-variant') -> MagicMock:
    mock = MagicMock(
        name=name,
        id=name,
        arch=None,
        boot=tft_artemis.environment.FlavorBoot(),
        ssh=tft_artemis.drivers.PoolImageSSHInfo(),
        supports_kickstart=True,
        variant=variant,
        bootc_image=None,
        serialize=lambda: {
            'name': name,
            'id': name,
            'arch': None,
            'supports_kickstart': True,
            'variant': variant,
            'bootc_image': None,
        },
    )

    return mock


@pytest.fixture(name='pool')
def fixture_pool(logger: ContextAdapter) -> tft_artemis.drivers.beaker.BeakerDriver:
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
        is_supported:
          translations:
              - operator: '=='
                value: false
                element: '<not><and><key_value key="HVM" op="=" value="1"/><system_type value="Machine"/></and></not>'

              - operator: '=='
                value: true
                element: '<and><key_value key="HVM" op="=" value="1"/><system_type value="Machine"/></and>'
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
      iommu:
        model_name:
          translations:
            - operator: '=='
              value: intel
              element: |
                <and>
                 <system><hypervisor op="==" value="" /></system>
                 <cpu><vendor op="==" value="GenuineIntel" /></cpu>
                </and>

            - operator: '=='
              value: amd
              element: |
                <and>
                 <system><hypervisor op="==" value="" /></system>
                 <cpu><vendor op="==" value="AuthenticAMD" /></cpu>
                </and>
    """

    return tft_artemis.drivers.beaker.BeakerDriver(logger, 'beaker', parse_spec(pool_config))


@pytest.mark.parametrize(
    ('env', 'expected'),
    [
        (
            """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose

        kickstart: {}
        """,
            """
        <system>
         <arch op="==" value="x86_64"/>
        </system>
        """,
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
        kickstart: {}
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
        """,
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
              - type: eth
        os:
          compose: dummy-compose
        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="NR_ETH" op="&gt;=" value="3"/>
        </and>
        """,
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
        kickstart: {}
        """,
            'failure\n\n'
            "constraint: '[network[1].type == nosuchinterface]'\n"
            'constraint_name: network[1].type\nmessage: only eth networks are supported for beaker constraints\n'
            'recoverable: true\n'
            'fail_guest_request: true',
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
        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="TPM" op="==" value="2.0"/>
        </and>
        """,
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
        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="TPM" op="&gt;=" value="2"/>
        </and>
        """,
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
        kickstart: {}
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
        """,
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
        kickstart: {}
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
        """,
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

        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <and>
          <key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/>
          <key_value key="NR_ETH" op="&gt;=" value="2"/>
         </and>
        </and>
        """,
        ),
        (
            """
        ---
        hw:
          arch: x86_64
          constraints:
            system:
              model-name: "Power9"
        os:
          compose: dummy-compose
        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <system>
          <model op="==" value="Power9"/>
         </system>
        </and>
        """,
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
                    flag:
                      - avx
                      - avx2
                      - "!= smep"
                    vendor-name: GenuineIntel
                disk:
                    - size: 40 GiB
                    - size: 120 GiB
                memory: 8 GiB
                network:
                    - type: eth
                    - type: eth
                tpm:
                    version: "2.0"
                beaker:
                    pool: "kernel-hw"
                    panic-watchdog: true
                virtualization:
                    is-supported: true
                    is-virtualized: false
                    hypervisor: xen
                iommu:
                    is-supported: true
                    model-name: intel
        os:
          compose: dummy-compose

        kickstart: {}
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
           <cpu>
            <vendor op="==" value="GenuineIntel"/>
           </cpu>
           <and>
            <cpu>
             <flag op="==" value="avx"/>
            </cpu>
            <cpu>
             <flag op="==" value="avx2"/>
            </cpu>
            <cpu>
             <flag op="!=" value="smep"/>
            </cpu>
           </and>
          </and>
          <system>
           <memory op="==" value="8192"/>
          </system>
          <and>
           <and>
            <disk>
             <size op="==" value="42949672960"/>
            </disk>
            <key_value key="NR_DISKS" op="&gt;=" value="2"/>
           </and>
           <and>
            <disk>
             <size op="==" value="128849018880"/>
            </disk>
            <key_value key="NR_DISKS" op="&gt;=" value="2"/>
           </and>
          </and>
          <and>
           <and>
            <system>
             <hypervisor op="==" value=""/>
            </system>
            <cpu>
             <vendor op="==" value="GenuineIntel"/>
            </cpu>
           </and>
           <key_value key="VIRT_IOMMU" op="==" value="1"/>
          </and>
          <key_value key="NR_ETH" op="&gt;=" value="2"/>
          <key_value key="TPM" op="==" value="2.0"/>
          <and>
           <system>
            <hypervisor op="==" value=""/>
           </system>
           <and>
            <key_value key="HVM" op="=" value="1"/>
            <system_type value="Machine"/>
           </and>
           <system>
            <hypervisor op="==" value="XEN"/>
           </system>
          </and>
          <pool value="kernel-hw"/>
         </and>
        </and>
        """,
        ),
        (
            """
        ---
        hw:
          arch: x86_64
          constraints:
            device:
              driver: ahci
        os:
          compose: dummy-compose

        kickstart: {}
        """,
            """
        <and>
         <system>
          <arch op="==" value="x86_64"/>
         </system>
         <key_value key="MODULE" op="==" value="ahci"/>
        </and>
        """,
        ),
    ],
    ids=[
        'simple-arch',
        'cpu.processors',
        'multiple-nics',
        'multiple-nics-bad-interface',
        'tpm-2.0',
        'tpm-at-least-2',
        'compatible-single',
        'compatible-multiple',
        'multiple-nics-and-bios',
        'system.model-name',
        'maximal-constraint',
        'device-driver',
    ],
)
def test_environment_to_beaker_filter(
    dummy_guest_request: MagicMock, pool: tft_artemis.drivers.beaker.BeakerDriver, env: str, expected: str
) -> None:
    environment = parse_env(env)

    r_beaker_filter = tft_artemis.drivers.beaker.environment_to_beaker_filter(environment, dummy_guest_request, pool)

    should_fail = expected.startswith('failure')
    if not should_fail:
        assert r_beaker_filter.is_ok
        beaker_filter = r_beaker_filter.unwrap()
    else:
        beaker_filter = r_beaker_filter.unwrap_error()

    if isinstance(beaker_filter, tft_artemis.Failure):
        assert str(beaker_filter) == expected

    else:
        assert beaker_filter.prettify().strip() == textwrap.dedent(expected).strip()


@pytest.mark.parametrize(
    ('avoid_groups', 'expected'),
    [
        ([], '<and/>'),
        (
            ['dummy-group-1', 'dummy-group-2', 'dummy-group-3'],
            '<and><group op="!=" value="dummy-group-1"/><group op="!=" value="dummy-group-2"/><group op="!=" value="dummy-group-3"/></and>',  # noqa: E501
        ),
    ],
    ids=['no-avoid-group', 'avoid-groups'],
)
def test_groups_to_beaker_filter(avoid_groups: list[str], expected: str) -> None:
    r_beaker_filter = tft_artemis.drivers.beaker.groups_to_beaker_filter(avoid_groups)

    assert r_beaker_filter.is_ok

    beaker_filter = r_beaker_filter.unwrap()

    assert str(beaker_filter) == expected


@pytest.mark.parametrize(
    ('avoid_hostnames', 'expected'),
    [
        ([], '<and/>'),
        (
            ['dummy-hostname-1', 'dummy-hostname-2', 'dummy-hostname-3'],
            '<and><hostname op="!=" value="dummy-hostname-1"/><hostname op="!=" value="dummy-hostname-2"/><hostname op="!=" value="dummy-hostname-3"/></and>',  # noqa: E501
        ),
    ],
    ids=['no-hostnames', 'with-avoid-hostnames'],
)
def test_hostnames_to_beaker_filter(avoid_hostnames: list[str], expected: str) -> None:
    r_beaker_filter = tft_artemis.drivers.beaker.hostnames_to_beaker_filter(avoid_hostnames)

    assert r_beaker_filter.is_ok

    beaker_filter = r_beaker_filter.unwrap()

    assert str(beaker_filter) == expected


@pytest.mark.parametrize(
    ('filters', 'expected'),
    [
        ([], '<and/>'),
        (
            ['<A/>', '<B/>', '<C/>', '<and><D/><E/></and>', '<or><F/><G/></or>'],
            '<and><A/><B/><C/><D/><E/><or><F/><G/></or></and>',
        ),
        (
            ['<and><A/><B/></and>', '<C/>', '<and><D/><E/></and>', '<or><F/><G/></or>'],
            '<and><A/><B/><C/><D/><E/><or><F/><G/></or></and>',
        ),
        (
            ['<or><A/><B/></or>', '<C/>', '<and><D/><E/></and>', '<or><F/><G/></or>'],
            '<and><or><A/><B/></or><C/><D/><E/><or><F/><G/></or></and>',
        ),
    ],
    ids=['no-filters', 'filters', 'filter-with-and', 'filter-with-or'],
)
def test_merge_beaker_filters(filters: list[str], expected: str) -> None:
    r_final_filter = tft_artemis.drivers.beaker.merge_beaker_filters(
        [bs4.BeautifulSoup(a_filter, 'xml').contents[0] for a_filter in filters]
    )

    assert r_final_filter.is_ok

    final_filter = r_final_filter.unwrap()

    assert str(final_filter) == expected


@pytest.mark.parametrize(
    ('env', 'avoid_groups', 'avoid_hostnames', 'expected'),
    [
        (
            """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose

        kickstart: {}
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

        kickstart: {}
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
        """,
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

        kickstart: {}
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
        """,
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

        kickstart: {}
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
        """,
        ),
        (
            """
        ---

        hw:
          arch: x86_64
          constraints:
            hostname: '~ dummy..*.com'

        os:
          compose: dummy-compose

        kickstart: {}
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
        """,
        ),
    ],
    ids=[
        'simple-arch',
        'arch-and-constraints',
        'arch-and-constraints-and-avoid-groups-and-hostnames',
        'hostname',
        'hostname-match',
    ],
)
def test_create_beaker_filter(
    dummy_guest_request: MagicMock,
    pool: tft_artemis.drivers.beaker.BeakerDriver,
    env: str,
    avoid_groups: list[str],
    avoid_hostnames: list[str],
    expected: Optional[str],
) -> None:
    environment = parse_env(env)

    r_filter = tft_artemis.drivers.beaker.create_beaker_filter(
        environment, dummy_guest_request, pool, avoid_groups, avoid_hostnames
    )

    assert r_filter.is_ok

    filter = r_filter.unwrap()

    if filter is None:
        assert filter is expected

    else:
        assert expected

        assert filter.prettify().strip() == textwrap.dedent(expected).strip()


@pytest.mark.parametrize(
    ('pool_config', 'expected'),
    [({}, []), ({'avoid-groups': ['dummy-group-1', 'dummy-group-2']}, ['dummy-group-1', 'dummy-group-2'])],
    ids=['no-groups', 'with-groups'],
)
def test_avoid_groups(logger: ContextAdapter, pool_config: dict[str, Any], expected: list[str]) -> None:
    pool = tft_artemis.drivers.beaker.BeakerDriver(logger, 'beaker', pool_config)

    r_avoid_groups = pool.avoid_groups

    assert r_avoid_groups.is_ok
    assert r_avoid_groups.unwrap() == expected


@pytest.mark.parametrize(
    ('cached_data', 'expected'),
    [
        ({}, []),
        (
            {
                'group-1': tft_artemis.drivers.beaker.AvoidGroupHostnames(
                    'group-1', ['dummy-hostname-1', 'dummy-hostname-2']
                ),
                'group-2': tft_artemis.drivers.beaker.AvoidGroupHostnames('group-2', ['dummy-hostname-2']),
            },
            ['dummy-hostname-1', 'dummy-hostname-2', 'dummy-hostname-2'],
        ),
    ],
    ids=['no-groups', 'with-groups'],
)
def test_avoid_hostnames(
    logger: ContextAdapter,
    mockpatch: MockPatcher,
    cached_data: dict[str, tft_artemis.drivers.beaker.AvoidGroupHostnames],
    expected: list[str],
) -> None:
    pool = tft_artemis.drivers.beaker.BeakerDriver(logger, 'beaker', cached_data)
    mockpatch(pool, 'get_avoid_groups_hostnames').return_value = Ok(cached_data)

    r_avoid_hostnames = pool.avoid_hostnames

    if r_avoid_hostnames.is_error:
        r_avoid_hostnames.unwrap_error().handle(logger)

    assert r_avoid_hostnames.is_ok
    assert r_avoid_hostnames.unwrap() == expected


@pytest.mark.parametrize(
    ('env', 'expected'),
    [
        (
            """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose

        kickstart:
          kernel-options: "ksdevice=eth1"
          kernel-options-post: quiet
          script: |
            lang en_US.UTF-8
            keyboard us
          metadata: |
            "no-autopart harness=restraint"
          pre-install: |
            %pre --log=/tmp/kickstart_pre.log
            echo "Pre-install ks script"
            %end
          post-install: |
            %post --nochroot
            umount --recursive /mnt/sysimage
            %end
        """,
            [
                '--kernel-options',
                'ksdevice=eth1',
                '--kernel-options-post',
                'quiet',
                '--ks-meta',
                '"no-autopart harness=restraint"\n',
                '--ks-append',
                'lang en_US.UTF-8\nkeyboard us\n',
                '--ks-append',
                '%pre --log=/tmp/kickstart_pre.log\necho "Pre-install ks script"\n%end\n',
                '--ks-append',
                '%post --nochroot\numount --recursive /mnt/sysimage\n%end\n',
            ],
        ),
    ],
    ids=[
        'full-ks',
    ],
)
def test_bkr_ks_options(pool: tft_artemis.drivers.beaker.BeakerDriver, env: str, expected: list[str]) -> None:
    environment = parse_env(env)

    r_wow_options = tft_artemis.drivers.beaker.BeakerDriver._create_bkr_kickstart_options(pool, environment.kickstart)

    assert r_wow_options == expected


@pytest.mark.parametrize(
    ('env', 'expected'),
    [
        (
            """
        ---

        hw:
          arch: x86_64

          constraints: {}

        os:
          compose: dummy-compose

        kickstart: {}
        """,
            [
                'workflow-simple',
                '--dry-run',
                '--prettyxml',
                '--distro',
                'dummy-compose',
                '--arch',
                'x86_64',
                '--task',
                '/distribution/reservesys',
                '--taskparam',
                'RESERVETIME=86400',
                '--variant',
                'dummy-variant',
                '--ignore-panic',
                '--whiteboard',
                '[artemis] [undefined-deployment] dummy_guest',
            ],
        ),
        (
            """
        ---

        hw:
          arch: x86_64

          constraints:
            beaker:
              panic-watchdog: true

        os:
          compose: dummy-compose

        kickstart: {}
        """,
            [
                'workflow-simple',
                '--dry-run',
                '--prettyxml',
                '--distro',
                'dummy-compose',
                '--arch',
                'x86_64',
                '--task',
                '/distribution/reservesys',
                '--taskparam',
                'RESERVETIME=86400',
                '--variant',
                'dummy-variant',
                '--whiteboard',
                '[artemis] [undefined-deployment] dummy_guest',
            ],
        ),
    ],
    ids=[
        'default',
        'enable-panic-watchdog',
    ],
)
def test_bkr_wow_options(
    logger: ContextAdapter,
    mockpatch: MockPatcher,
    session: sqlalchemy.orm.session.Session,
    dummy_guest_request: MagicMock,
    dummy_image_info: MagicMock,
    pool: tft_artemis.drivers.beaker.BeakerDriver,
    env: str,
    expected: list[str],
) -> None:
    environment = parse_env(env)
    dummy_guest_request.environment = environment
    mockpatch(tft_artemis.drivers.beaker.BeakerDriver, 'get_guest_tags').return_value = Ok({})

    r_wow_options = tft_artemis.drivers.beaker.BeakerDriver._create_wow_options(
        pool, logger, session, dummy_guest_request, dummy_image_info
    )

    assert not r_wow_options.is_error

    assert r_wow_options.unwrap() == expected
