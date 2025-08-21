# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import textwrap
from typing import Any, List
from unittest.mock import MagicMock

import gluetool.utils
import pytest
from gluetool.log import ContextAdapter
from gluetool.result import Result

import tft.artemis
import tft.artemis.drivers.beaker
import tft.artemis.environment
from tft.artemis.environment import (
    UNITS,
    Constraint,
    ConstraintBase,
    Environment,
    Flavor,
    FlavorBoot,
    FlavorCompatible,
    FlavorCpu,
    FlavorNetwork,
    FlavorNetworks,
    FlavorVirtualization,
    Operator,
)


@pytest.fixture(name='schema_v0_0_19')
def fixture_schema_v0_0_19() -> tft.artemis.JSONSchemaType:
    r_schema = tft.artemis.load_packaged_validation_schema('environment-v0.0.19.yml')

    assert r_schema.is_ok

    return r_schema.unwrap()


@pytest.fixture(name='kickstart_schema')
def fixture_kickstart_schema() -> tft.artemis.JSONSchemaType:
    r_schema = tft.artemis.load_packaged_validation_schema('environment-v0.0.53.yml')

    assert r_schema.is_ok

    return r_schema.unwrap()


def parse_hw(text: str) -> ConstraintBase:
    r_constraint = tft.artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    if r_constraint.is_error:
        r_constraint.unwrap_error().handle(tft.artemis.get_logger())

    assert r_constraint.is_ok

    return r_constraint.unwrap()


def parse_spec(text: str) -> Any:
    return gluetool.utils.from_yaml(textwrap.dedent(text))


@pytest.fixture(name='dummy_guest_request')
def fixture_dummy_guest_request(name: str = 'dummy_guest_request') -> MagicMock:
    return MagicMock(
        name=name,
        environment=tft.artemis.environment.Environment(
            hw=tft.artemis.environment.HWRequirements(arch='x86_64'),
            os=tft.artemis.environment.OsRequirements(compose='dummy-compose'),
            kickstart=tft.artemis.environment.Kickstart(),
        ),
    )


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
    """

    return tft.artemis.drivers.beaker.BeakerDriver(logger, 'beaker', parse_spec(pool_config))


def _eval_flavor(
    logger: ContextAdapter, constraint: ConstraintBase, flavor: Flavor
) -> Result[bool, tft.artemis.Failure]:
    tft.artemis.log_dict_yaml(logger.debug, 'constraint', constraint.serialize())
    tft.artemis.log_dict_yaml(logger.debug, 'flavor', flavor.serialize())

    return constraint.eval_flavor(logger, flavor)


def eval_flavor(logger: ContextAdapter, constraint: ConstraintBase, flavor: Flavor) -> bool:
    r = _eval_flavor(logger, constraint, flavor)

    assert r.is_ok

    return r.unwrap()


def test_example_simple(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        memory: 8 GiB
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('8 GiB')),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('9 GiB')),
        )
        is False
    )


def test_example_cpu(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            processors: 2
            cores: 16
            model: 37
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                cpu=tft.artemis.environment.FlavorCpu(processors=2, cores=16, model=37),
            ),
        )
        is True
    )


def test_example_disk(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          - size: 500 GiB
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks([tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))]),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks([tft.artemis.environment.FlavorDisk(size=UNITS('600 GiB'))]),
            ),
        )
        is False
    )


def test_example_multiple_disks(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          - size: ">= 40 GiB"
          - size: ">= 1 TiB"
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB')),
                    ]
                ),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('20 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB')),
                    ]
                ),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB')),
                    ]
                ),
            ),
        )
        is False
    )


def test_example_disk_oldstyle_space(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          space: 500 GiB
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks([tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))]),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks([tft.artemis.environment.FlavorDisk(size=UNITS('600 GiB'))]),
            ),
        )
        is False
    )


def test_example_disks_expansion(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          - size: ">= 40 GiB"
          - size: ">= 1 TiB"
          - size: ">= 40 GiB"
          - size: ">= 40 GiB"
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(
                            is_expansion=True, max_additional_items=5, min_size=UNITS('10 GiB'), max_size=UNITS('2 TiB')
                        ),
                    ]
                ),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(
                            is_expansion=True, max_additional_items=1, min_size=UNITS('10 GiB'), max_size=UNITS('2 TiB')
                        ),
                    ]
                ),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('20 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB')),
                    ]
                ),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB')),
                    ]
                ),
            ),
        )
        is False
    )


def test_example_network(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        network:
          - type: eth
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                network=FlavorNetworks([FlavorNetwork(type='eth'), FlavorNetwork(type='wifi')]),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                network=FlavorNetworks([FlavorNetwork(type='wifi'), FlavorNetwork(type='eth')]),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', network=FlavorNetworks([FlavorNetwork(type='eth')])
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', network=FlavorNetworks([FlavorNetwork(type='wifi')])
            ),
        )
        is False
    )


def test_example_multiple_networks(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        network:
          - type: eth
          - type: wifi
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                network=FlavorNetworks([FlavorNetwork(type='eth'), FlavorNetwork(type='wifi')]),
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                network=FlavorNetworks([FlavorNetwork(type='wifi'), FlavorNetwork(type='eth')]),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                network=FlavorNetworks([FlavorNetwork(type='eth'), FlavorNetwork(type='eth')]),
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', network=FlavorNetworks([FlavorNetwork(type='eth')])
            ),
        )
        is False
    )


def test_example_boot(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        boot:
          method: bios
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['bios'])),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['uefi'])),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot()),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['bios', 'uefi'])
            ),
        )
        is True
    )


def test_example_boot_not(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        boot:
          method: "!= bios"
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['bios'])),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['uefi'])),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot()),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', boot=FlavorBoot(method=['bios', 'uefi'])
            ),
        )
        is False
    )


def test_example_compatible(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        compatible:
          distro:
            - rhel-8
            - rhel-9
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', compatible=FlavorCompatible(distro=['rhel-8', 'rhel-9'])
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', compatible=FlavorCompatible(distro=['rhel-9'])
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', compatible=FlavorCompatible(distro=[])
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', compatible=FlavorCompatible(distro=['rhel-9', 'rhel-8'])
            ),
        )
        is True
    )


def test_example_compatible_oneline(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        compatible:
          distro:
            - rhel-9
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', compatible=FlavorCompatible(distro=['rhel-9'])
            ),
        )
        is True
    )


def test_example_virtualization_is_virtualized(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        virtualization:
          is-virtualized: true
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(is_virtualized=True)
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(is_virtualized=False)
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization()
            ),
        )
        is False
    )


def test_example_virtualization_is_supported(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        virtualization:
          is-supported: true
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(is_supported=True)
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(is_supported=False)
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization()
            ),
        )
        is False
    )


def test_example_virtualization_hypervisor(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        virtualization:
          hypervisor: xen
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(hypervisor='xen')
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization(hypervisor='kvm')
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', virtualization=FlavorVirtualization()
            ),
        )
        is False
    )


def test_example_operators(logger: ContextAdapter) -> None:
    flavor_big = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('9 GiB'))

    flavor_right = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('8 GiB'))

    flavor_small = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('7 GiB'))

    constraint = parse_hw(
        """
        ---

        memory: '> 8 GiB'
        """
    )

    assert eval_flavor(logger, constraint, flavor_big) is True
    assert eval_flavor(logger, constraint, flavor_right) is False
    assert eval_flavor(logger, constraint, flavor_small) is False

    constraint = parse_hw(
        """
        ---

        memory: '>= 8 GiB'
        """
    )

    assert eval_flavor(logger, constraint, flavor_big) is True
    assert eval_flavor(logger, constraint, flavor_right) is True
    assert eval_flavor(logger, constraint, flavor_small) is False

    constraint = parse_hw(
        """
        ---

        memory: "< 8 GiB"
        """
    )

    assert eval_flavor(logger, constraint, flavor_big) is False
    assert eval_flavor(logger, constraint, flavor_right) is False
    assert eval_flavor(logger, constraint, flavor_small) is True

    constraint = parse_hw(
        """
        ---

        memory: '<= 8 GiB'
        """
    )

    assert eval_flavor(logger, constraint, flavor_big) is False
    assert eval_flavor(logger, constraint, flavor_right) is True
    assert eval_flavor(logger, constraint, flavor_small) is True


def test_example_exact_value(logger: ContextAdapter) -> None:
    constraint1 = parse_hw(
        """
        ---

        memory: 8 GiB
        """
    )

    constraint2 = parse_hw(
        """
        ---

        memory: '= 8 GiB'
        """
    )

    assert repr(constraint1) == repr(constraint2)


def test_example_unit_with_space() -> None:
    constraint1 = parse_hw(
        """
        ---

        memory: '8GiB'
        """
    )

    constraint2 = parse_hw(
        """
        ---

        memory: '8 GiB'
        """
    )

    assert repr(constraint1) == repr(constraint2)


def test_example_units_conversion(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        memory: 8192 MiB
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', memory=UNITS('8 GiB')),
        )
        is True
    )


def test_example_regex(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            model-name: "~ .*AMD.*"
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(model_name='someAMDmodel')
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                cpu=tft.artemis.environment.FlavorCpu(model_name='someIntelmodel'),
            ),
        )
        is False
    )


def test_example_logic(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        and:
            - cpu:
                family: 15
            - or:
                - cpu:
                        model: 65
                - cpu:
                        model: 67
                - cpu:
                        model: 69
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=15, model=65)
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=15, model=67)
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=15, model=69)
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=15, model=70)
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=17, model=65)
            ),
        )
        is False
    )


def test_clueless_flavor(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            family: 79
            model-name: AMD
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                cpu=tft.artemis.environment.FlavorCpu(family=79, model_name=None),
            ),
        )
        is False
    )


def test_missing_hw_constraints(logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64
          constraints:

        os:
          compose: dummy-compose

        kickstart: {}
        """
    )

    environment = Environment.unserialize(spec)

    assert environment.has_hw_constraints is False

    r_constraints = environment.get_hw_constraints()

    assert r_constraints.is_ok
    assert r_constraints.unwrap() is None


def test_empty_hw_constraints(logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64
          constraints: {}

        os:
          compose: dummy-compose

        kickstart: {}
        """
    )

    environment = Environment.unserialize(spec)

    assert environment.has_hw_constraints is False

    r_constraints = environment.get_hw_constraints()

    assert r_constraints.is_ok
    assert r_constraints.unwrap() is None


def test_cpu_flags(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            flag:
              - avx
              - avx2
              - "!= smep"
        """
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(flag=[])
            ),
        )
        is False
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(flag=['avx', 'avx2'])
            ),
        )
        is True
    )

    assert (
        eval_flavor(
            logger,
            constraint,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                cpu=tft.artemis.environment.FlavorCpu(flag=['avx', 'avx2', 'smep']),
            ),
        )
        is False
    )


def test_schema_no_constraints_v0_0_19(schema_v0_0_19: tft.artemis.JSONSchemaType, logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose
        """
    )

    r_validation = tft.artemis.validate_data(spec, schema_v0_0_19)

    assert r_validation.is_ok

    errors = r_validation.unwrap()

    assert errors == []


def test_schema_simple_v0_0_19(schema_v0_0_19: tft.artemis.JSONSchemaType, logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64
          constraints:
            memory: 8192000
            disk:
              space: ">= 120 GiB"

        os:
          compose: dummy-compose
        """
    )

    r_validation = tft.artemis.validate_data(spec, schema_v0_0_19)

    assert r_validation.is_ok

    errors = r_validation.unwrap()

    assert errors == []


def test_schema_logic_v0_0_19(schema_v0_0_19: tft.artemis.JSONSchemaType, logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64
          constraints:
            and:
              - memory: 8192000
                disk:
                  space: ">= 120 GiB"
              - or:
                - cpu:
                    model: 65
                - cpu:
                    model: 67
                - cpu:
                    model: 69

        os:
          compose: dummy-compose
        """
    )

    r_validation = tft.artemis.validate_data(spec, schema_v0_0_19)

    assert r_validation.is_ok

    errors = r_validation.unwrap()

    assert errors == []


def test_parse_maximal_constraint() -> None:
    _ = parse_hw("""
        ---

        arch: "x86_64"
        constraints:
            boot:
                method: bios
            compatible:
                distro:
                    - rhel-7
                    - rhel-8
            cpu:
                sockets: 1
                cores: 2
                threads: 8
                cores-per-thread: 2
                threads-per-core: 4
                processors: 8
                model: 62
                model-name: "Haswell"
                family: 6
                family-name: Skylake
                flag:
                  - avx
                  - avx2
                  - "!= smep"
            disk:
                - size: 40 GiB
                - size: 120 GiB
                - model-name: "PERC H310"
            gpu:
                 device: 1
                 device-name: "AMD Radeon Pro V520 GPUs"
                 vendor: 2
                 vendor-name: "AMD"
                 driver: amd
            memory: 8 GiB
            network:
                - type: eth
                - type: eth
            system:
                vendor: 0x413C
                vendor-name: "~ Dell.*"
                model: 79
                model-name: "~ PowerEdge R750"
                numa-nodes: "< 4"
            tpm:
                version: "2.0"
            virtualization:
                is-supported: true
                is-virtualized: false
                hypervisor: xen
            zcrypt:
                adapter: CEX8C
                mode: CCA
            beaker:
                pool: kernel-hw
        """)


@pytest.mark.parametrize(
    ('hw', 'expected'),
    [
        (
            """
        ---

        arch: "ppc64"
        constraints:
            and:
              - cpu:
                  model: ">= 5111808"
              - cpu:
                  model: "<= 5177343"
        """,
            '<and><system><arch op="==" value="ppc64"/></system><and><cpu><model op="&gt;=" value="5111808"/></cpu><cpu><model op="&lt;=" value="5177343"/></cpu></and></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: "ppc64"
        constraints:
            cpu:
              model-name: "~ .*PPC970.*"
        """,
            '<and><system><arch op="==" value="ppc64"/></system><cpu><model_name op="like" value="%PPC970%"/></cpu></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: "x86_64"
        constraints:
            disk:
              - size: ">= 60 GiB"
        """,
            '<and><system><arch op="==" value="x86_64"/></system><and><disk><size op="&gt;=" value="64424509440"/></disk><key_value key="NR_DISKS" op="&gt;=" value="1"/></and></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: "x86_64"
        constraints:
            disk:
              - model-name: "PERC H310"
        """,
            '<and><system><arch op="==" value="x86_64"/></system><disk><model op="==" value="PERC H310"/></disk></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: x86_64
        constraints:
            boot:
                method: bios
        """,
            '<and><system><arch op="==" value="x86_64"/></system><key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: x86_64
        constraints:
            boot:
                method: uefi
        """,
            '<and><system><arch op="==" value="x86_64"/></system><key_value key="NETBOOT_METHOD" op="=" value="efigrub"/></and>',  # noqa: E501
        ),
        (
            """
        ---

        arch: x86_64
        constraints:
            boot:
                method: "!= uefi"
        """,
            '<and><system><arch op="==" value="x86_64"/></system><key_value key="NETBOOT_METHOD" op="!=" value="efigrub"/></and>',  # noqa: E501
        ),
    ],
    ids=[
        'IBM__POWER9',
        'IBM__POWER_PPC970',
        'DISK__SIZE_MIN_60G',
        'DISK__MODEL_NAME',
        'NETBOOT_LEGACY',
        'NETBOOT_UEFI',
        'not NETBOOT_UEFI',
    ],
)
def test_beaker_preset(
    dummy_guest_request: MagicMock,
    logger: ContextAdapter,
    pool: tft.artemis.drivers.beaker.BeakerDriver,
    hw: str,
    expected: str,
) -> None:
    spec = parse_spec(
        """
        ---

        hw: {}

        os:
          compose: dummy-compose

        kickstart: {}
        """
    )

    spec['hw'] = parse_spec(hw)

    environment = Environment.unserialize(spec)

    r_constraints = environment.get_hw_constraints()

    assert r_constraints.is_ok

    r_host_filter = tft.artemis.drivers.beaker.environment_to_beaker_filter(environment, dummy_guest_request, pool)

    if r_host_filter.is_error:
        r_host_filter.unwrap_error().handle(logger)

        assert False, 'host filter failed'

    assert r_host_filter.is_ok

    host_filter = r_host_filter.unwrap()

    assert str(host_filter) == expected


@pytest.mark.parametrize(
    ('hw', 'flavor', 'expected_spans'),
    [
        (
            """
        ---

        and:
            - cpu:
                family: 15
            - or:
                - cpu:
                        model: 65
                - cpu:
                        model: 67
                - cpu:
                        model: 69
        """,
            tft.artemis.environment.Flavor(
                name='dummy-flavor', id='dummy-flavor', cpu=tft.artemis.environment.FlavorCpu(family=15, model=65)
            ),
            [['cpu.model == 65', 'cpu.family == 15']],
        ),
        (
            """
        ---

        and:
            - or:
              - disk:
                  - size: ">= 11 GiB"

              - disk:
                  - size: ">= 13 GiB"

            - or:
              - disk:
                  - size: ">= 40 GiB"
                  - size: ">= 1 TiB"

              - disk:
                  - size: ">= 40 GiB"
                  - size: "< 2 TiB"

              - or:
                - cpu:
                    processors: ">=4"

                - memory: "= 8 GiB"

                - disk:
                    - size: ">= 40 GiB"

                - and:
                    - disk:
                        - size: ">= 40 GiB"

                    - memory: "= 16 GiB"

                - and:
                    - disk:
                        - size: ">= 10 GiB"

                    - disk:
                        - size: ">= 20 GiB"

                - or:
                    - cpu:
                        processors: ">= 2"

                    - cpu:
                        processors: ">= 3"
        """,
            tft.artemis.environment.Flavor(
                name='dummy-flavor',
                id='dummy-flavor',
                cpu=FlavorCpu(processors=8),
                disk=tft.artemis.environment.FlavorDisks(
                    [
                        tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                        tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB')),
                    ]
                ),
            ),
            [
                ['disk[0].size >= 11 gibibyte', 'disk[0].size >= 40 gibibyte', 'disk[1].size >= 1 tebibyte'],
                ['disk[0].size >= 11 gibibyte', 'disk[0].size >= 40 gibibyte', 'disk[1].size < 2 tebibyte'],
                ['disk[0].size >= 11 gibibyte', 'cpu.processors >= 4'],
                ['disk[0].size >= 11 gibibyte', 'disk[0].size >= 40 gibibyte'],
                ['disk[0].size >= 11 gibibyte', 'disk[0].size >= 10 gibibyte', 'disk[0].size >= 20 gibibyte'],
                ['disk[0].size >= 11 gibibyte', 'cpu.processors >= 2'],
                ['disk[0].size >= 11 gibibyte', 'cpu.processors >= 3'],
                ['disk[0].size >= 13 gibibyte', 'disk[0].size >= 40 gibibyte', 'disk[1].size >= 1 tebibyte'],
                ['disk[0].size >= 13 gibibyte', 'disk[0].size >= 40 gibibyte', 'disk[1].size < 2 tebibyte'],
                ['disk[0].size >= 13 gibibyte', 'cpu.processors >= 4'],
                ['disk[0].size >= 13 gibibyte', 'disk[0].size >= 40 gibibyte'],
                ['disk[0].size >= 13 gibibyte', 'disk[0].size >= 10 gibibyte', 'disk[0].size >= 20 gibibyte'],
                ['disk[0].size >= 13 gibibyte', 'cpu.processors >= 2'],
                ['disk[0].size >= 13 gibibyte', 'cpu.processors >= 3'],
            ],
        ),
    ],
    ids=['SPANS1', 'SPANS2'],
)
def test_spans(
    logger: ContextAdapter, hw: str, flavor: tft.artemis.environment.Flavor, expected_spans: List[List[str]]
) -> None:
    constraint = parse_hw(hw)

    assert eval_flavor(logger, constraint, flavor) is True

    r_pruned_constraint = constraint.prune_on_flavor(logger, flavor)

    assert r_pruned_constraint.is_ok

    pruned_constraint = r_pruned_constraint.unwrap()

    assert pruned_constraint is not None

    spans = [[str(constraint) for constraint in span] for span in pruned_constraint.spans(logger)]

    assert spans == expected_spans


def test_missing_flavor_attribute(logger: ContextAdapter) -> None:
    constraint = tft.artemis.environment.Constraint.from_specification('foo', '> 1 GiB')

    flavor = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor')

    r = _eval_flavor(logger, constraint, flavor)

    assert r.is_error
    assert r.unwrap_error().message == 'unknown flavor property'
    assert r.unwrap_error().details['property'] == 'foo'


def test_reducer_short_circuit_and(logger: ContextAdapter) -> None:
    group = tft.artemis.environment.And(
        [
            tft.artemis.environment.Constraint.from_specification('cpu.processors', '> 1'),
            tft.artemis.environment.Constraint.from_specification('foo', '> 1 GiB'),
        ]
    )

    flavor = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', cpu=FlavorCpu(processors=8))

    r = _eval_flavor(logger, group, flavor)

    assert r.is_error
    assert r.unwrap_error().message == 'unknown flavor property'
    assert r.unwrap_error().details['property'] == 'foo'


def test_reducer_short_circuit_ok(logger: ContextAdapter) -> None:
    group = tft.artemis.environment.Or(
        [
            tft.artemis.environment.Constraint.from_specification('cpu.processors', '> 1'),
            tft.artemis.environment.Constraint.from_specification('foo', '> 1 GiB'),
        ]
    )

    flavor = tft.artemis.environment.Flavor(name='dummy-flavor', id='dummy-flavor', cpu=FlavorCpu(processors=8))

    r = _eval_flavor(logger, group, flavor)

    assert r.is_ok
    assert r.unwrap() is True


@pytest.mark.parametrize(
    ('constraint_name', 'expected'),
    [
        ('arch', ('arch', None, None, 'arch')),
        ('boot.method', ('boot', None, 'method', 'boot.method')),
        ('disk[79].size', ('disk', 79, 'size', 'disk[].size')),
    ],
    ids=['arch', 'boot.method', 'disk[79].size'],
)
def test_expand_name(constraint_name: str, expected: tft.artemis.environment.ConstraintNameComponents) -> None:
    assert (
        tft.artemis.environment.Constraint(
            name=constraint_name,
            # The following don't match expected type, but they are not used by any code we're going to run.
            operator=None,  # type: ignore[arg-type]
            operator_handler=None,  # type: ignore[arg-type]
            value=tft.artemis.environment.UNITS.Quantity(1, 'gibibyte'),
            raw_value=None,  # type: ignore[arg-type]
        ).expand_name()
        == expected
    )


@pytest.mark.parametrize(
    ('hw', 'expected'),
    [
        (
            """
        ---

        hostname: foo
        """,
            True,
        ),
        (
            """
        ---

        memory: "2048 GiB"
        """,
            False,
        ),
        (
            """
        ---

        and:
          - memory: "2048 GiB"
          - cpu:
              cores: 64
          - or:
              - virtualization:
                  is-virtualized: true
              - hostname: foo
        """,
            True,
        ),
        (
            """
        ---

        and:
          - memory: "2048 GiB"
          - cpu:
              cores: 64
          - or:
              - virtualization:
                  is-virtualized: true
              - virtualization:
                  is-virtualized: false
        """,
            False,
        ),
    ],
    ids=['uses', 'does-not-use', 'uses-nested', 'does-not-use-nested'],
)
def test_uses_constraint(logger: ContextAdapter, hw: str, expected: bool) -> None:
    constraint = parse_hw(hw)

    r = constraint.uses_constraint(logger, 'hostname')

    assert r.is_ok
    assert r.unwrap() is expected


@pytest.mark.parametrize(
    ('raw_operator', 'operator'),
    [
        ('', Operator.EQ),
        ('= ', Operator.EQ),
        ('!= ', Operator.NEQ),
        ('>', Operator.GT),
        ('>=', Operator.GTE),
        ('<', Operator.LT),
        ('<=', Operator.LTE),
        ('~ ', Operator.MATCH),
        ('!~ ', Operator.NOTMATCH),
        ('contains ', Operator.CONTAINS),
        ('not contains ', Operator.NOTCONTAINS),
        ('=~ ', Operator.MATCH),
    ],
    ids=[
        'implicit-eq',
        'eq',
        'neq',
        'gt',
        'gte',
        'lt',
        'lte',
        'match',
        'not-match',
        'contains',
        'not-contains',
        'legacy-match',
    ],
)
def test_operator_parsing(logger: ContextAdapter, raw_operator: str, operator: Operator) -> None:
    constraint = Constraint.from_specification('memory', f'{raw_operator}1 GiB')

    assert constraint.operator == operator
    assert constraint.value == UNITS('1 GiB')


def test_kickstart_schema(kickstart_schema: tft.artemis.JSONSchemaType, logger: ContextAdapter) -> None:
    spec = parse_spec(
        """
        ---

        hw:
          arch: x86_64

        os:
          compose: dummy-compose

        kickstart:
          pre-install: |
            %pre --log=/tmp/kickstart_pre.log
            echo "Pre-install ks script"
            %end
          post-install: |
            %post --nochroot
            umount --recursive /mnt/sysimage
            %end
          script: |
            lang en_US.UTF-8
            keyboard us
            part /boot --fstype="ext4" --size=512
            part swap --size=4096
            part / --fstype="xfs" --size=1024 --mkfsoptions="-m crc=0 -n ftype=0" --grow
          metadata: |
            "no_autopart harness=restraint"
          kernel-options: "ksdevice=eth1"
          kernel-options-post: "quiet"
        """
    )

    expected_serialization = {
        'hw': {'arch': 'x86_64', 'constraints': None},
        'kickstart': {
            'kernel-options': 'ksdevice=eth1',
            'kernel-options-post': 'quiet',
            'metadata': '"no_autopart harness=restraint"\n',
            'post-install': '%post --nochroot\numount --recursive /mnt/sysimage\n%end\n',
            'pre-install': '%pre --log=/tmp/kickstart_pre.log\necho "Pre-install ks script"\n%end\n',
            'script': 'lang en_US.UTF-8\nkeyboard us\npart /boot --fstype="ext4" --size=512\npart swap --size=4096\npart / --fstype="xfs" --size=1024 --mkfsoptions="-m crc=0 -n ftype=0" --grow\n',  # noqa: E501
        },
        'os': {'compose': 'dummy-compose'},
        'pool': None,
        'snapshots': False,
        'spot_instance': None,
    }

    r_validation = tft.artemis.validate_data(spec, kickstart_schema)

    assert r_validation.is_ok

    errors = r_validation.unwrap()

    assert errors == []

    environment = Environment.unserialize(spec)

    assert environment.serialize() == expected_serialization
