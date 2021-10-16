import textwrap
from typing import Any, List

import gluetool.utils
import pytest
from gluetool.log import ContextAdapter, log_blob

import tft.artemis
import tft.artemis.drivers.beaker
import tft.artemis.environment
from tft.artemis.environment import UNITS, ConstraintBase, Environment, Flavor, FlavorCpu, FlavorNetwork, FlavorNetworks


@pytest.fixture(name='schema_v0_0_19')
def fixture_schema_v0_0_19() -> tft.artemis.JSONSchemaType:
    r_schema = tft.artemis.load_validation_schema('environment-v0.0.19.yml')

    assert r_schema.is_ok

    return r_schema.unwrap()


def parse_hw(text: str) -> ConstraintBase:
    r_constraint = tft.artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    assert r_constraint.is_ok

    return r_constraint.unwrap()


def parse_spec(text: str) -> Any:
    return gluetool.utils.from_yaml(textwrap.dedent(text))


def eval_flavor(
    logger: ContextAdapter,
    constraint: ConstraintBase,
    flavor: Flavor
) -> bool:
    log_blob(logger.debug, 'constraint', constraint.format())  # noqa: FS002  # intended format()
    log_blob(logger.debug, 'flavor', repr(flavor))

    return constraint.eval_flavor(logger, flavor)


def test_example_simple(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        memory: 8 GiB
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            memory=UNITS('8 GiB')
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            memory=UNITS('9 GiB')
        )
    ) is False


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

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                processors=2,
                cores=16,
                model=37
            )
        )
    ) is True


def test_example_disk(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          - size: 500 GiB
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('600 GiB'))
            ])
        )
    ) is False


def test_example_multiple_disks(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          - size: ">= 40 GiB"
          - size: ">= 1 TiB"
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB'))
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('20 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB'))
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))
            ])
        )
    ) is False


def test_example_disk_oldstyle_space(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        disk:
          space: 500 GiB
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('600 GiB'))
            ])
        )
    ) is False


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

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(
                    is_expansion=True,
                    max_additional_items=5,
                    min_size=UNITS('10 GiB'),
                    max_size=UNITS('2 TiB')
                )
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(
                    is_expansion=True,
                    max_additional_items=1,
                    min_size=UNITS('10 GiB'),
                    max_size=UNITS('2 TiB')
                )
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('20 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB'))
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('500 GiB'))
            ])
        )
    ) is False


def test_example_network(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        network:
          - type: eth
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='eth'),
                FlavorNetwork(type='wifi')
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='wifi'),
                FlavorNetwork(type='eth')
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='eth')
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='wifi')
            ])
        )
    ) is False


def test_example_multiple_networks(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        network:
          - type: eth
          - type: wifi
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='eth'),
                FlavorNetwork(type='wifi')
            ])
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='wifi'),
                FlavorNetwork(type='eth')
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='eth'),
                FlavorNetwork(type='eth')
            ])
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            network=FlavorNetworks([
                FlavorNetwork(type='eth')
            ])
        )
    ) is False


def test_example_operators(logger: ContextAdapter) -> None:
    flavor_big = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor',
        memory=UNITS('9 GiB')
    )

    flavor_right = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor',
        memory=UNITS('8 GiB')
    )

    flavor_small = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor',
        memory=UNITS('7 GiB')
    )

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

    assert constraint1.format() == constraint2.format()  # noqa: FS002  # intended format()


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

    assert constraint1.format() == constraint2.format()  # noqa: FS002  # intended format()


def test_example_units_conversion(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        memory: 8192 MiB
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            memory=UNITS('8 GiB')
        )
    ) is True


def test_example_regex(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            model_name: "=~ .*AMD.*"
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                model_name='someAMDmodel'
            )
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                model_name='someIntelmodel'
            )
        )
    ) is False


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

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=65
            )
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=67
            )
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=69
            )
        )
    ) is True

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=70
            )
        )
    ) is False

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=17,
                model=65
            )
        )
    ) is False


def test_clueless_flavor(logger: ContextAdapter) -> None:
    constraint = parse_hw(
        """
        ---

        cpu:
            family: 79
            model_name: AMD
        """
    )

    assert eval_flavor(
        logger,
        constraint,
        tft.artemis.environment.Flavor(
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=79,
                model_name=None
            )
        )
    ) is False


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


@pytest.mark.parametrize(('hw', 'expected'), [
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
        '<and><system><arch op="==" value="ppc64"/></system><and><cpu><model op="&gt;=" value="5111808"/></cpu><cpu><model op="&lt;=" value="5177343"/></cpu></and></and>'  # noqa: E501
    ),
    (
        """
        ---

        arch: "ppc64"
        constraints:
            cpu:
              model_name: "=~ .*PPC970.*"
        """,
        '<and><system><arch op="==" value="ppc64"/></system><cpu><model_name op="like" value="%PPC970%"/></cpu></and>'
    ),
    (
        """
        ---

        arch: "x86_64"
        constraints:
            disk:
              - size: ">= 60 GiB"
        """,
        '<and><system><arch op="==" value="x86_64"/></system><disk><size op="&gt;=" value="64424509440"/></disk></and>'
    )
], ids=[
    'IBM__POWER9',
    'IBM__POWER_PPC970',
    'DISK__SIZE_MIN_60G'
])
def test_beaker_preset(logger: ContextAdapter, hw: str, expected: str) -> None:
    spec = parse_spec(
        """
        ---

        hw: {}

        os:
          compose: dummy-compose
        """
    )

    spec['hw'] = parse_spec(hw)

    environment = Environment.unserialize_from_json(spec)

    r_constraints = environment.get_hw_constraints()

    assert r_constraints.is_ok

    r_host_filter = tft.artemis.drivers.beaker.environment_to_beaker_filter(environment)

    assert r_host_filter.is_ok

    host_filter = r_host_filter.unwrap()

    assert str(host_filter) == expected


@pytest.mark.parametrize(('hw', 'flavor', 'expected_spans'), [
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
            name='dummy-flavor',
            id='dummy-flavor',
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=65
            )
        ),
        [
            ['(FLAVOR.cpu.model == 65)', '(FLAVOR.cpu.family == 15)']
        ]
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
            cpu=FlavorCpu(
                processors=8
            ),
            disk=tft.artemis.environment.FlavorDisks([
                tft.artemis.environment.FlavorDisk(size=UNITS('40 GiB')),
                tft.artemis.environment.FlavorDisk(size=UNITS('1 TiB'))
            ])
        ),
        [
            [
                '(FLAVOR.disk[0].size >= 11 gibibyte)',
                '(FLAVOR.disk[0].size >= 40 gibibyte)',
                '(FLAVOR.disk[1].size >= 1 tebibyte)'
            ],
            [
                '(FLAVOR.disk[0].size >= 11 gibibyte)',
                '(FLAVOR.disk[0].size >= 40 gibibyte)',
                '(FLAVOR.disk[1].size < 2 tebibyte)'
            ],
            ['(FLAVOR.disk[0].size >= 11 gibibyte)', '(FLAVOR.cpu.processors >= 4)'],
            ['(FLAVOR.disk[0].size >= 11 gibibyte)', '(FLAVOR.disk[0].size >= 40 gibibyte)'],
            [
                '(FLAVOR.disk[0].size >= 11 gibibyte)',
                '(FLAVOR.disk[0].size >= 10 gibibyte)',
                '(FLAVOR.disk[0].size >= 20 gibibyte)'
            ],
            ['(FLAVOR.disk[0].size >= 11 gibibyte)', '(FLAVOR.cpu.processors >= 2)'],
            ['(FLAVOR.disk[0].size >= 11 gibibyte)', '(FLAVOR.cpu.processors >= 3)'],
            [
                '(FLAVOR.disk[0].size >= 13 gibibyte)',
                '(FLAVOR.disk[0].size >= 40 gibibyte)',
                '(FLAVOR.disk[1].size >= 1 tebibyte)'
            ],
            [
                '(FLAVOR.disk[0].size >= 13 gibibyte)',
                '(FLAVOR.disk[0].size >= 40 gibibyte)',
                '(FLAVOR.disk[1].size < 2 tebibyte)'
            ],
            ['(FLAVOR.disk[0].size >= 13 gibibyte)', '(FLAVOR.cpu.processors >= 4)'],
            ['(FLAVOR.disk[0].size >= 13 gibibyte)', '(FLAVOR.disk[0].size >= 40 gibibyte)'],
            [
                '(FLAVOR.disk[0].size >= 13 gibibyte)',
                '(FLAVOR.disk[0].size >= 10 gibibyte)',
                '(FLAVOR.disk[0].size >= 20 gibibyte)'
            ],
            ['(FLAVOR.disk[0].size >= 13 gibibyte)', '(FLAVOR.cpu.processors >= 2)'],
            ['(FLAVOR.disk[0].size >= 13 gibibyte)', '(FLAVOR.cpu.processors >= 3)']
        ]
    )
], ids=[
    'SPANS1',
    'SPANS2'
])
def test_spans(
    logger: ContextAdapter,
    hw: str,
    flavor: tft.artemis.environment.Flavor,
    expected_spans: List[List[str]]
) -> None:
    constraint = parse_hw(hw)

    assert eval_flavor(logger, constraint, flavor) is True

    pruned_constraint = constraint.prune_on_flavor(logger, flavor)

    assert pruned_constraint is not None

    spans = [
        [
            str(constraint)
            for constraint in span
        ]
        for span in pruned_constraint.spans(logger)
    ]

    assert spans == expected_spans
