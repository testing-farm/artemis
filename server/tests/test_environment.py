import textwrap

import gluetool.utils
import pytest

import tft.artemis.drivers.beaker
import tft.artemis.environment
from tft.artemis.environment import UNITS, Environment


@pytest.fixture(name='schema_v0_0_19')
def fixture_schema_v0_0_19():
    r_schema = tft.artemis.load_validation_schema('environment-v0.0.19.yml')

    assert r_schema.is_ok

    return r_schema.unwrap()


def parse_hw(text):
    r_constraint = tft.artemis.environment.constraints_from_environment_requirements(
        gluetool.utils.from_yaml(textwrap.dedent(text))
    )

    assert r_constraint.is_ok

    return r_constraint.unwrap()


def parse_spec(text):
    return gluetool.utils.from_yaml(textwrap.dedent(text))


def test_example_simple(logger):
    constraint = parse_hw(
        """
        ---

        memory: 8 GiB
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=UNITS('8 GiB')
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=UNITS('9 GiB')
        )
    ) is False


def test_example_cpu(logger):
    constraint = parse_hw(
        """
        ---

        cpu:
            processors: 2
            cores: 16
            model: 37
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                processors=2,
                cores=16,
                model=37
            )
        )
    ) is True


def test_example_disk(logger):
    constraint = parse_hw(
        """
        ---

        disk:
            space: 500 GiB
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            disk=tft.artemis.environment.FlavorDisk(
                space=UNITS('500 GiB')
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            disk=tft.artemis.environment.FlavorDisk(
                space=UNITS('600 GiB')
            )
        )
    ) is False


def test_example_operators(logger):
    flavor_big = tft.artemis.environment.Flavor(
        memory=UNITS('9 GiB')
    )

    flavor_right = tft.artemis.environment.Flavor(
        memory=UNITS('8 GiB')
    )

    flavor_small = tft.artemis.environment.Flavor(
        memory=UNITS('7 GiB')
    )

    constraint = parse_hw(
        """
        ---

        memory: '> 8 GiB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(logger, flavor_big) is True
    assert constraint.eval_flavor(logger, flavor_right) is False
    assert constraint.eval_flavor(logger, flavor_small) is False

    constraint = parse_hw(
        """
        ---

        memory: '>= 8 GiB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(logger, flavor_big) is True
    assert constraint.eval_flavor(logger, flavor_right) is True
    assert constraint.eval_flavor(logger, flavor_small) is False

    constraint = parse_hw(
        """
        ---

        memory: "< 8 GiB"
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(logger, flavor_big) is False
    assert constraint.eval_flavor(logger, flavor_right) is False
    assert constraint.eval_flavor(logger, flavor_small) is True

    constraint = parse_hw(
        """
        ---

        memory: '<= 8 GiB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(logger, flavor_big) is False
    assert constraint.eval_flavor(logger, flavor_right) is True
    assert constraint.eval_flavor(logger, flavor_small) is True


def test_example_exact_value():
    constraint1 = parse_hw(
        """
        ---

        memory: 8 GiB
        """
    )

    print(constraint1.format())

    constraint2 = parse_hw(
        """
        ---

        memory: '= 8 GiB'
        """
    )

    print(constraint2.format())

    assert constraint1.format() == constraint2.format()


def test_example_unit_with_space():
    constraint1 = parse_hw(
        """
        ---

        memory: '8GiB'
        """
    )

    print(constraint1.format())

    constraint2 = parse_hw(
        """
        ---

        memory: '8 GiB'
        """
    )

    print(constraint2.format())

    assert constraint1.format() == constraint2.format()


def test_example_units_conversion(logger):
    constraint = parse_hw(
        """
        ---

        memory: 8192 MiB
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=UNITS('8 GiB')
        )
    ) is True


def test_example_regex(logger):
    constraint = parse_hw(
        """
        ---

        cpu:
            model_name: "=~ .*AMD.*"
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                model_name='someAMDmodel'
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                model_name='someIntelmodel'
            )
        )
    ) is False


def test_example_logic(logger):
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

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=65
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=67
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=69
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=15,
                model=70
            )
        )
    ) is False

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=17,
                model=65
            )
        )
    ) is False


def test_clueless_flavor(logger):
    constraint = parse_hw(
        """
        ---

        cpu:
            family: 79
            model_name: AMD
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            cpu=tft.artemis.environment.FlavorCpu(
                family=79,
                model_name=None
            )
        )
    ) is False


def test_schema_no_constraints_v0_0_19(schema_v0_0_19, logger):
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

    for error in errors:
        print(error)

    assert errors == []


def test_schema_simple_v0_0_19(schema_v0_0_19, logger):
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

    for error in errors:
        print(error)

    assert errors == []


def test_schema_logic_v0_0_19(schema_v0_0_19, logger):
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

    for error in errors:
        print(error)

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
        '<and><system><arch op="==" value="ppc64"/></system><and><cpu><model op="&gt;=" value="5111808"/></cpu><cpu><model op="&lt;=" value="5177343"/></cpu></and></and>'
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
              space: ">= 60 GiB"
        """,
        '<and><system><arch op="==" value="x86_64"/></system><disk><size op="&gt;=" value="64424509440"/></disk></and>'
    )
], ids=[
    'IBM__POWER9',
    'IBM__POWER_PPC970',
    'DISK__SIZE_MIN_60G'
])
def test_beaker_preset(logger, hw, expected):
    spec = parse_spec(
        """
        ---

        hw: {}

        os:
          compose: dummy-compose
        """
    )

    spec['hw'] = parse_spec(hw)

    print(spec)

    environment = Environment.unserialize_from_json(spec)

    r_host_filter = tft.artemis.drivers.beaker.environment_to_beaker_filter(environment)

    assert r_host_filter.is_ok

    host_filter = r_host_filter.unwrap()

    print(host_filter)

    assert str(host_filter) == expected
