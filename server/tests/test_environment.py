import textwrap

import gluetool.utils

import tft.artemis.environment
from tft.artemis.environment import UNITS


def parse_hw(text):
    return tft.artemis.environment.constraints_from_environment_requirements(gluetool.utils.from_yaml(textwrap.dedent(text)))


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
