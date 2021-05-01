import textwrap

import gluetool.utils

import tft.artemis.environment


def parse_hw(text):
    return tft.artemis.environment.constraints_from_environment_requirements(gluetool.utils.from_yaml(textwrap.dedent(text)))


def test_example_simple(logger):
    constraint = parse_hw(
        """
        ---

        memory: 8 GB
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=9 * 1024 * 1024 * 1024
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
            ),
            memory=8 * 1024 * 1024 * 1024
        )
    ) is True


def test_example_disk(logger):
    constraint = parse_hw(
        """
        ---

        disk:
            space: 500 GB
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            disk=tft.artemis.environment.FlavorDisk(
                space=500 * 1024 * 1024 * 1024
            )
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            disk=tft.artemis.environment.FlavorDisk(
                space=600 * 1024 * 1024 * 1024
            )
        )
    ) is False


def test_example_operators(logger):
    constraint = parse_hw(
        """
        ---

        memory: '> 8 GB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 + 1
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024
        )
    ) is False

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 - 1
        )
    ) is False

    constraint = parse_hw(
        """
        ---

        memory: '>= 8 GB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 + 1
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 - 1
        )
    ) is False

    constraint = parse_hw(
        """
        ---

        memory: "< 8 GB"
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 + 1
        )
    ) is False

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024
        )
    ) is False

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 - 1
        )
    ) is True

    constraint = parse_hw(
        """
        ---

        memory: '<= 8 GB'
        """
    )

    print(constraint.format())

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 + 1
        )
    ) is False

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024
        )
    ) is True

    assert constraint.eval_flavor(
        logger,
        tft.artemis.environment.Flavor(
            memory=8 * 1024 * 1024 * 1024 - 1
        )
    ) is True


def test_example_exact_value():
    constraint1 = parse_hw(
        """
        ---

        memory: 8 GB
        """
    )

    print(constraint1.format())

    constraint2 = parse_hw(
        """
        ---

        memory: '= 8 GB'
        """
    )

    print(constraint2.format())

    assert constraint1.format() == constraint2.format()


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
