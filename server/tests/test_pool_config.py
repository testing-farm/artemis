import textwrap

import gluetool.utils
from pint import Quantity

import tft.artemis.drivers
import tft.artemis.drivers.beaker
import tft.artemis.environment


def parse_spec(text):
    spec = gluetool.utils.from_yaml(textwrap.dedent(text))
    print(text)
    print(spec)

    print('patch:', gluetool.log.format_dict(spec))

    return spec


def test_patch_nop():
    flavor_spec = parse_spec(
        """
        ---

        # This one's required by schema, but patcher code does not read it anymore.
        # Keeping it here to enforce YAML spec to be a mapping, as expected, instead
        # of typing `{}`.
        name: dummy-flavor
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id'
    )

    print(flavor)

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    print(flavor)

    assert r_outcome.is_ok


def test_patch_unsupported():
    flavor_spec = parse_spec(
        """
        ---

        arch: aarch64
        memory: 1024
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id'
    )

    print(flavor)

    assert flavor.arch is None
    assert flavor.memory is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    print(flavor)

    assert r_outcome.is_ok
    assert flavor.arch is None
    assert flavor.memory is None


def test_patch_cpu():
    flavor_spec = parse_spec(
        """
        ---

        cpu:
          family: 6
          family-name: Haswell
          model: 7
          model-name: i7-4850HQ
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id'
    )

    print(flavor)

    assert flavor.cpu.family is None
    assert flavor.cpu.family_name is None
    assert flavor.cpu.model is None
    assert flavor.cpu.model_name is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    print(flavor)

    assert r_outcome.is_ok

    assert flavor.cpu.family == 6
    assert flavor.cpu.family_name == 'Haswell'
    assert flavor.cpu.model == 7
    assert flavor.cpu.model_name == 'i7-4850HQ'


def test_patch_disk():
    flavor_spec = parse_spec(
        """
        ---

        disk:
          - size: 10 GiB
          - size: '1023'
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id',
        disk=tft.artemis.environment.FlavorDisks([
            tft.artemis.environment.FlavorDisk()
        ])
    )

    print(flavor)

    assert flavor.disk[0].size is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    print(flavor)

    assert r_outcome.is_ok

    assert flavor.disk[0].size == Quantity('10 GiB')
    assert flavor.disk[1].size == Quantity('1023 bytes')


def test_patch_virtualization():
    flavor_spec = parse_spec(
        """
        ---

        virtualization:
          is-supported: false
          is-virtualized: true
          hypervisor: xen
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id'
    )

    print(flavor)

    assert flavor.virtualization.is_supported is None
    assert flavor.virtualization.is_virtualized is None
    assert flavor.virtualization.hypervisor is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    print(flavor)

    assert r_outcome.is_ok

    assert flavor.virtualization.is_supported is False
    assert flavor.virtualization.is_virtualized is True
    assert flavor.virtualization.hypervisor == 'xen'


def test_patch_flavors(logger):
    patches = parse_spec(
        """
        ---

        - name: foo
          cpu:
            family: 6

        - name-regex: ba.
          cpu:
            family: 7
        """
    )

    flavors = {
        'foo': tft.artemis.environment.Flavor(
            name='foo',
            id='foo'
        ),
        'bar': tft.artemis.environment.Flavor(
            name='bar',
            id='bar'
        ),
        'baz': tft.artemis.environment.Flavor(
            name='baz',
            id='baz'
        )
    }

    print(flavors)

    assert flavors['foo'].cpu.family is None
    assert flavors['bar'].cpu.family is None
    assert flavors['baz'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    print(flavors)

    assert r_outcome.is_ok

    assert flavors['foo'].cpu.family == 6
    assert flavors['bar'].cpu.family == 7
    assert flavors['baz'].cpu.family == 7


def test_patch_flavors_no_such_name(logger):
    patches = parse_spec(
        """
        ---

        - name: foo
          cpu:
            family: 6
        """
    )

    flavors = {
        'bar': tft.artemis.environment.Flavor(
            name='bar',
            id='bar'
        )
    }

    print(flavors)

    assert flavors['bar'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    print(flavors)

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown patched flavor'
    assert r_outcome.unwrap_error().details['flavorname'] == 'foo'

    assert flavors['bar'].cpu.family is None


def test_patch_flavors_no_such_name_regex(logger):
    patches = parse_spec(
        """
        ---

        - name-regex: f.+
          cpu:
            family: 6
        """
    )

    flavors = {
        'bar': tft.artemis.environment.Flavor(
            name='bar',
            id='bar'
        )
    }

    print(flavors)

    assert flavors['bar'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    print(flavors)

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown patched flavor'
    assert r_outcome.unwrap_error().details['flavorname'] == 'f.+'

    assert flavors['bar'].cpu.family is None


def test_custom_flavors(logger):
    patches = parse_spec(
        """
        ---

        - name: foo-with-family
          base: foo
          cpu:
            family: 6
        """
    )

    flavors = {
        'foo': tft.artemis.environment.Flavor(
            name='foo',
            id='foo'
        )
    }

    print(flavors)

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    r_outcome = tft.artemis.drivers._custom_flavors(
        logger,
        flavors,
        patches
    )

    print(flavors)

    assert r_outcome.is_ok

    custom_flavors = r_outcome.unwrap()

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    assert len(custom_flavors) == 1
    assert custom_flavors[0].name == 'foo-with-family'
    assert custom_flavors[0].id == 'foo'
    assert custom_flavors[0].cpu.family == 6


def test_custom_flavors_no_such_base(logger):
    patches = parse_spec(
        """
        ---

        - name: foo-with-family
          base: bar
          cpu:
            family: 6
        """
    )

    flavors = {
        'foo': tft.artemis.environment.Flavor(
            name='foo',
            id='foo'
        )
    }

    print(flavors)

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    r_outcome = tft.artemis.drivers._custom_flavors(
        logger,
        flavors,
        patches
    )

    print(flavors)

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown base flavor'
    assert r_outcome.unwrap_error().details['customname'] == 'foo-with-family'
    assert r_outcome.unwrap_error().details['basename'] == 'bar'

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors
