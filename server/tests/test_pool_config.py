import textwrap
from typing import Any

import gluetool.utils
from gluetool.log import ContextAdapter

import tft.artemis
import tft.artemis.drivers
import tft.artemis.drivers.beaker
import tft.artemis.environment
from tft.artemis.environment import UNITS


def parse_spec(text: str) -> Any:
    return gluetool.utils.from_yaml(textwrap.dedent(text))


def test_patch_nop() -> None:
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

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok


def test_patch_unsupported() -> None:
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

    assert flavor.arch is None
    assert flavor.memory is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok
    assert flavor.arch is None
    assert flavor.memory is None


def test_patch_cpu() -> None:
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

    assert flavor.cpu.family is None
    assert flavor.cpu.family_name is None
    assert flavor.cpu.model is None
    assert flavor.cpu.model_name is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok

    assert flavor.cpu.family == 6
    assert flavor.cpu.family_name == 'Haswell'
    assert flavor.cpu.model == 7
    assert flavor.cpu.model_name == 'i7-4850HQ'


def test_patch_disk() -> None:
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

    assert flavor.disk[0].size is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok

    assert flavor.disk[0].size == UNITS('10 GiB')
    assert flavor.disk[1].size == UNITS('1023 bytes')


def test_patch_virtualization() -> None:
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

    assert flavor.virtualization.is_supported is None
    assert flavor.virtualization.is_virtualized is None
    assert flavor.virtualization.hypervisor is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok

    assert flavor.virtualization.is_supported is False
    assert flavor.virtualization.is_virtualized is True
    assert flavor.virtualization.hypervisor == 'xen'


def test_patch_disk_expansion() -> None:
    flavor_spec = parse_spec(
        """
        ---

        disk:
          - size: 10 GiB
          - is-expansion: true
            max-additional-disks: 9
            min-size: 10 GiB
            max-size: 100 GiB
        """
    )

    flavor = tft.artemis.environment.Flavor(
        name='dummy-flavor',
        id='dummy-flavor-id',
        disk=tft.artemis.environment.FlavorDisks([
            tft.artemis.environment.FlavorDisk(),
            tft.artemis.environment.FlavorDisk(),
            tft.artemis.environment.FlavorDisk()
        ])
    )

    assert flavor.disk[0].size is None
    assert flavor.disk[1].size is None
    assert flavor.disk[2].size is None

    r_outcome = tft.artemis.drivers._apply_flavor_specification(
        flavor,
        flavor_spec
    )

    assert r_outcome.is_ok

    assert len(flavor.disk) == 2
    assert flavor.disk[0].size == UNITS('10 GiB')
    assert flavor.disk[1].is_expansion is True
    assert flavor.disk[1].min_size == UNITS('10 GiB')
    assert flavor.disk[1].max_size == UNITS('100 GiB')


def test_patch_flavors(logger: ContextAdapter) -> None:
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

    assert flavors['foo'].cpu.family is None
    assert flavors['bar'].cpu.family is None
    assert flavors['baz'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    assert r_outcome.is_ok

    assert flavors['foo'].cpu.family == 6
    assert flavors['bar'].cpu.family == 7
    assert flavors['baz'].cpu.family == 7


def test_patch_flavors_no_such_name(logger: ContextAdapter) -> None:
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

    assert flavors['bar'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown patched flavor'
    assert r_outcome.unwrap_error().details['flavorname'] == 'foo'

    assert flavors['bar'].cpu.family is None


def test_patch_flavors_no_such_name_regex(logger: ContextAdapter) -> None:
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

    assert flavors['bar'].cpu.family is None

    r_outcome = tft.artemis.drivers._patch_flavors(
        logger,
        flavors,
        patches
    )

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown patched flavor'
    assert r_outcome.unwrap_error().details['flavorname'] == 'f.+'

    assert flavors['bar'].cpu.family is None


def test_custom_flavors(logger: ContextAdapter) -> None:
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

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    r_outcome = tft.artemis.drivers._custom_flavors(
        logger,
        flavors,
        patches
    )

    assert r_outcome.is_ok

    custom_flavors = r_outcome.unwrap()

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    assert len(custom_flavors) == 1
    assert custom_flavors[0].name == 'foo-with-family'
    assert custom_flavors[0].id == 'foo'
    assert custom_flavors[0].cpu.family == 6


def test_custom_flavors_no_such_base(logger: ContextAdapter) -> None:
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

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors

    r_outcome = tft.artemis.drivers._custom_flavors(
        logger,
        flavors,
        patches
    )

    assert r_outcome.is_error

    assert r_outcome.unwrap_error().message == 'unknown base flavor'
    assert r_outcome.unwrap_error().details['customname'] == 'foo-with-family'
    assert r_outcome.unwrap_error().details['basename'] == 'bar'

    assert flavors['foo'].cpu.family is None
    assert 'foo-with-family' not in flavors
