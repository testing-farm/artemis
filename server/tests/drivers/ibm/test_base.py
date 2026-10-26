# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0


from types import SimpleNamespace
from typing import Any

import gluetool.log
import pytest
from gluetool.result import Ok, Result

import tft.artemis.drivers.ibmcloud
import tft.artemis.drivers.ibmcloud.vpc
from tft.artemis import Failure
from tft.artemis.drivers import UNKNOWN_FLAVOR_NAME

FLAVOR_TAG = 'ArtemisInstanceFlavor'

IBM_TAGS_EXAMPLES: dict[str, str] = {
    'tag1': 'value1',
    'tag2': 'value2',
    # TODO: wrong type, but that's on purpose: our code expects `str`, but we already encountered `None` there.
    # We must handle such an invalid value, but in the long term, we need to prevent `None` sneaking in.
    'tag3': None,  # type: ignore[dict-item]
    'tag4': '',
    'tag5': 'foo bar',
    'tag6': 'foo "bar"',
    'tag7': "foo 'bar'",
    'tag8': 'https://foo.bar/~baz',
    # This one is exactly matching the limit...
    'tag9': 'a' * (tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH - 5),
    # This one is one character beyond the limit...
    'tag10': 'a' * (tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH - 5),
    # And this one has a name that is way too long.
    'c' * tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH: 'ddddd',
    # Some real-world usage
    'COLDSTORE_URL': f'http://artifacts.osci.redhat.com//baseos-ci//brew-build/66/53/25/66532507//https___{"f" * 45}-ci-test-brew-ts_tmt-artemis/7663//',  # noqa: E501
}


def test_serialize_tags() -> None:
    assert tft.artemis.drivers.ibmcloud._serialize_tags(IBM_TAGS_EXAMPLES) == [
        'tag1:value1',
        'tag2:value2',
        'tag3',
        'tag4',
        'tag5:foo bar',
        'tag6:foo _bar_',
        'tag7:foo _bar_',
        'tag8:https___foo.bar__baz',
        f'tag9:{"a" * (tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH - 5)}',
        f'tag10:{"a" * (tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH - 6)}',
        'c' * tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH,
        f'COLDSTORE_URL:http___artifacts.osci.redhat.com__baseos-ci__brew-build_66_53_25_66532507__https___{"f" * 31}',
    ]


def _simulate_cloud_stored_flavor_value(flavor_tag: str, flavor_name: str) -> str:
    """
    Reproduce the flavor tag value IBMCloud ends up storing, independently of the driver's read-side helper.

    This goes through the real write path (:py:func:`_serialize_tags`), then applies the lowercasing the cloud
    does on storage and strips the tag key prefix - exactly what the driver reads back off an instance.
    """

    serialized = tft.artemis.drivers.ibmcloud._serialize_tags({flavor_tag: flavor_name})[0].lower()

    prefix = f'{flavor_tag.lower()}:'
    assert serialized.startswith(prefix)

    return serialized[len(prefix) :]


@pytest.mark.parametrize(
    ('flavor_name', 'mangled'),
    [
        # A plain name is only lowercased by the cloud.
        ('BX2-2x8', False),
        # Disallowed characters are replaced on write.
        ('foo/bar@baz', True),
        # An overlong name is truncated to fit the key:value length budget.
        ('x' * (tft.artemis.drivers.ibmcloud.TAG_MAX_LENGTH + 10), True),
    ],
    ids=['lowercase', 'char-replacement', 'truncation'],
)
def test_flavor_tag_value_roundtrip(flavor_name: str, mangled: bool) -> None:
    stored = _simulate_cloud_stored_flavor_value(FLAVOR_TAG, flavor_name)

    # The read-side helper must predict the exact value the cloud stores.
    assert tft.artemis.drivers.ibmcloud._sanitize_flavor_tag_value(FLAVOR_TAG, flavor_name) == stored

    # Sanity: the mangled cases really do differ from a plain lowercasing, so the test exercises the
    # character-replacement and truncation branches rather than passing trivially.
    if mangled:
        assert stored != flavor_name.lower()

    # ...and the stored value must round-trip back to the configured flavor name.
    mapping, ambiguous = tft.artemis.drivers.ibmcloud._map_flavor_names_by_tag_value(FLAVOR_TAG, [flavor_name])

    assert ambiguous == set()
    assert mapping[stored] == flavor_name


def test_map_flavor_names_duplicate_not_ambiguous() -> None:
    # The same configured name repeated is not a collision.
    mapping, ambiguous = tft.artemis.drivers.ibmcloud._map_flavor_names_by_tag_value(FLAVOR_TAG, ['bx2-2x8', 'bx2-2x8'])

    assert ambiguous == set()
    assert mapping[_simulate_cloud_stored_flavor_value(FLAVOR_TAG, 'bx2-2x8')] == 'bx2-2x8'


def test_map_flavor_names_collision_is_ambiguous() -> None:
    # Two distinct configured names that sanitize and lowercase onto the same stored value cannot be told
    # apart, so the stored value is flagged ambiguous and resolves to the unknown-flavor sentinel rather
    # than silently to one of them.
    names = ['Foo/Bar', 'foo_bar']

    collided = _simulate_cloud_stored_flavor_value(FLAVOR_TAG, names[0])
    assert collided == _simulate_cloud_stored_flavor_value(FLAVOR_TAG, names[1])

    mapping, ambiguous = tft.artemis.drivers.ibmcloud._map_flavor_names_by_tag_value(FLAVOR_TAG, names)

    assert ambiguous == {collided}
    assert mapping[collided] == UNKNOWN_FLAVOR_NAME


def test_flavor_tag_search_is_region_scoped(
    monkeypatch: pytest.MonkeyPatch,
    logger: gluetool.log.ContextAdapter,
    ibmvpc_pool: tft.artemis.drivers.ibmcloud.vpc.IBMCloudVPCDriver,
) -> None:
    # Instance names are unique only within a region, while the underlying Global Search spans the whole
    # account. The usage lookup must scope the search to the pool's region, otherwise a same-named instance
    # in another region could overwrite the local one in the name-keyed mapping and mis-report its flavor.
    ibmvpc_pool.pool_config['default-region'] = 'eu-de'

    monkeypatch.setattr(type(ibmvpc_pool), '_instance_flavor_tag', property(lambda self: Ok('artemisflavor')))
    monkeypatch.setattr(ibmvpc_pool, 'get_pool_flavor_infos', lambda: Ok([]))

    captured_filters: list[str] = []

    def _fake_search(_logger: gluetool.log.ContextAdapter, resource_filter: str) -> Result[list[Any], Failure]:
        captured_filters.append(resource_filter)

        return Ok([])

    monkeypatch.setattr(ibmvpc_pool, 'get_resources_by_filter', _fake_search)

    r_instances = ibmvpc_pool.get_instances_with_flavor_tags_names(logger, 'instance')

    assert r_instances.is_ok
    assert len(captured_filters) == 1
    # Trailing '*' is required: VPC stores a zone (e.g. eu-de-2) in the region field, so the region prefix
    # must match as a wildcard rather than exactly.
    assert 'region:eu-de*' in captured_filters[0]
    assert 'type:instance' in captured_filters[0]


def test_flavor_tag_ambiguity_does_not_abort(
    monkeypatch: pytest.MonkeyPatch,
    logger: gluetool.log.ContextAdapter,
    ibmvpc_pool: tft.artemis.drivers.ibmcloud.vpc.IBMCloudVPCDriver,
) -> None:
    # A flavor naming mistake must not abort the whole metrics refresh (cores, memory, limits, usage) that
    # routing and provisioning depend on. The lookup reports the collision but still succeeds, resolving the
    # ambiguous instances to the unknown-flavor sentinel.
    ibmvpc_pool.pool_config['default-region'] = 'eu-de'

    monkeypatch.setattr(type(ibmvpc_pool), '_instance_flavor_tag', property(lambda self: Ok('artemisflavor')))
    monkeypatch.setattr(
        ibmvpc_pool,
        'get_pool_flavor_infos',
        lambda: Ok([SimpleNamespace(name='Foo/Bar'), SimpleNamespace(name='foo_bar')]),
    )

    collided = tft.artemis.drivers.ibmcloud._sanitize_flavor_tag_value('artemisflavor', 'Foo/Bar')

    def _fake_search(_logger: gluetool.log.ContextAdapter, _resource_filter: str) -> Result[list[Any], Failure]:
        return Ok([{'name': 'guest-1', 'tags': [f'artemisflavor:{collided}']}])

    monkeypatch.setattr(ibmvpc_pool, 'get_resources_by_filter', _fake_search)

    r_instances = ibmvpc_pool.get_instances_with_flavor_tags_names(logger, 'instance')

    assert r_instances.is_ok
    assert r_instances.unwrap() == {'guest-1': UNKNOWN_FLAVOR_NAME}
