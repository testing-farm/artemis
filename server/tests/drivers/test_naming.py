# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import dataclasses
import re
import string
from unittest import mock

import pytest
from gluetool.result import Ok

from tft.artemis.drivers import PoolDriver
from tft.artemis.drivers.aws import AWS_INSTANCE_NAME_SANITIZER, AWS_SECURITY_GROUP_NAME_SANITIZER
from tft.artemis.drivers.azure import AZURE_RESOURCE_GROUP_NAME_SANITIZER, AZURE_VM_NAME_SANITIZER
from tft.artemis.drivers.gcp import GCP_INSTANCE_NAME_SANITIZER
from tft.artemis.drivers.ibmcloud.power import IBM_POWER_INSTANCE_NAME_SANITIZER
from tft.artemis.drivers.ibmcloud.vpc import IBM_VPC_INSTANCE_NAME_SANITIZER
from tft.artemis.drivers.naming import LookupMethod, NamingStrategy
from tft.artemis.drivers.openstack import OPENSTACK_INSTANCE_NAME_SANITIZER
from tft.artemis.drivers.sanitizers import StringSanitizer
from tft.artemis.knobs import Knob

GUESTNAME = '3f1ab0c2-6a1d-4a4e-9a8b-0f4c2d6e8a10'

ALL_SANITIZERS = [
    AWS_INSTANCE_NAME_SANITIZER,
    AWS_SECURITY_GROUP_NAME_SANITIZER,
    AZURE_RESOURCE_GROUP_NAME_SANITIZER,
    AZURE_VM_NAME_SANITIZER,
    GCP_INSTANCE_NAME_SANITIZER,
    IBM_POWER_INSTANCE_NAME_SANITIZER,
    IBM_VPC_INSTANCE_NAME_SANITIZER,
    OPENSTACK_INSTANCE_NAME_SANITIZER,
]

TEMPLATE_KNOB: Knob[str] = Knob(
    'test.mapping.dummy-name.template',
    'A dummy name template',
    has_db=False,
    per_entity=True,
    envvar='ARTEMIS_TEST_DUMMY_NAME_TEMPLATE',
    cast_from_str=str,
    default='',
)


@dataclasses.dataclass
class DummyResource:
    name: str


@pytest.fixture(name='guest_request')
def fixture_guest_request() -> mock.MagicMock:
    guest_request = mock.MagicMock(name='guest_request')
    guest_request.guestname = GUESTNAME

    return guest_request


@pytest.mark.parametrize('sanitizer', ALL_SANITIZERS)
def test_sanitize_default_name_unchanged(sanitizer: StringSanitizer) -> None:
    # Default names must not change, existing resources would not be recognized otherwise.
    name = f'artemis-{GUESTNAME}'

    assert sanitizer(name) == name


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('Artemis_Guest.Foo', 'artemis-guest-foo'),
        ('1-artemis', 'a1-artemis'),
        ('--artemis--guest--', 'artemis--guest'),
        ('artemis  guest', 'artemis-guest'),
    ],
)
def test_sanitize_gcp(name: str, expected: str) -> None:
    assert GCP_INSTANCE_NAME_SANITIZER(name) == expected


@pytest.mark.parametrize(
    ('sanitizer', 'name'),
    [
        (AWS_SECURITY_GROUP_NAME_SANITIZER, '-team--artemis-'),
        (AWS_SECURITY_GROUP_NAME_SANITIZER, 'team artemis (guest) #1'),
        (AZURE_RESOURCE_GROUP_NAME_SANITIZER, '-team--artemis-'),
        (AZURE_VM_NAME_SANITIZER, 'team--artemis'),
        (GCP_INSTANCE_NAME_SANITIZER, 'team--artemis'),
        (IBM_VPC_INSTANCE_NAME_SANITIZER, 'team--artemis'),
    ],
)
def test_sanitize_valid_name_unchanged(sanitizer: StringSanitizer, name: str) -> None:
    # Names a backend accepts must not change, existing resources would not be recognized otherwise.
    assert sanitizer(name) == name


@pytest.mark.parametrize(
    ('sanitizer', 'name', 'expected'),
    [
        (AZURE_VM_NAME_SANITIZER, 'artemis-guest.', 'artemis-guest'),
        (AZURE_RESOURCE_GROUP_NAME_SANITIZER, 'artemis guest.', 'artemis-guest'),
    ],
)
def test_sanitize_azure(sanitizer: StringSanitizer, name: str, expected: str) -> None:
    assert sanitizer(name) == expected


@pytest.mark.parametrize('sanitizer', ALL_SANITIZERS)
def test_sanitize_shorten(sanitizer: StringSanitizer) -> None:
    assert sanitizer.max_length is not None

    name = 'a' * (sanitizer.max_length + 20)
    sanitized = sanitizer(name)

    assert len(sanitized) <= sanitizer.max_length
    assert re.fullmatch(r'a+-[0-9a-f]{8}', sanitized)

    # Deterministic...
    assert sanitizer(name) == sanitized

    # ... and unique.
    assert sanitizer(f'{name}b') != sanitized


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('artemis-foo', True),
        ('artemis-foo-3', True),
        ('artemis-foo-12', True),
        ('artemis-foo-x', False),
        ('artemis-foo3', False),
        ('artemis-foo-bar', False),
        ('artemis-fo', False),
        ('xartemis-foo', False),
    ],
)
def test_matches(name: str, expected: bool) -> None:
    assert NamingStrategy('instance').matches('artemis-foo', name) is expected


def test_matches_escapes_expected_name() -> None:
    assert NamingStrategy('instance').matches('artemis.foo', 'artemisxfoo') is False


@pytest.mark.parametrize(
    ('postfix', 'expected'),
    [
        (3, 'artemis-fo-3'),
        (12, 'artemis-f-12'),
    ],
)
def test_with_postfix_shortens(postfix: int, expected: str) -> None:
    naming = NamingStrategy('instance', sanitizer=StringSanitizer(max_length=12))

    assert naming.with_postfix('artemis-foo', postfix) == expected


def test_with_postfix_fits() -> None:
    naming = NamingStrategy('instance', sanitizer=StringSanitizer(max_length=20))

    assert naming.with_postfix('artemis-foo', 3) == 'artemis-foo-3'


@pytest.mark.parametrize(
    ('name', 'expected'),
    [
        ('artemis-foo', True),
        ('artemis-fo-3', True),
        ('artemis-f-12', True),
        # Postfix written differently than ``with_postfix`` would.
        ('artemis-fo-03', False),
        # Not shortened, too long for the backend, and not ours.
        ('artemis-foo-3', False),
        ('artemis-fx-3', False),
    ],
)
def test_matches_shortened(name: str, expected: bool) -> None:
    naming = NamingStrategy('instance', sanitizer=StringSanitizer(max_length=12))

    assert naming.matches('artemis-foo', name) is expected


def test_select() -> None:
    resources = [DummyResource('artemis-foo'), DummyResource('artemis-foo-1'), DummyResource('artemis-foobar')]

    assert NamingStrategy('instance').select('artemis-foo', resources) == resources[:2]
    assert NamingStrategy('instance', lookup=LookupMethod.BACKEND).select('artemis-foo', resources) == resources


def test_get_template_default() -> None:
    assert NamingStrategy('instance').get_template('dummy-pool').unwrap() == 'artemis-{{ GUESTNAME }}'


def test_get_template_empty_knob_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('ARTEMIS_RESOURCE_NAME_TEMPLATE', 'global-{{ GUESTNAME }}')

    naming = NamingStrategy('instance', template_knob=TEMPLATE_KNOB)

    assert naming.get_template('dummy-pool').unwrap() == 'global-{{ GUESTNAME }}'


def test_get_template_knob(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('ARTEMIS_RESOURCE_NAME_TEMPLATE', 'global-{{ GUESTNAME }}')
    monkeypatch.setenv('ARTEMIS_TEST_DUMMY_NAME_TEMPLATE', 'dummy-{{ GUESTNAME }}')
    monkeypatch.setenv('ARTEMIS_TEST_DUMMY_NAME_TEMPLATE_dummy_pool', 'pool-{{ GUESTNAME }}')

    naming = NamingStrategy('instance', template_knob=TEMPLATE_KNOB)

    assert naming.get_template('dummy-pool').unwrap() == 'pool-{{ GUESTNAME }}'
    assert naming.get_template('another-pool').unwrap() == 'dummy-{{ GUESTNAME }}'


def test_render(guest_request: mock.MagicMock) -> None:
    naming = NamingStrategy(
        'security_group',
        sanitizer=StringSanitizer(
            allowed_charset=string.ascii_lowercase + string.digits + '-', replacement='-', lowercase=True
        ),
    )

    r_name = naming.render(
        '{{ RESOURCE_TYPE }}-{{ POOLNAME }}-{{ TAGS.owner }}-{{ GUESTNAME }}',
        'dummy-pool',
        guest_request,
        tags={'owner': 'Some_User'},
    )

    assert r_name.unwrap() == f'security-group-dummy-pool-some-user-{GUESTNAME}'


def test_render_deployment(guest_request: mock.MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('tft.artemis.drivers.naming.KNOB_DEPLOYMENT', mock.MagicMock(value='production-01'))

    r_name = NamingStrategy('instance').render('{{ DEPLOYMENT }}-{{ GUESTNAME }}', 'dummy-pool', guest_request)

    assert r_name.unwrap() == f'production-01-{GUESTNAME}'


def test_render_error(guest_request: mock.MagicMock) -> None:
    r_name = NamingStrategy('instance').render('{{ GUESTNAME', 'dummy-pool', guest_request)

    assert r_name.failure().message == 'could not render resource name template'


@pytest.mark.parametrize('template', ['artemis-{{ POOLNAME }}', 'artemis-{{ GUESTNAME[:8] }}'])
def test_render_without_guestname(guest_request: mock.MagicMock, template: str) -> None:
    r_name = NamingStrategy('instance').render(template, 'dummy-pool', guest_request)

    assert r_name.failure().message == 'resource name does not contain guest name'


@pytest.mark.parametrize(
    ('tags_include_label', 'expected'),
    [
        # Instance names cannot see the guest label, it is derived from them.
        (False, f'base-none-{GUESTNAME}'),
        (True, f'full-label-{GUESTNAME}'),
    ],
)
def test_render_resource_name_tags(
    guest_request: mock.MagicMock, monkeypatch: pytest.MonkeyPatch, tags_include_label: bool, expected: str
) -> None:
    monkeypatch.setenv(
        'ARTEMIS_TEST_DUMMY_NAME_TEMPLATE',
        "{{ TAGS.owner }}-{{ TAGS.ArtemisGuestLabel | default('none') }}-{{ GUESTNAME }}",
    )

    pool = mock.MagicMock(name='pool')
    pool.poolname = 'dummy-pool'
    pool.get_base_guest_tags.return_value = Ok({'owner': 'base'})
    pool.get_guest_tags.return_value = Ok({'owner': 'full', 'ArtemisGuestLabel': 'label'})

    naming = NamingStrategy('dummy', template_knob=TEMPLATE_KNOB, tags_include_label=tags_include_label)

    assert PoolDriver.render_resource_name(pool, mock.MagicMock(), guest_request, naming).unwrap() == expected


def test_render_resource_name_no_tags(guest_request: mock.MagicMock) -> None:
    # Tags are not fetched when the template does not use them.
    pool = mock.MagicMock(name='pool')
    pool.poolname = 'dummy-pool'

    r_name = PoolDriver.render_resource_name(pool, mock.MagicMock(), guest_request, NamingStrategy('dummy'))

    assert r_name.unwrap() == f'artemis-{GUESTNAME}'
    pool.get_base_guest_tags.assert_not_called()
    pool.get_guest_tags.assert_not_called()
