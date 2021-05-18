import pytest
from gluetool.result import Error, Ok

import tft.artemis
from tft.artemis.drivers import IP_ADDRESS_PATTERN, vm_info_to_ip


@pytest.mark.parametrize(
    ('output', 'key', 'regex', 'expected'),
    [
        ({'address': '127.0.0.1'}, 'address', None, Ok('127.0.0.1')),
        ({'address': 'IPv4=127.0.0.1, IPv6=2001:db8::8a2e:370:7334'}, 'address', None, Ok('127.0.0.1')),
        ({'address': None}, 'address', None, Ok(None)),
        ({'address': '127.0.0'}, 'address', None, Error(tft.artemis.Failure('failed to parse an IP address'))),
    ]
)
def test_vm_info_to_ip(output, key, regex, expected):
    r_ip = vm_info_to_ip(output, key, regex=regex)

    if expected.is_ok:
        assert r_ip.is_ok
        assert r_ip.unwrap() == expected.unwrap()

    else:
        assert r_ip.is_error
        assert isinstance(r_ip.unwrap_error(), tft.artemis.Failure)
