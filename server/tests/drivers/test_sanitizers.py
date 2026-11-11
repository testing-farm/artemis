# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import re
import string

import pytest

from tft.artemis.drivers.sanitizers import NOOP_SANITIZER, ShorteningMethod, StringSanitizer


def test_noop() -> None:
    assert NOOP_SANITIZER('Foo_Bar--baz\n') == 'Foo_Bar--baz\n'


def test_default_charset() -> None:
    assert StringSanitizer()('foo\x00bar') == 'foo_bar'


@pytest.mark.parametrize(
    ('squash', 'expected'),
    [
        (False, 'foo__bar-baz'),
        (True, 'foo_bar-baz'),
    ],
)
def test_chars_mapping(squash: bool, expected: str) -> None:
    sanitizer = StringSanitizer(allowed_charset=string.ascii_letters + '-_', chars_mapping={'/': '-'}, squash=squash)

    assert sanitizer('foo  bar/baz') == expected


def test_lowercase_before_replace() -> None:
    # Uppercase letters must not be replaced when lowercasing makes them allowed.
    sanitizer = StringSanitizer(allowed_charset=string.ascii_lowercase, lowercase=True)

    assert sanitizer('FooBar') == 'foobar'


def test_strip_and_leading_letter() -> None:
    sanitizer = StringSanitizer(strip_chars='-', must_start_with_letter=True)

    assert sanitizer('-1-foo-') == 'a1-foo'


def test_truncate() -> None:
    assert StringSanitizer(max_length=5)('a' * 20) == 'a' * 5


def test_full_length_unchanged() -> None:
    # A string using the whole length limit is kept, no room is reserved for a postfix.
    assert StringSanitizer(max_length=10, shortening=ShorteningMethod.HASH)('a' * 10) == 'a' * 10


def test_hash_tiny() -> None:
    # No room for the head, the hash must suffice.
    assert re.fullmatch(r'[0-9a-f]{8}', StringSanitizer(max_length=9, shortening=ShorteningMethod.HASH)('a' * 20))
