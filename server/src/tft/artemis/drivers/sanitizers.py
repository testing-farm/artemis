# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Sanitization of strings sent to backends.

Backends impose rules on strings Artemis sends them - resource names, tag keys, tag values. A
:py:class:`StringSanitizer` describes one set of such rules, and adjusts a string to satisfy them. Drivers define
sanitizers for each kind of string their backend constrains.
"""

import dataclasses
import enum
import functools
import hashlib
import re
import string
from collections.abc import Mapping
from typing import Optional

#: Hash length used when a string is shortened by :py:attr:`ShorteningMethod.HASH`.
HASH_LENGTH = 8


class ShorteningMethod(enum.Enum):
    """
    How a string longer than the length limit is shortened.
    """

    #: The string is cut at the length limit.
    TRUNCATE = 'truncate'

    #: The head of the string is kept, and the rest is replaced with a hash of the whole string. Unlike
    #: :py:attr:`TRUNCATE`, two long strings sharing a prefix remain distinct.
    HASH = 'hash'


@dataclasses.dataclass(frozen=True)
class StringSanitizer:
    """
    Rules a backend imposes on a kind of string.

    Rules are applied in the following order: lowercasing, character replacement, stripping of edge characters,
    adding a leading letter, shortening.
    """

    #: Characters allowed in the string.
    allowed_charset: str = string.printable

    #: If unset, characters are not replaced, and :py:attr:`allowed_charset` is ignored.
    sanitize_charset: bool = True

    #: Replacements for particular disallowed characters. Characters not listed here are replaced with
    #: :py:attr:`replacement`.
    chars_mapping: Optional[Mapping[str, str]] = None

    #: Replacement for disallowed characters not listed in :py:attr:`chars_mapping`.
    replacement: str = '_'

    #: If set, every run of disallowed characters is replaced as a whole. A run of one character is replaced
    #: according to :py:attr:`chars_mapping`, longer runs with a single :py:attr:`replacement`.
    squash: bool = False

    #: If set, the string is converted to lowercase.
    lowercase: bool = False

    #: Characters the string must not start or end with. They are stripped from both ends of the string.
    strip_chars: str = ''

    #: If set, a string not starting with a letter is prefixed with one.
    must_start_with_letter: bool = False

    #: Maximal length of the string.
    max_length: Optional[int] = None

    #: How a string longer than :py:attr:`max_length` is shortened.
    shortening: ShorteningMethod = ShorteningMethod.TRUNCATE

    @functools.cached_property
    def _pattern(self) -> 're.Pattern[str]':
        return re.compile(f'[^{re.escape(self.allowed_charset)}]{"+" if self.squash else ""}')

    def _replace(self, match: 're.Match[str]') -> str:
        return (self.chars_mapping or {}).get(match.group(0), self.replacement)

    def _shorten(self, value: str, max_length: int) -> str:
        if self.shortening == ShorteningMethod.TRUNCATE:
            return value[:max_length]

        digest = hashlib.sha1(value.encode()).hexdigest()[:HASH_LENGTH]  # noqa: S324
        head = value[: max(max_length - HASH_LENGTH - 1, 0)].rstrip('-')

        return f'{head}-{digest}' if head else digest

    def __call__(self, value: str) -> str:
        """
        Adjust a string to satisfy the rules.

        :param value: string to sanitize.
        :returns: sanitized string. A string that already satisfies all rules is returned unchanged.
        """

        if self.lowercase:
            value = value.lower()

        if self.sanitize_charset:
            value = self._pattern.sub(self._replace, value)

        if self.strip_chars:
            value = value.strip(self.strip_chars)

        if self.must_start_with_letter and not value[:1].isalpha():
            value = f'a{value}'

        if self.max_length is None or len(value) <= self.max_length:
            return value

        return self._shorten(value, self.max_length)


#: Leaves every string unchanged.
NOOP_SANITIZER = StringSanitizer(sanitize_charset=False)
