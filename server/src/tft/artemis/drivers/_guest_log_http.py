# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Fetching guest logs over HTTP with a bounded memory footprint.
"""

import dataclasses
import re
from collections.abc import Callable
from typing import Optional

import gluetool.log
import requests
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import GuestLog
from ..knobs import KNOB_DISABLE_CERT_VERIFICATION, KNOB_HTTP_TIMEOUT
from . import KNOB_UPDATE_GUEST_REQUEST_LOG_MAX_SIZE, GuestLogUpdateProgress

#: Matches the ``Content-Range`` header of a partial response, e.g. ``bytes 100-199/1000``.
CONTENT_RANGE_PATTERN = re.compile(r'^bytes\s+(\d+)-(\d+)/(\d+|\*)$')


def _read_at_most(response: requests.Response, limit: int) -> tuple[bytes, bool]:
    """
    Read the response body, but never keep more than ``limit`` bytes in memory.

    :param response: a streamed response to read from.
    :param limit: the maximum number of bytes to return.
    :returns: a tuple of two items, the body, or its first ``limit`` bytes, and a boolean which is set when the body
        was longer than ``limit`` bytes.
    """

    # One extra byte tells whether the body is longer than the limit. `read()` with an amount keeps reading until
    # it collects that many bytes or the body ends.
    content = response.raw.read(limit + 1, decode_content=True)

    return content[:limit], len(content) > limit


def _parse_int_header(response: requests.Response, header: str) -> Optional[int]:
    value = response.headers.get(header)

    if value is None or not value.strip().isdigit():
        return None

    return int(value)


def _parse_content_range(response: requests.Response) -> tuple[Optional[int], Optional[int]]:
    """
    Extract the first byte position and the complete length from the ``Content-Range`` header.

    :returns: a tuple of two items, the position of the first byte of the partial response, and the complete length
        of the log. Either may be ``None`` when the header is missing or does not provide it.
    """

    match = CONTENT_RANGE_PATTERN.match(response.headers.get('Content-Range', '').strip())

    if match is None:
        return None, None

    first_byte, _, complete_length = match.groups()

    return int(first_byte), None if complete_length == '*' else int(complete_length)


@dataclasses.dataclass(frozen=True)
class _Truncation:
    """
    Describes how a log was truncated.
    """

    #: Which part of the log was kept, ``first`` or ``last``.
    part: str

    #: Number of bytes kept.
    stored_size: int

    #: Size of the complete log, if the server reported it.
    complete_size: Optional[int]


def _read_tail(response: requests.Response, max_size: int) -> tuple[bytes, Optional[_Truncation]]:
    """
    Read a ``206 Partial Content`` response: the server honored the range and sent the tail of the log.
    """

    content, _ = _read_at_most(response, max_size)
    first_byte, complete_size = _parse_content_range(response)

    if first_byte == 0:
        return content, None

    # Without a usable `Content-Range`, a body shorter than the range is assumed to be the whole log.
    if first_byte is None and len(content) < max_size:
        return content, None

    return content, _Truncation('last', len(content), complete_size)


def _read_head(response: requests.Response, max_size: int) -> tuple[bytes, Optional[_Truncation]]:
    """
    Read a ``200 OK`` response: the server ignored the range and sent the whole log, keep its head.
    """

    content, truncated = _read_at_most(response, max_size)

    if not truncated:
        return content, None

    return content, _Truncation('first', len(content), _parse_int_header(response, 'Content-Length'))


def _decode(response: requests.Response, content: bytes) -> str:
    # Mirror what `requests.Response.text` would do, except for the guessing of the encoding: guessing
    # needs the whole body, and the body may be cut in the middle of a multibyte character.
    return content.decode(response.encoding or 'utf-8', errors='replace')


def _truncation_note(url: str, truncation: _Truncation) -> str:
    if truncation.complete_size is None:
        complete = f'more than {truncation.stored_size} bytes'

    else:
        complete = f'{truncation.complete_size} bytes'

    return (
        f'[Artemis: log truncated, showing the {truncation.part} {truncation.stored_size} bytes of {complete}. '
        f'Full log: {url}]\n'
    )


def _download(
    url: str,
    max_size: int,
    *,
    failure_message: str,
    failure_from_response: Optional[Callable[[requests.Response], Failure]],
) -> Result[tuple[str, Optional[_Truncation]], Failure]:
    """
    Download at most ``max_size`` bytes of a log.

    The log is requested with a suffix range, therefore servers supporting range requests return just its tail. When
    the server ignores the range, the body is read in chunks, and the reading stops once the limit is reached. A
    missing or incorrect ``Content-Length`` cannot make Artemis read more than the limit.

    :returns: a tuple of two items, the downloaded text, and a description of the truncation, or ``None`` if the log
        was not truncated. Or a :py:class:`Failure` describing an error.
    """

    try:
        with requests.get(
            url,
            # Ranges apply to the encoded representation: with compression, the tail would be a fragment
            # of a gzip stream.
            headers={'Range': f'bytes=-{max_size}', 'Accept-Encoding': 'identity'},
            stream=True,
            verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
            timeout=KNOB_HTTP_TIMEOUT.value,
        ) as response:
            # Range of an empty log cannot be satisfied.
            if response.status_code == requests.codes.requested_range_not_satisfiable:
                return Ok(('', None))

            if not response.ok and failure_from_response is not None:
                return Error(failure_from_response(response))

            response.raise_for_status()

            if response.status_code == requests.codes.partial_content:
                content, truncation = _read_tail(response, max_size)

            else:
                content, truncation = _read_head(response, max_size)

            return Ok((_decode(response, content), truncation))

    except requests.exceptions.RequestException as exc:
        return Error(Failure.from_exc(failure_message, exc, url=url))


def fetch_guest_log_blob(
    logger: gluetool.log.ContextAdapter,
    poolname: str,
    guest_log: GuestLog,
    url: str,
    *,
    failure_message: str,
    failure_from_response: Optional[Callable[[requests.Response], Failure]] = None,
) -> Result[GuestLogUpdateProgress, Failure]:
    """
    Download a guest log from the given URL, and turn it into an unabridged guest log blob.

    The size of the stored content is limited by :py:data:`KNOB_UPDATE_GUEST_REQUEST_LOG_MAX_SIZE`. A truncated log is
    prefixed with a note saying it was truncated, its original size, and the URL of the full log.

    :param logger: logger to use for logging.
    :param poolname: name of the pool the guest log belongs to, used for picking the size limit.
    :param guest_log: guest log to update.
    :param url: URL to download the log from.
    :param failure_message: message of the failure reported when the download fails.
    :param failure_from_response: if set, it is called to construct a failure for responses with an unsuccessful
        status code. If not set, a failure is constructed from the exception raised by
        :py:meth:`requests.Response.raise_for_status`.
    :returns: guest log update progress, or a :py:class:`Failure` describing an error.
    """

    r_max_size = KNOB_UPDATE_GUEST_REQUEST_LOG_MAX_SIZE.get_value(
        entityname=f'{poolname}:{guest_log.logname}/{guest_log.contenttype.value}'
    )

    if r_max_size.is_error:
        return Error(Failure.from_failure('failed to load guest log size limit', r_max_size.unwrap_error()))

    r_download = _download(
        url, r_max_size.unwrap(), failure_message=failure_message, failure_from_response=failure_from_response
    )

    if r_download.is_error:
        return Error(r_download.unwrap_error())

    text, truncation = r_download.unwrap()

    if truncation is not None:
        note = _truncation_note(url, truncation)

        logger.warning(f'guest log {guest_log.logname}/{guest_log.contenttype.value} too large: {note.strip()}')

        text = note + text

    return Ok(GuestLogUpdateProgress.from_unabridged(logger, guest_log, text))
