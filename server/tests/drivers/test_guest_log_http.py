# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import io
from typing import Any, Optional, Union
from unittest.mock import MagicMock

import pytest
import requests
import requests.structures
from gluetool.log import ContextAdapter
from gluetool.result import Ok

import tft.artemis.drivers
import tft.artemis.drivers._guest_log_http
from tft.artemis import Failure
from tft.artemis.db import GuestLog, GuestLogContentType, GuestLogState

from .. import MockPatcher

URL = 'https://beaker.example.com/recipes/1200665440/logs/anaconda.log'

MAX_SIZE = 10


class CountingBytesIO(io.BytesIO):
    """
    A response body which remembers how many bytes were read from it.
    """

    bytes_read = 0

    def read(self, size: Optional[int] = -1, decode_content: Optional[bool] = None) -> bytes:
        data = super().read(size)

        self.bytes_read += len(data)

        return data


def make_response(status_code: int, body: bytes = b'', headers: Optional[dict[str, str]] = None) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.headers = requests.structures.CaseInsensitiveDict(headers or {})
    response.raw = CountingBytesIO(body)
    response.encoding = 'utf-8'
    response.url = URL

    return response


def note(part: str, complete: str) -> str:
    return f'[Artemis: log truncated, showing the {part} {MAX_SIZE} bytes of {complete}. Full log: {URL}]\n'


@pytest.fixture(name='guest_log')
def fixture_guest_log() -> MagicMock:
    guest_log = MagicMock(spec=GuestLog)
    guest_log.logname = 'anaconda.log:dump'
    guest_log.contenttype = GuestLogContentType.BLOB
    guest_log.blobs = []

    return guest_log


@pytest.fixture(name='max_size')
def fixture_max_size(mockpatch: MockPatcher) -> MagicMock:
    return mockpatch(tft.artemis.drivers.KNOB_UPDATE_GUEST_REQUEST_LOG_MAX_SIZE, 'get_value', return_value=Ok(MAX_SIZE))


def fetch(logger: ContextAdapter, guest_log: MagicMock, **kwargs: Any) -> Any:
    return tft.artemis.drivers._guest_log_http.fetch_guest_log_blob(
        logger, 'dummy-pool', guest_log, URL, failure_message='failed to fetch log', **kwargs
    )


def test_request(logger: ContextAdapter, mockpatch: MockPatcher, guest_log: MagicMock, max_size: MagicMock) -> None:
    mock_requests_get = mockpatch(requests, 'get', return_value=make_response(200, b'0123456789'))

    r_progress = fetch(logger, guest_log)

    assert r_progress.is_ok

    progress = r_progress.unwrap()

    assert progress.state == GuestLogState.IN_PROGRESS
    assert progress.overwrite is True
    assert len(progress.blobs) == 1

    max_size.assert_called_once_with(entityname='dummy-pool:anaconda.log:dump/blob')

    _, kwargs = mock_requests_get.call_args

    assert kwargs['stream'] is True
    assert kwargs['headers']['Range'] == f'bytes=-{MAX_SIZE}'
    assert kwargs['headers']['Accept-Encoding'] == 'identity'


@pytest.mark.parametrize(
    ('status_code', 'body', 'headers', 'expected'),
    [
        (200, b'0123456789', {'Content-Length': '10'}, '0123456789'),
        # Range larger than the log: the server returns the whole log as a partial response.
        (206, b'01234', {'Content-Range': 'bytes 0-4/5'}, '01234'),
        (
            206,
            b'9012345678',
            {'Content-Range': 'bytes 603979766-603979775/603979776'},
            note('last', '603979776 bytes') + '9012345678',
        ),
        (206, b'9012345678', {}, note('last', 'more than 10 bytes') + '9012345678'),
        # The tail starts in the middle of a multibyte character.
        (
            206,
            'ž123456789'.encode()[1:],
            {'Content-Range': 'bytes 1-10/11'},
            note('last', '11 bytes') + '\ufffd123456789',
        ),
        # Server ignores the range and sends the whole log.
        (200, b'0123456789' * 1024, {'Content-Length': '10240'}, note('first', '10240 bytes') + '0123456789'),
        # Lying about the size must not make Artemis read the whole body.
        (200, b'0123456789' * 1024, {'Content-Length': '5'}, note('first', '5 bytes') + '0123456789'),
        (200, b'0123456789' * 1024, {}, note('first', 'more than 10 bytes') + '0123456789'),
        # Range of an empty log cannot be satisfied.
        (416, b'', {'Content-Range': 'bytes */0'}, ''),
    ],
    ids=[
        'small-log',
        'complete-partial-content',
        'tail',
        'tail-without-content-range',
        'tail-multibyte',
        'head-honest-content-length',
        'head-lying-content-length',
        'head-without-content-length',
        'empty-log',
    ],
)
def test_content(
    logger: ContextAdapter,
    mockpatch: MockPatcher,
    guest_log: MagicMock,
    max_size: MagicMock,
    status_code: int,
    body: bytes,
    headers: dict[str, str],
    expected: str,
) -> None:
    response = make_response(status_code, body, headers)

    mockpatch(requests, 'get', return_value=response)

    r_progress = fetch(logger, guest_log)

    assert r_progress.is_ok
    assert r_progress.unwrap().blobs[0].content == expected

    # Never read more than one byte past the limit.
    assert response.raw.bytes_read == min(len(body), MAX_SIZE + 1)


@pytest.mark.parametrize(
    'outcome',
    [make_response(500, b'oops'), requests.exceptions.ConnectionError('connection refused')],
    ids=['http-error', 'connection-error'],
)
def test_error(
    logger: ContextAdapter,
    mockpatch: MockPatcher,
    guest_log: MagicMock,
    max_size: MagicMock,
    outcome: Union[requests.Response, Exception],
) -> None:
    # A list makes the mock return the response, or raise the exception.
    mockpatch(requests, 'get').side_effect = [outcome]

    r_progress = fetch(logger, guest_log)

    assert r_progress.is_error

    failure = r_progress.unwrap_error()

    assert failure.message == 'failed to fetch log'
    assert failure.details['url'] == URL


def test_failure_from_response(
    logger: ContextAdapter, mockpatch: MockPatcher, guest_log: MagicMock, max_size: MagicMock
) -> None:
    mockpatch(requests, 'get', return_value=make_response(404, b'no such log'))

    def _failure_from_response(response: requests.Response) -> Failure:
        return Failure('unexpected response', status_code=response.status_code, body=response.text)

    r_progress = fetch(logger, guest_log, failure_from_response=_failure_from_response)

    assert r_progress.is_error

    failure = r_progress.unwrap_error()

    assert failure.message == 'unexpected response'
    assert failure.details['status_code'] == 404
    assert failure.details['body'] == 'no such log'


def test_default_max_size() -> None:
    r_max_size = tft.artemis.drivers.KNOB_UPDATE_GUEST_REQUEST_LOG_MAX_SIZE.get_value(
        entityname='dummy-pool:anaconda.log:dump/blob'
    )

    assert r_max_size.is_ok
    assert r_max_size.unwrap() == 32 * 1024 * 1024
