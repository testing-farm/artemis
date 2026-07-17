# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import datetime
import hashlib
from unittest.mock import MagicMock

import gluetool.log

from tft.artemis.db import GuestLog
from tft.artemis.drivers import GuestLogBlob, GuestLogUpdateProgress


def test_sanitize_content_replaces_null_bytes() -> None:
    assert GuestLogBlob.sanitize_content('\x00a\x00b\x00') == '\ufffda\ufffdb\ufffd'


def test_from_content_sanitizes_null_bytes() -> None:
    blob = GuestLogBlob.from_content('hello\x00world')

    assert blob.content == 'hello\ufffdworld'
    assert blob.content_hash == hashlib.sha256('hello\ufffdworld'.encode()).hexdigest()


def test_from_snapshot_sanitizes_null_bytes() -> None:
    logger = MagicMock(spec=gluetool.log.ContextAdapter)
    log = MagicMock(spec=GuestLog)
    log.blobs = []
    timestamp = datetime.datetime(2024, 1, 1)

    progress = GuestLogUpdateProgress.from_snapshot(
        logger,
        log,
        timestamp,
        'hello\x00world',
        lambda guest_log, ts, content, content_hash: False,
    )

    assert len(progress.blobs) == 1
    assert progress.blobs[0].content == 'hello\ufffdworld'

    expected_hash = hashlib.sha256('hello\ufffdworld'.encode()).hexdigest()
    assert progress.blobs[0].content_hash == expected_hash
