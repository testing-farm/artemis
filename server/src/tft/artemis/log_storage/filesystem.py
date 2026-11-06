from ._base import LogStorage
import tempfile
from ..db import GuestRequest, GuestLog
from pathlib import Path
import abc
import dataclasses
from typing import Generic, TypeVar, Protocol, TypeAlias, Iterator, override, IO
from gluetool.log import ContextAdapter
from .. import Failure
from returns.result import Result as _Result, Success as _Ok, Failure as _Error
import datetime
from returns.pipeline import is_successful
from ..knobs import Knob
from .. import render_template, template_environment
from ..drivers import GuestLogBlob


KNOB_LOG_STORAGE_ROOT: Knob[Path] = Knob(
    'foo',
    'bar',
    has_db=False,
    envvar='ARTEMIS_LOG_STORAGE_FILESYSTEM_ROOT',
    cast_from_str=Path,
    default=None,
)

KNOB_LOG_STORAGE_BLOB_FILEPATH_TEMPLATE: Knob[str] = Knob(
    'foo',
    'bar',
    has_db=False,
    envvar='ARTEMIS_LOG_STORAGE_FILESYSTEM_BLOB_FILEPATH_TEMPLATE',
    cast_from_str=str,
    default='{{ GUESTNAME[:2] }}/{{ GUESTNAME }}/{{ LOG.logname }}/{{ LOG.contenttype.value }}/{{ BLOB.ctime }}.log',
)

KNOB_LOG_STORAGE_BLOB_URL_TEMPLATE: Knob[str] = Knob(
    'foo',
    'bar',
    has_db=False,
    envvar='ARTEMIS_LOG_STORAGE_FILESYSTEM_BLOB_URL_TEMPLATE',
    cast_from_str=str,
    default='http://localhost:8002/{{ KEY }}',
)


class FilesystemLogStorage(LogStorage):
    NAME = 'filesystem'

    @classmethod
    def generate_blob_key(cls, guest_request: GuestRequest, log: GuestLog, blob: GuestLogBlob) -> _Result[str, Failure]:
        return render_template(
            KNOB_LOG_STORAGE_BLOB_FILEPATH_TEMPLATE.value,
            LOG=log,
            BLOB=blob,
            **template_environment(guest_request)
        )

    @classmethod
    def _blob_storage_location(cls, guest_request: GuestRequest, log: GuestLog, blob: GuestLogBlob) -> _Result[tuple[str, Path], Failure]:
        return cls.generate_blob_key(guest_request, log, blob) \
            .map(lambda key: (key, KNOB_LOG_STORAGE_ROOT.value / key))

    @override
    def store(self, logger: ContextAdapter, guest_request: GuestRequest, log: GuestLog, blob: GuestLogBlob) -> _Result[str, Failure]:
        r_storage_location = self._blob_storage_location(guest_request, log, blob)

        if not is_successful(r_storage_location):
            return _Error(r_storage_location.failure())

        storage_key, storage_path = r_storage_location.unwrap()

        try:
            storage_path.parent.mkdir(parents=True, exist_ok=True)

        except Exception as exc:
            return _Error(Failure.from_exc('failed to create storage directory', exc))

        with tempfile.NamedTemporaryFile(
            delete=False,
            dir=KNOB_LOG_STORAGE_ROOT.value,
            prefix=f'{guest_request.guestname}-{log.logname}-{log.contenttype.value}-{blob.ctime}',
            suffix='.log'
        ) as f:
            temporary_filepath = Path(f.name)

            temporary_filepath.write_bytes(blob.content.encode())

            temporary_filepath.rename(storage_path)

        return _Ok(storage_key)

    @override
    def read(self, key: str) -> _Result[bytes, Failure]:
        storage_path = KNOB_LOG_STORAGE_ROOT.value / key

        try:
            return _Ok(storage_path.read_bytes())

        except Exception as exc:
            return _Error(Failure.from_exc('failed to read log file', exc, storage_path=str(storage_path)))

    @override
    def url(self, key: str) -> _Result[str, Failure]:
        return render_template(
            KNOB_LOG_STORAGE_BLOB_URL_TEMPLATE.value,
            KEY=key,
        )
