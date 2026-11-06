import abc
from ..db import GuestRequest, GuestLog
import dataclasses
from typing import Generic, TypeVar, Protocol, TypeAlias, Iterator, IO
from gluetool.log import ContextAdapter
from .. import Failure
from returns.result import Result as _Result, Success as _Ok, Failure as _Error
import datetime
from returns.pipeline import is_successful
from ..drivers import GuestLogBlob


class LogStorage(abc.ABC):
    NAME: str

    @classmethod
    @abc.abstractmethod
    def generate_blob_key(cls, guest_request: GuestRequest, log: GuestLog, blob: GuestLogBlob) -> _Result[str, Failure]:
        raise NotImplementedError

    @abc.abstractmethod
    def store(self, logger: ContextAdapter, guest_request: GuestRequest, log: GuestLog, blob: GuestLogBlob) -> _Result[str, Failure]:
        raise NotImplementedError

    @abc.abstractmethod
    def read(self, key: str) -> _Result[bytes, Failure]:
        raise NotImplementedError

#    @abc.abstractmethod
#    def open(self, key: str) -> _Result[IO[bytes], Failure]:
#        raise NotImplementedError

    @abc.abstractmethod
    def url(self, key: str) -> _Result[str, Failure]:
        raise NotImplementedError

#    @abc.abstractmethod
#    def iter_keys(self, logger: ContextAdapter) -> Iterator[tuple[str, datetime.datetime]]:
#        raise NotImplementedError

#    def open(self, logger, key: str) -> Result[IO[bytes], Failure]: ...   # streaming read
#    def fetch(self, logger, key: str) -> Result[str, Failure]: ...        # convenience for old API versions
#    def delete(self, logger, keys: list[str]) -> Result[int, Failure]: ...
