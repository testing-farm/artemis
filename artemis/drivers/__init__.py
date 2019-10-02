import argparse

from gluetool.result import Result

import artemis
from artemis.guest import Guest
from artemis.environment import Environment

# Type annotations
from typing import Any, Dict, Optional
import threading


class PoolCapabilities(argparse.Namespace):
    supports_snapshots = False


class PoolDriver:
    def __init__(self, server_config, pool_config):
        # type: (Dict[str, Any], Dict[str, Any]) -> None

        self.server_config = server_config
        self.pool_config = pool_config

    def can_acquire(self,
                    environment  # type: Environment
                   ):  # noqa
        # type: (...) -> Result[bool, str]
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """

        raise NotImplementedError()

    def acquire_guest(self,
                      environment,  # type: Environment
                      key,  # type: artemis.keys.Key
                      cancelled=None  # type: Optional[threading.Event]
                     ):  # noqa
        # type: (...) -> Result[Guest, str]
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key to upload to the guest.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, str]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        raise NotImplementedError()

    def release_guest(self, guest):
        # type: (Guest) -> Result[bool, str]
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        raise NotImplementedError()

    def capabilities(self):
        # type: () -> Result[PoolCapabilities, str]

        # nothing yet, thinking about what capabilities might Beaker provide...

        return Result.Ok(PoolCapabilities())
