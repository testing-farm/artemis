import argparse

import gluetool.log
from gluetool.result import Result

import artemis
import artemis.environment
from artemis import Failure
from artemis.guest import Guest

# Type annotations
from typing import Any, Dict, Optional
import threading


class PoolCapabilities(argparse.Namespace):
    supports_snapshots = False


class PoolDriver(gluetool.log.LoggerMixin):
    def __init__(self, logger: gluetool.log.ContextAdapter, pool_config: Dict[str, Any]) -> None:
        super(PoolDriver, self).__init__(logger)

        self.pool_config = pool_config

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[Guest, Failure]:
        raise NotImplementedError()

    def can_acquire(
        self,
        environment: artemis.environment.Environment
    ) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.
        """

        raise NotImplementedError()

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: artemis.environment.Environment,
        master_key: artemis.db.SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key used for SSH connection.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        raise NotImplementedError()

    def release_guest(self, guest: Guest) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, Failure]
        """

        raise NotImplementedError()

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        # nothing yet, thinking about what capabilities might Beaker provide...

        return Result.Ok(PoolCapabilities())
