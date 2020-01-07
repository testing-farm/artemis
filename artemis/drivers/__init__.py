import argparse
import sqlalchemy
from io import BytesIO

import gluetool.log
from gluetool.result import Result, Ok

from molten import Response, HTTP_404
from molten.contrib.prometheus import expose_metrics, _HEADERS

import artemis
import artemis.environment
from artemis import Failure, safe_call
from artemis import metrics
from artemis.guest import Guest, GuestState

# Type annotations
from typing import Any, List, Dict, Optional, Tuple, cast
import threading


class PoolCapabilities(argparse.Namespace):
    supports_snapshots = False


class PoolDriver(gluetool.log.LoggerMixin):
    def __init__(self, logger: gluetool.log.ContextAdapter, pool_config: Dict[str, Any]) -> None:
        super(PoolDriver, self).__init__(logger)

        self.pool_config = pool_config
        self.poolname = None

    def guest_factory(
        self,
        guest_request: artemis.db.GuestRequest,
        ssh_key: artemis.db.SSHKey
    ) -> Result[Guest, Failure]:
        raise NotImplementedError()

    def sanity(self) -> Result[bool, Failure]:
        """
        Do sanity checks after initializing the driver. Useful to check for pool configuration
        correctness or anything else.
        """
        return Ok(True)

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
        guest_request: artemis.db.GuestRequest,
        environment: artemis.environment.Environment,
        master_key: artemis.db.SSHKey,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        If the returned guest is missing an address, it is considered to be unfinished,
        and followup calls to ``update_guest`` would be scheduled by Artemis core.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key key: master key used for SSH connection.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, Failure]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        raise NotImplementedError()

    def update_guest(
        self,
        guest: Guest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[Guest, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.
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

    def current_guests_in_pool(self, session: sqlalchemy.orm.session.Session) -> List[artemis.db.GuestRequest]:
        return cast(List[artemis.db.GuestRequest],
                    session.query(artemis.db.GuestRequest)
                    .filter(artemis.db.GuestRequest.poolname == self.poolname)
                    .all())

    def metrics(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session
    ) -> Optional[Response]:
        """ Provide Promethues metrics about current pool state. """

        # Current metrics
        metrics.CURRENT_GUEST_REQUESTS_ALL_COUNT.set(
            float(session.query(artemis.db.GuestRequest).count())
        )

        guests = self.current_guests_in_pool(session)
        metrics.CURRENT_GUEST_REQUESTS_COUNT.labels(self.poolname).set(len(guests))

        for state in GuestState:
            guest_count = len([guest for guest in guests if guest.state == state.value])
            metrics.CURRENT_GUEST_REQUESTS_STATE_COUNT.labels(self.poolname, state.value).set(
                float(guest_count)
            )

        # Metrics from metrics table in db
        query = session.query(sqlalchemy.sql.func.sum(artemis.db.Metrics.count))

        result = safe_call(query.one)

        if result.is_error:
            cast(Failure, result.value).log(logger.warn,  # type: ignore
                                            label='unable to get metric via query: {}'.format(query))
            return Response(HTTP_404,
                            headers=_HEADERS,
                            stream=BytesIO('coundn\'t get metric(s)'.encode('utf-8')))

        all_count = cast(Tuple[int], result.value)[0] or 0
        metrics.GUEST_REQUESTS_ALL_COUNT.set(
            float(all_count)
        )

        query = session.query(sqlalchemy.sql.func.sum(artemis.db.Metrics.count)) \
            .filter(artemis.db.Metrics.poolname == self.poolname)

        result = safe_call(query.one)

        if result.is_error:
            cast(Failure, result.value).log(logger.warn,  # type: ignore
                                            label='unable to get metric via query: {}'.format(query))
            return Response(HTTP_404,
                            headers=_HEADERS,
                            stream=BytesIO('coundn\'t get metric(s)'.encode('utf-8')))

        pool_count = cast(Tuple[int], result.value)[0] or 0
        metrics.GUEST_REQUESTS_COUNT.labels(session, logger, self.poolname).set(
            float(pool_count)
        )

        for state in GuestState:
            query = session.query(artemis.db.Metrics) \
                        .filter(artemis.db.Metrics.poolname == self.poolname) \
                        .filter(artemis.db.Metrics.state == state.value)

            result = safe_call(query.one)

            if result.is_error:
                failure = cast(Failure, result.value)

                if not isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
                    failure.log(logger.warn,  # type: ignore
                                label='unable to get metric via query: {}'.format(query))
                    return Response(HTTP_404,
                                    headers=_HEADERS,
                                    stream=BytesIO('coundn\'t get metric(s)'.encode('utf-8')))

                count = 0

            else:
                count = cast(artemis.db.Metrics, result.value).count

            metrics.GUEST_REQUESTS_STATE_COUNT.labels(session, logger, self.poolname, state.value).set(
                float(count)
            )

        return expose_metrics()
