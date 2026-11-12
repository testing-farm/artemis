# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import re
from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from ..db import DB
from ..knobs import Knob
from . import (
    DispatcherGroup,
    DoerReturnType,
    DoerType,
    Workspace as _Workspace,
    get_pool_logger,
    parse_dispatcher_groups,
    register_pool_dispatcher_actors,
    step,
)
from .refresh_pool_flavor_info import refresh_pool_flavor_info

KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-flavor-info.schedule',
    'When to run OpenStack flavor info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_FLAVOR_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *',
)

KNOB_REFRESH_POOL_FLAVOR_INFO_GROUPS: Knob[list[DispatcherGroup]] = Knob(
    'actor.refresh-pool-flavor-info.groups',
    """
    Flavor info refresh groups, as a semicolon-separated list of `PATTERN:CRONTAB` entries, where
    `PATTERN` is a regular expression matched against pool names, and `CRONTAB` is a Cron-like schedule.
    For example, `ibmcloud-.*:0/27 * * * *;(?!ibmcloud-).*:*/5 * * * *`. Groups are independent, so patterns should be
    kept disjoint. Empty (the default) means a single group refreshing all pools on the plain schedule knob.
    """,
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_FLAVOR_INFO_GROUPS',
    cast_from_str=parse_dispatcher_groups,
    default=[],
)


class Workspace(_Workspace):
    """
    Workspace for hostname groups refresh dispatcher.
    """

    TASKNAME = 'refresh-pool-flavor-info-dispatcher'

    #: Compiled regular expression selecting, by name, which pools this dispatcher run refreshes. Set per group.
    poolname_pattern: re.Pattern[str] = re.compile('.*')

    @step
    def run(self) -> None:
        with self.transaction() as transaction:
            self.load_pools(transaction)

            if self.result:
                return

            self._progress(transaction, 'scheduling pool flavor info refresh')

            for pool in self.pools_matching_name(self.poolname_pattern):
                if self.result:
                    return

                self.dispatch_task(
                    transaction,
                    refresh_pool_flavor_info,
                    pool.poolname,
                    logger=get_pool_logger(Workspace.TASKNAME, self.logger, pool.poolname),
                )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname_pattern: re.Pattern[str] = re.compile('.*'),
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param poolname_pattern: compiled regular expression (:py:class:`re.Pattern`) selecting, by name, which
            pools to refresh.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, db=db, task=Workspace.TASKNAME)
        workspace.poolname_pattern = poolname_pattern

        return workspace

    @classmethod
    def refresh_pool_flavor_info_dispatcher(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname_pattern: re.Pattern[str] = re.compile('.*'),
    ) -> DoerReturnType:
        """
        Schedule flavor info refresh for the pools whose name matches the given pattern.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param poolname_pattern: compiled regular expression (:py:class:`re.Pattern`) selecting, by name, which
            pools to refresh.
        :returns: task result.
        """

        return cls.create(logger, db, session, poolname_pattern).begin().run().complete().final_result


# Register one periodic dispatcher actor per configured group - this is what makes periodiq schedule the
# dispatcher several times, on different intervals and for different sets of pools. With no groups configured,
# a single actor named `refresh_pool_flavor_info_dispatcher` is registered, preserving the original behavior.
register_pool_dispatcher_actors(
    globals(),
    base_actor_name='refresh_pool_flavor_info_dispatcher',
    taskname=Workspace.TASKNAME,
    doer=cast(DoerType, Workspace.refresh_pool_flavor_info_dispatcher),
    groups=KNOB_REFRESH_POOL_FLAVOR_INFO_GROUPS.value,
    default_schedule=KNOB_REFRESH_POOL_FLAVOR_INFO_SCHEDULE.value,
)
