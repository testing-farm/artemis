# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import re
from typing import Any, Optional, cast

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
from .refresh_pool_image_info import refresh_pool_image_info

KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-image-info.schedule',
    'When to run pool image info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_IMAGE_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *',
)

KNOB_REFRESH_POOL_IMAGE_INFO_GROUPS: Knob[list[DispatcherGroup]] = Knob(
    'actor.refresh-pool-image-info.groups',
    """
    Image info refresh groups, as a semicolon-separated list of `PATTERN:CRONTAB` entries, where
    `PATTERN` is a regular expression matched against pool names, and `CRONTAB` is a Cron-like schedule.
    For example, `ibmcloud-.*:0/27 * * * *`. Groups are independent, so patterns should be kept disjoint. Pools
    matching no group are refreshed by an implicit catch-all on the plain schedule knob, so no explicit catch-all
    group is needed. Empty (the default) means a single group refreshing all pools on the plain schedule knob.
    """,
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_IMAGE_INFO_GROUPS',
    cast_from_str=parse_dispatcher_groups,
    default=[],
)


class Workspace(_Workspace):
    """
    Workspace for hostname groups refresh dispatcher.
    """

    TASKNAME = 'refresh-pool-image-info-dispatcher'

    #: Compiled regular expression selecting, by name, which pools this dispatcher run refreshes. Set per group.
    poolname_pattern: re.Pattern[str]

    #: Compiled regular expressions whose pools this dispatcher run excludes. Empty for a normal group; set to
    #: every configured group's pattern for the implicit catch-all actor, so it refreshes the pools no group covers.
    exclude_patterns: list[re.Pattern[str]]

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        poolname_pattern: re.Pattern[str],
        exclude_patterns: Optional[list[re.Pattern[str]]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(logger, session, **kwargs)

        self.poolname_pattern = poolname_pattern
        self.exclude_patterns = exclude_patterns or []

    @step
    def run(self) -> None:
        with self.transaction() as transaction:
            self.load_pools(transaction)

            if self.result:
                return

            self._progress(transaction, 'scheduling pool image info refresh')

            for pool in self.pools_matching_name(self.poolname_pattern, self.exclude_patterns):
                if self.result:
                    return

                self.dispatch_task(
                    transaction,
                    refresh_pool_image_info,
                    pool.poolname,
                    logger=get_pool_logger(Workspace.TASKNAME, self.logger, pool.poolname),
                )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname_pattern: re.Pattern[str],
        exclude_patterns: Optional[list[re.Pattern[str]]] = None,
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param poolname_pattern: compiled regular expression (:py:class:`re.Pattern`) selecting, by name, which
            pools to refresh.
        :param exclude_patterns: compiled regular expressions whose pools to exclude. Empty for a normal group;
            every configured group's pattern for the implicit catch-all actor.
        :returns: newly created workspace.
        """

        return cls(
            logger,
            session,
            db=db,
            task=Workspace.TASKNAME,
            poolname_pattern=poolname_pattern,
            exclude_patterns=exclude_patterns,
        )

    @classmethod
    def refresh_pool_image_info_dispatcher(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        poolname_pattern: re.Pattern[str],
        exclude_patterns: Optional[list[re.Pattern[str]]] = None,
    ) -> DoerReturnType:
        """
        Schedule image info refresh for the pools whose name matches the given pattern and matches none of the
        excluded patterns.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param poolname_pattern: compiled regular expression (:py:class:`re.Pattern`) selecting, by name, which
            pools to refresh.
        :param exclude_patterns: compiled regular expressions whose pools to exclude. Empty for a normal group;
            every configured group's pattern for the implicit catch-all actor.
        :returns: task result.
        """

        return cls.create(logger, db, session, poolname_pattern, exclude_patterns).begin().run().complete().final_result


# Register one periodic dispatcher actor per configured group - this is what makes periodiq schedule the
# dispatcher several times, on different intervals and for different sets of pools. With groups configured, an
# implicit catch-all actor is also registered on the default schedule to refresh pools no group matches. With no
# groups configured, a single actor named `refresh_pool_image_info_dispatcher` is registered, preserving the
# original behavior.
register_pool_dispatcher_actors(
    globals(),
    base_actor_name='refresh_pool_image_info_dispatcher',
    taskname=Workspace.TASKNAME,
    doer=cast(DoerType, Workspace.refresh_pool_image_info_dispatcher),
    groups=KNOB_REFRESH_POOL_IMAGE_INFO_GROUPS.value,
    default_schedule=KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE.value,
)
