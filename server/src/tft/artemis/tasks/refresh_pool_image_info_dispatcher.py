# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Find the most suitable pool for a given request, and dispatch its provisioning.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

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
from .refresh_pool_image_info import refresh_pool_image_info

KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE: Knob[str] = Knob(
    'actor.refresh-pool-image-info.schedule',
    'When to run pool image info refresh task, as a Cron-like specification.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_IMAGE_INFO_SCHEDULE',
    cast_from_str=str,
    default='*/5 * * * *',
)

KNOB_REFRESH_POOL_IMAGE_INFO_POOL_TAG_FILTER: Knob[str] = Knob(
    'actor.refresh-pool-image-info.pool-tag-filter',
    'If set, only pools matching this pool-tag filter get their image info refreshed. Forms: "key=value" (that'
    ' tag and value), "key" (tag present, any value), "!key" (tag absent - the catch-all for ungrouped pools),'
    ' "key!=value" (not that value, including pools lacking the tag). Empty (the default) means all pools.',
    has_db=False,
    envvar='ARTEMIS_ACTOR_REFRESH_POOL_IMAGE_INFO_POOL_TAG_FILTER',
    cast_from_str=str,
    default='',
)

KNOB_REFRESH_POOL_IMAGE_INFO_GROUPS: Knob[list[DispatcherGroup]] = Knob(
    'actor.refresh-pool-image-info.groups',
    'JSON array of image-info refresh groups. Each group is an object with keys name, schedule and'
    ' pool-tag-filter, for example a group named "slow" with schedule "*/15 * * * *" and'
    ' pool-tag-filter "refresh-group=slow". When the groups together cover all pools, every pool is'
    ' refreshed on its group schedule. Empty (the default) means a single group using the plain'
    ' schedule and pool-tag-filter knobs.',
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

    #: Pool-tag filter selecting which pools this dispatcher run refreshes. Set per group; empty means all pools.
    tag_filter: str = ''

    @step
    def run(self) -> None:
        with self.transaction() as transaction:
            self.load_pools(transaction)

            if self.result:
                return

            self._progress(transaction, 'scheduling pool image info refresh')

            for pool in self.pools_matching_tag(self.tag_filter):
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
        tag_filter: str = '',
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param tag_filter: pool-tag filter selecting which pools to refresh. Empty means all pools.
        :returns: newly created workspace.
        """

        workspace = cls(logger, session, db=db, task=Workspace.TASKNAME)
        workspace.tag_filter = tag_filter

        return workspace

    @classmethod
    def refresh_pool_image_info_dispatcher(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        tag_filter: str = '',
    ) -> DoerReturnType:
        """
        Schedule image info refresh for the pools matching the given pool-tag filter.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param tag_filter: pool-tag filter selecting which pools to refresh. Empty means all pools.
        :returns: task result.
        """

        return cls.create(logger, db, session, tag_filter=tag_filter).begin().run().complete().final_result


# Register one periodic dispatcher actor per configured group - this is what makes periodiq schedule the
# dispatcher several times, on different intervals and for different sets of pools. With no groups configured,
# a single actor named `refresh_pool_image_info_dispatcher` is registered, preserving the original behavior.
register_pool_dispatcher_actors(
    globals(),
    base_actor_name='refresh_pool_image_info_dispatcher',
    taskname=Workspace.TASKNAME,
    doer=cast(DoerType, Workspace.refresh_pool_image_info_dispatcher),
    groups=KNOB_REFRESH_POOL_IMAGE_INFO_GROUPS.value,
    default_schedule=KNOB_REFRESH_POOL_IMAGE_INFO_SCHEDULE.value,
    default_tag_filter=KNOB_REFRESH_POOL_IMAGE_INFO_POOL_TAG_FILTER.value,
)
