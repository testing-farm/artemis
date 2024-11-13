# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Try to find a suitable guest, which can satisfy the request from the specified shelf.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import json
import uuid
from typing import Any, Optional, cast

import gluetool.log
import sqlalchemy
import sqlalchemy.orm.session

from .. import Failure
from ..api.environment import DEFAULT_SSH_PORT, DEFAULT_SSH_USERNAME
from ..api.models import GuestRequest as GuestRequestSchema
from ..db import DB, DMLResult, GuestLogContentType, GuestRequest, execute_dml
from ..environment import Environment
from ..guest import GuestState
from . import _ROOT_LOGGER, DoerReturnType, DoerType
from . import Workspace as _Workspace
from . import get_shelf_logger, step, task, task_core
from .guest_shelf_lookup import guest_shelf_lookup


class Workspace(_Workspace):
    """
    Workspace for guest shelf lookup task.
    """

    TASKNAME = 'preprovision'

    guest_template: GuestRequestSchema
    guest_count: int
    # ownername: str
    # environment: Environment
    # log_types: List[Tuple[str, GuestLogContentType]]

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        shelfname: str,
        guest_template: GuestRequestSchema,
        guest_count: int,
        guestname: Optional[str] = None,
        task: Optional[str] = None,
        db: Optional[DB] = None,
        **default_details: Any
    ) -> None:
        super().__init__(logger, session, guestname=guestname, task=task, db=db)

        self.shelfname = shelfname
        self.guest_template = guest_template
        self.guest_count = guest_count

    @step
    def run(self) -> None:
        log_types = []

        if self.guest_template.log_types:
            try:
                log_types = [
                    (logtype, GuestLogContentType(contenttype))
                    for (logtype, contenttype) in self.guest_template.log_types
                ]

            except Exception as exc:
                return self._fail(
                    Failure.from_exc('failed to parse log types', exc),
                    'failed to parse log types'
                )

        try:
            environment = Environment.unserialize(self.guest_template.environment)

        except Exception as exc:
            return self._fail(
                Failure.from_exc('failed to parse environment', exc),
                'failed to parse guest template environment'
            )

        with self.transaction():
            assert self.shelfname

            self.load_shelf(self.shelfname, state=GuestState.READY)

            if self.result:
                return

            assert self.shelf

            from .return_guest_to_shelf import return_guest_to_shelf

            for _ in range(self.guest_count):
                if self.result:
                    return

                guestname = str(uuid.uuid4())

                stmt = GuestRequest.create_query(
                    guestname=guestname,
                    environment=environment,
                    ownername=self.shelf.ownername,
                    shelfname=self.shelfname,
                    ssh_keyname=self.guest_template.keyname,
                    ssh_port=DEFAULT_SSH_PORT,
                    ssh_username=DEFAULT_SSH_USERNAME,
                    priorityname=self.guest_template.priority_group,
                    user_data=self.guest_template.user_data,
                    skip_prepare_verify_ssh=self.guest_template.skip_prepare_verify_ssh,
                    post_install_script=self.guest_template.post_install_script,
                    log_types=log_types,
                    watchdog_dispatch_delay=self.guest_template.watchdog_dispatch_delay,
                    watchdog_period_delay=self.guest_template.watchdog_period_delay,
                    bypass_shelf_lookup=True,
                    on_ready=[(return_guest_to_shelf, [GuestState.READY.value])],
                    security_group_rules_ingress=None,
                    security_group_rules_egress=None
                )

                r_create: DMLResult[GuestRequest] = execute_dml(
                    self.logger,
                    self.session,
                    stmt
                )

                if r_create.is_error:
                    return self._error(r_create, 'failed to create new guest')

                GuestRequest.log_event_by_guestname(
                    self.logger,  # shelf logger, does not contain guestname
                    self.session,
                    guestname,
                    'created',
                    **{
                        'environment': environment.serialize(),
                        'user_data': self.guest_template.user_data
                    }
                )

                self.request_task(guest_shelf_lookup, guestname)

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        shelfname: str,
        guest_template: str,
        guest_count: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param shelfname: name of the shelf to create guests for.
        :param guest_template: Template of a guest to be pre-provisioned.
        :param guest_count: Number of guests to be created.
        :returns: task result.
        """

        return cls(
            logger,
            session,
            task=cls.TASKNAME,
            shelfname=shelfname,
            guest_template=GuestRequestSchema(**json.loads(guest_template)),
            guest_count=int(guest_count)
        )

    @classmethod
    def preprovision(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        shelfname: str,
        guest_template: str,
        guest_count: str
    ) -> DoerReturnType:
        """
        Create and dispatch provisioning for the specified number of new guests.

        .. note::

           Task must be aware of the possibility of another task performing the same job at the same time. All changes
           must preserve consistent and restartable state.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param shelfname: name of the shelf to create guests for.
        :param guest_template: Template of a guest to be pre-provisioned.
        :param guest_count: Number of guests to be created.
        :returns: task result.
        """

        return cls.create(logger, db, session, shelfname, guest_template, guest_count) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task()
def preprovision(shelfname: str, guest_template: str, guest_count: str) -> None:
    """
    Attempt to find a suitable guest in a shelf (if specified).

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.preprovision),
        logger=get_shelf_logger(Workspace.TASKNAME, _ROOT_LOGGER, shelfname),
        doer_args=(shelfname, guest_template, guest_count)
    )
