# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union, cast

import fastapi
import gluetool.log
import redis
import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.orm.exc
from fastapi import Depends, Request, Response, status
from typing_extensions import Annotated

from ... import __VERSION__, Failure, FailureDetailsType, JSONSchemaType
from ... import db as artemis_db
from ... import log_dict_yaml, metrics, validate_data
from ...cache import get_cache_value, iter_cache_keys
from ...context import DATABASE, LOGGER, SESSION
from ...drivers import PoolDriver
from ...environment import Environment
from ...guest import GuestState
from ...knobs import KNOB_DEPLOYMENT, KNOB_DEPLOYMENT_ENVIRONMENT, Knob
from ...security_group_rules import SecurityGroupRule
from ...tasks import Actor, TaskCall, _get_ssh_key, get_snapshot_logger
from .. import environment as global_env
from .. import errors
from ..dependencies import get_db
from ..models import AboutResponse, AuthContext, ConsoleUrlResponse, CreateUserRequest, EventSearchParameters, \
    GuestEvent, GuestLogResponse, GuestRequest, GuestResponse, GuestShelfResponse, KnobResponse, KnobUpdateRequest, \
    PreprovisioningRequest, SnapshotRequest, SnapshotResponse, TokenResetResponse, TokenTypes, UserResponse
from ..models.v0_0_69 import GuestLogResponse_v0_0_69
from ..models.v0_0_72 import GuestRequest_v0_0_72, GuestResponse_v0_0_72

GuestLogResponseType = TypeVar('GuestLogResponseType', GuestLogResponse, GuestLogResponse_v0_0_69)
GuestResponseType = TypeVar('GuestResponseType', GuestResponse, GuestResponse_v0_0_72)
GuestRequestType = TypeVar('GuestRequestType', GuestRequest, GuestRequest_v0_0_72)


class GuestRequestManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    # NOTE(ivasilev) No idea why how to make mypy happy, muting for now
    def get_guest_requests(self, response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
                           ) -> List[GuestResponseType]:
        with self.db.get_session() as session:
            r_guests = artemis_db.SafeQuery.from_session(session, artemis_db.GuestRequest).all()

            if r_guests.is_error:
                raise errors.InternalServerError(caused_by=r_guests.unwrap_error())

            return [
                response_model.from_db(guest)
                for guest in r_guests.unwrap()
            ]

    def create(
        self,
        guest_request: GuestRequestType,
        ownername: str,
        logger: gluetool.log.ContextAdapter,
        environment_schema: JSONSchemaType,
        response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
    ) -> GuestResponseType:
        from ...tasks import get_guest_logger
        from ...tasks.guest_shelf_lookup import guest_shelf_lookup

        guestname = str(uuid.uuid4())

        failure_details = {
            'guestname': guestname,
            'raw_keyname': guest_request.keyname,
            'raw_environment': guest_request.environment,
            'raw_shelfname': guest_request.shelfname,
            'raw_user_data': guest_request.user_data,
            'raw_post_install_script': guest_request.post_install_script,
            'raw_log_types': guest_request.log_types
        }

        guest_logger = get_guest_logger('create-guest-request', logger, guestname)

        with self.db.get_session(transactional=True) as session:
            SESSION.set(session)

            # Validate guest request
            guest_request = _validate_guest_request(
                guest_logger,
                session,
                guest_request,
                ownername,
                environment_schema,
                failure_details
            )

            environment = _parse_environment(
                guest_logger,
                guest_request.environment,
                failure_details
            )

            security_group_rules_ingress = _parse_security_group_rules(
                guest_logger,
                guest_request.security_group_rules_ingress,
                failure_details
            )
            security_group_rules_egress = _parse_security_group_rules(
                guest_logger,
                guest_request.security_group_rules_egress,
                failure_details
            )

            create_guest_stmt = artemis_db.GuestRequest.create_query(
                guestname=guestname,
                environment=environment,
                ownername=global_env.DEFAULT_GUEST_REQUEST_OWNER,
                shelfname=guest_request.shelfname,
                ssh_keyname=guest_request.keyname,
                ssh_port=global_env.DEFAULT_SSH_PORT,
                ssh_username=global_env.DEFAULT_SSH_USERNAME,
                priorityname=guest_request.priority_group,
                user_data=guest_request.user_data,
                bypass_shelf_lookup=guest_request.bypass_shelf_lookup,
                skip_prepare_verify_ssh=guest_request.skip_prepare_verify_ssh,
                post_install_script=guest_request.post_install_script,
                log_types=_parse_log_types(logger, guest_request.log_types, failure_details),
                watchdog_dispatch_delay=guest_request.watchdog_dispatch_delay,
                watchdog_period_delay=guest_request.watchdog_period_delay,
                on_ready=[],
                security_group_rules_ingress=security_group_rules_ingress,
                security_group_rules_egress=security_group_rules_egress
            )

            r_create = artemis_db.execute_db_statement(guest_logger, session, create_guest_stmt)

            if r_create.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_create.unwrap_error(),
                    failure_details=failure_details
                )

            artemis_db.GuestRequest.log_event_by_guestname(
                guest_logger,
                session,
                guestname,
                'created',
                **{
                    'environment': environment.serialize(),
                    'user_data': guest_request.user_data,
                }
            )

            r_task = artemis_db.TaskRequest.create(guest_logger, session, guest_shelf_lookup, guestname)

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            guest_logger.info('created')
            log_dict_yaml(
                guest_logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(guest_shelf_lookup, guestname, task_request_id=task_request_id).serialize()
            )

            # Everything went well, update our accounting.
            metrics.ProvisioningMetrics.inc_requested()

        gr = self.get_by_guestname(guestname, response_model=response_model)

        if gr is None:
            # Now isn't this just funny... We just created the record, how could it be missing? There's probably
            # no point in trying to clean up what we started - if the guest is missing, right after we created it,
            # then things went south. At least it would get logged.
            raise errors.InternalServerError(
                logger=guest_logger,
                failure_details=failure_details
            )

        return gr

    def get_by_guestname(
        self,
        guestname: str,
        response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
    ) -> Optional[GuestResponseType]:
        with self.db.get_session() as session:
            r_guest_request_record = artemis_db.SafeQuery.from_session(session, artemis_db.GuestRequest) \
                .filter(artemis_db.GuestRequest.guestname == guestname) \
                .one_or_none()

            if r_guest_request_record.is_error:
                raise errors.InternalServerError(caused_by=r_guest_request_record.unwrap_error())

            guest_request_record = r_guest_request_record.unwrap()

            if guest_request_record is None:
                return None

            return response_model.from_db(guest_request_record)

    def delete_by_guestname(
        self,
        guestname: str,
        logger: gluetool.log.ContextAdapter,
        state: Optional[GuestState] = None
    ) -> None:
        from ...tasks import get_guest_logger
        from ...tasks.release_guest_request import release_guest_request
        from ...tasks.return_guest_to_shelf import return_guest_to_shelf

        failure_details = {
            'guestname': guestname
        }

        guest_logger = get_guest_logger('delete-guest-request', logger, guestname)

        with self.db.get_session(transactional=True) as session:
            gr_query = artemis_db.SafeQuery \
                .from_session(session, artemis_db.GuestRequest) \
                .filter(artemis_db.GuestRequest.guestname == guestname)

            if state is not None:
                gr_query = gr_query.filter(artemis_db.GuestRequest.state == state)

            r_guest_request = gr_query.one_or_none()

            if r_guest_request.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_guest_request.unwrap_error(),
                    failure_details=failure_details
                )

            # Once condemned, the request cannot change its state to anything else. It can only disappear.
            guest_request = r_guest_request.unwrap()

            if guest_request is None:
                raise errors.NoSuchEntityError(
                    logger=guest_logger,
                    failure_details=failure_details
                )

            current_state = guest_request.state
            guest_delete_task = release_guest_request
            extra_actor_args = []

            if guest_request.state == GuestState.READY:  # type: ignore[comparison-overlap]
                guest_delete_task = return_guest_to_shelf
                extra_actor_args = [GuestState.CONDEMNED.value]

            if guest_request.state != GuestState.CONDEMNED:  # type: ignore[comparison-overlap]
                snapshot_count_subquery = session.query(
                    sqlalchemy.func.count(artemis_db.SnapshotRequest.snapshotname).label('snapshot_count')
                ).filter(
                    artemis_db.SnapshotRequest.guestname == guestname
                ).subquery('t')

                query = sqlalchemy \
                    .update(artemis_db.GuestRequest.__table__) \
                    .where(artemis_db.GuestRequest.guestname == guestname) \
                    .where(snapshot_count_subquery.c.snapshot_count == 0) \
                    .values(state=GuestState.CONDEMNED)

                r_state = artemis_db.execute_db_statement(guest_logger, session, query)

                # The query can miss either with existing snapshots, or when the guest request has been
                # removed from DB already. The "gone already" situation could be better expressed by
                # returning "404 Not Found", but we can't tell which of these two situations caused the
                # change to go vain, therefore returning general "409 Conflict", expressing our believe
                # user should resolve the conflict and try again.
                if r_state.is_error:
                    failure = r_state.unwrap_error()

                    if failure.details.get('serialization_failure', False):
                        raise errors.ConflictError(
                            logger=guest_logger,
                            caused_by=failure,
                            failure_details=failure_details
                        )

                    raise errors.InternalServerError(
                        logger=guest_logger,
                        caused_by=failure,
                        failure_details=failure_details
                    )

                artemis_db.GuestRequest.log_event_by_guestname(
                    guest_logger,
                    session,
                    guestname,
                    'condemned'
                )

                guest_logger.info('condemned')

            r_task = artemis_db.TaskRequest.create(
                guest_logger,
                session,
                guest_delete_task,
                guestname,
                *extra_actor_args
            )

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=guest_logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            log_dict_yaml(
                guest_logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(
                    guest_delete_task,
                    guestname,
                    task_request_id=task_request_id,
                    *extra_actor_args
                ).serialize()
            )

            metrics.ProvisioningMetrics.inc_guest_state_transition(
                guest_request.poolname,
                current_state,
                GuestState.CONDEMNED
            )

    def acquire_guest_console_url(
        self,
        guestname: str,
        logger: gluetool.log.ContextAdapter
    ) -> ConsoleUrlResponse:
        from ...tasks import acquire_guest_console_url as task_acquire_guest_console_url
        from ...tasks import dispatch_task

        r_dispatch = dispatch_task(logger, task_acquire_guest_console_url, guestname)
        if r_dispatch.is_error:
            raise errors.InternalServerError(caused_by=r_dispatch.unwrap_error(), logger=logger)

        return ConsoleUrlResponse(url=None, expires=None)


def acquire_guest_console_url(
        guestname: str,
        request: Request,
        manager: GuestRequestManager,
        logger: gluetool.log.ContextAdapter
) -> ConsoleUrlResponse:
    from ...tasks import get_guest_logger
    console_url_logger = get_guest_logger('acquire-guest-console-url', logger, guestname)

    # first see if the console has already been created and isn't expired yet
    gr = manager.get_by_guestname(guestname)
    if not gr:
        # no such guest found, aborting
        raise errors.NoSuchEntityError(request=request, logger=console_url_logger)
    console_url_response = ConsoleUrlResponse(
        url=gr.console_url,
        expires=gr.console_url_expires
    )
    has_expired = gr.console_url_expires and gr.console_url_expires < datetime.datetime.utcnow()
    if not gr.console_url or has_expired:
        if has_expired:
            logger.warning(f'Guest console url {console_url_response.url} has expired, will fetch a new one')
        else:
            logger.warning('Fetching a new guest console url')
        console_url_response = manager.acquire_guest_console_url(guestname, console_url_logger)
    return console_url_response


def _validate_guest_request(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guest_request: 'GuestRequestType',
    ownername: str,
    environment_schema: JSONSchemaType,
    failure_details: FailureDetailsType
) -> 'GuestRequestType':
    SESSION.set(session)

    guest_request.environment = _validate_environment(
        logger,
        guest_request.environment,
        environment_schema,
        failure_details
    )

    environment = _parse_environment(logger, guest_request.environment, failure_details)

    # Validate log_types
    _parse_log_types(logger, guest_request.log_types, failure_details)

    # Check whether key exists - still open to race condition, but the window is quite short,
    # and don't rely on this test when we actually create request. All we need here is a better
    # error message for user when they enter invalid key name.
    r_key = _get_ssh_key(ownername, guest_request.keyname)

    if r_key.is_error:
        raise errors.InternalServerError(
            logger=logger,
            caused_by=r_key.unwrap_error(),
            failure_details=failure_details
        )

    if r_key.unwrap() is None:
        raise errors.BadRequestError(
            message='No such SSH key exists',
            logger=logger,
            failure_details=failure_details
        )

    # Check whether pool exists - still open to race condition, but the window is quite short,
    # and we don't rely on this test when we actually create request. All we need here is a better
    # error message for user when they enter invalid pool name.
    if environment.pool is not None:
        r_pool = PoolDriver.load_or_none(logger, session, environment.pool)

        if r_pool.is_error:
            raise errors.InternalServerError(
                logger=logger,
                caused_by=r_pool.unwrap_error(),
                failure_details=failure_details
            )

        if r_pool.unwrap() is None:
            raise errors.BadRequestError(
                message='No such pool exists',
                logger=logger,
                failure_details=failure_details
            )

    # Validate the requested shelf is ready and can be used to serve guests.
    if guest_request.shelfname is not None:
        r_shelf = artemis_db.SafeQuery.from_session(session, artemis_db.GuestShelf) \
            .filter(artemis_db.GuestShelf.shelfname == guest_request.shelfname) \
            .filter(artemis_db.GuestShelf.state == GuestState.READY) \
            .one_or_none()

        if r_shelf.is_error:
            raise errors.InternalServerError(
                logger=logger,
                caused_by=r_shelf.unwrap_error(),
                failure_details=failure_details
            )

        if r_shelf.unwrap() is None:
            raise errors.BadRequestError(
                message='No such shelf exists',
                logger=logger,
                failure_details=failure_details
            )

    return guest_request


def _environment_compat(
    environment: Dict[str, Optional[Any]]
) -> Dict[str, Optional[Any]]:
    # COMPAT: v0.0.17, v0.0.18: `environment.arch` belongs to `environment.hw.arch`
    if 'arch' in environment:
        environment['hw'] = {
            'arch': environment.pop('arch')
        }

    # COMPAT: v0.0.53+: `kickstart` is now mandatory by implementation, yet older APIs
    # do not know about it.
    if 'kickstart' not in environment:
        environment['kickstart'] = {}

    return environment


def _validate_environment(
    logger: gluetool.log.ContextAdapter,
    environment: Dict[str, Optional[Any]],
    schema: JSONSchemaType,
    failure_details: FailureDetailsType
) -> Dict[str, Optional[Any]]:
    r_validation = validate_data(environment, schema)

    if r_validation.is_error:
        raise errors.InternalServerError(
            logger=logger,
            caused_by=r_validation.unwrap_error(),
            failure_details=failure_details
        )

    validation_errors = r_validation.unwrap()

    if validation_errors:
        failure_details['api_request_validation_errors'] = json.dumps(validation_errors)

        raise errors.BadRequestError(
            response={
                'message': 'Environment failed validation',
                'errors': validation_errors
            },
            logger=logger,
            failure_details=failure_details
        )

    return _environment_compat(environment)


def _parse_environment(
    logger: gluetool.log.ContextAdapter,
    environment: Dict[str, Optional[Any]],
    failure_details: FailureDetailsType
) -> Environment:
    try:
        return Environment.unserialize(environment)

    except Exception as exc:
        raise errors.BadRequestError(
            response={
                'message': 'Bad request'
            },
            logger=logger,
            caused_by=Failure.from_exc('failed to parse environment', exc),
            failure_details=failure_details
        )


def _parse_security_group_rules(
    logger: gluetool.log.ContextAdapter,
    security_group_rules: Optional[List[Dict[str, Any]]],
    failure_details: FailureDetailsType
) -> Optional[List[SecurityGroupRule]]:
    try:
        return [SecurityGroupRule.unserialize(rule) for rule in security_group_rules] if security_group_rules else None

    except Exception as exc:
        raise errors.BadRequestError(
            response={
                'message': 'Bad request'
            },
            logger=logger,
            caused_by=Failure.from_exc('failed to parse security group rules', exc),
            failure_details=failure_details
        )


def _parse_log_types(
    logger: gluetool.log.ContextAdapter,
    log_types: Optional[List[Any]],
    failure_details: FailureDetailsType
) -> List[Tuple[str, artemis_db.GuestLogContentType]]:
    parsed_log_types: List[Tuple[str, artemis_db.GuestLogContentType]] = []

    if log_types:
        try:
            parsed_log_types = [
                (logtype, artemis_db.GuestLogContentType(contenttype))
                for (logtype, contenttype) in log_types
            ]
        except Exception as exc:
            raise errors.BadRequestError(
                message='Got an unsupported log type',
                logger=logger,
                caused_by=Failure.from_exc('cannot convert log type to GuestLogContentType object', exc),
                failure_details=failure_details
            )

    return parsed_log_types


# NOTE(ivasilev) No idea why how to make mypy happy, muting for now
def get_guest_requests(
    manager: GuestRequestManager,
    request: Request,
    response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
) -> List[GuestResponseType]:
    return manager.get_guest_requests(response_model=response_model)


# NOTE(ivasilev) No idea why how to make mypy happy, muting for now
def get_guest_request(
    guestname: str,
    manager: GuestRequestManager,
    request: Request,
    response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
) -> GuestResponseType:
    guest_response = manager.get_by_guestname(guestname, response_model=response_model)

    if guest_response is None:
        raise errors.NoSuchEntityError(request=request)

    return guest_response


def delete_guest(
    guestname: str,
    request: Request,
    logger: gluetool.log.ContextAdapter,
    manager: GuestRequestManager
) -> None:
    guest = manager.get_by_guestname(guestname)

    if not guest:
        raise errors.NoSuchEntityError(request=request)

    if guest.state == GuestState.SHELVED:
        raise errors.ConflictError(request=request)

    manager.delete_by_guestname(guestname, logger)

    return None


class GuestEventManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    def get_events(
        self,
        search_params: EventSearchParameters
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                page=search_params.page,
                page_size=search_params.page_size,
                sort_field=search_params.sort_field,
                sort_order=search_params.sort_order,
                since=search_params.since,
                until=search_params.until
            )
            if r_events.is_error:
                raise errors.InternalServerError(caused_by=r_events.unwrap_error())

            return [
                GuestEvent.from_db(event_record)
                for event_record in r_events.unwrap()
            ]

    def get_events_by_guestname(
        self,
        guestname: str,
        search_params: EventSearchParameters
    ) -> List[GuestEvent]:
        with self.db.get_session() as session:
            r_events = artemis_db.GuestEvent.fetch(
                session,
                guestname=guestname,
                page=search_params.page,
                page_size=search_params.page_size,
                sort_field=search_params.sort_field,
                sort_order=search_params.sort_order,
                since=search_params.since,
                until=search_params.until
            )

            if r_events.is_error:
                raise errors.InternalServerError(caused_by=r_events.unwrap_error())

            return [
                GuestEvent.from_db(event_record)
                for event_record in r_events.unwrap()
            ]


def perform_safe_db_change(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    query: Any,
    conflict_error: Union[
        Type[errors.ConflictError],
        Type[errors.NoSuchEntityError],
        Type[errors.InternalServerError]
    ] = errors.ConflictError,
    failure_details: Optional[FailureDetailsType] = None
) -> None:
    """
    Helper for handling :py:func:`safe_db_change` in the same manner. Performs the query and tests the result:

    * raise ``500 Internal Server Error`` if the change failed,
    * raise ``conflict_error`` if the query didn't fail but changed no records,
    * do nothing and return when the query didn't fail and changed expected number of records.
    """

    r_change = artemis_db.safe_db_change(logger, session, query)

    if r_change.is_error:
        raise errors.InternalServerError(
            logger=logger,
            caused_by=r_change.unwrap_error(),
            failure_details=failure_details
        )

    if not r_change.unwrap():
        raise conflict_error(logger=logger, failure_details=failure_details)


class GuestShelfManager:
    @staticmethod
    def entry_get_shelves(
        manager: 'GuestShelfManager',
        auth: AuthContext,
        logger: gluetool.log.ContextAdapter
    ) -> List[GuestShelfResponse]:
        # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
        # and we got so far means user must be authenticated.
        if auth.is_authentication_enabled and auth.is_authenticated:
            assert auth.username

            ownername = auth.username

        else:
            ownername = global_env.DEFAULT_GUEST_REQUEST_OWNER

        return manager.get_shelves(ownername)

    @staticmethod
    def entry_get_shelf(
        manager: 'GuestShelfManager',
        shelfname: str,
        logger: gluetool.log.ContextAdapter
    ) -> Optional[GuestShelfResponse]:
        return manager.get_shelf(shelfname)

    @staticmethod
    def entry_create_shelf(
        manager: 'GuestShelfManager',
        shelfname: str,
        auth: AuthContext,
        logger: gluetool.log.ContextAdapter
    ) -> GuestShelfResponse:
        # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
        # and we got so far means user must be authenticated.
        if auth.is_authentication_enabled and auth.is_authenticated:
            assert auth.username

            ownername = auth.username

        else:
            ownername = global_env.DEFAULT_GUEST_REQUEST_OWNER

        return manager.create_shelf(shelfname, ownername, logger)

    @staticmethod
    def entry_delete_shelf(
        manager: 'GuestShelfManager',
        shelfname: str,
        request: Request,
        auth: AuthContext,
        logger: gluetool.log.ContextAdapter
    ) -> None:
        if not manager.get_shelf(shelfname):
            raise errors.NoSuchEntityError(request=request)

        manager.delete_by_shelfname(shelfname, logger)

        return None

    @staticmethod
    def entry_delete_shelved_guest(
        manager: GuestRequestManager,
        guestname: str,
        request: Request,
        auth: AuthContext,
        logger: gluetool.log.ContextAdapter
    ) -> None:
        guest = manager.get_by_guestname(guestname)

        if not guest:
            raise errors.NoSuchEntityError(request=request)

        manager.delete_by_guestname(guestname, logger, state=GuestState.SHELVED)

        metrics.ShelfMetrics.inc_forced_removals(guest.shelf)
        metrics.ShelfMetrics.inc_removals(guest.shelf)

        return None

    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    def get_shelves(self, ownername: str) -> List[GuestShelfResponse]:
        with self.db.get_session() as session:
            r_shelves = artemis_db.SafeQuery \
                .from_session(session, artemis_db.GuestShelf) \
                .filter(artemis_db.GuestShelf.ownername == ownername) \
                .all()

            if r_shelves.is_error:
                raise errors.InternalServerError(caused_by=r_shelves.unwrap_error())

            return [
                GuestShelfResponse.from_db(shelf)
                for shelf in r_shelves.unwrap()
            ]

    def get_shelf(self, shelfname: str) -> Optional[GuestShelfResponse]:
        with self.db.get_session() as session:
            r_shelf = artemis_db.SafeQuery \
                .from_session(session, artemis_db.GuestShelf) \
                .filter(artemis_db.GuestShelf.shelfname == shelfname) \
                .one_or_none()

            if r_shelf.is_error:
                raise errors.InternalServerError(caused_by=r_shelf.unwrap_error())

            shelf = r_shelf.unwrap()

            if shelf is None:
                return None

            return GuestShelfResponse.from_db(shelf)

    def create_shelf(
        self,
        shelfname: str,
        ownername: str,
        logger: gluetool.log.ContextAdapter
    ) -> GuestShelfResponse:
        failure_details = {
            'shelfname': shelfname
        }

        with self.db.get_session() as session:
            perform_safe_db_change(
                logger,
                session,
                artemis_db.GuestShelf.create_query(shelfname, ownername),
                conflict_error=errors.InternalServerError,
                failure_details=failure_details
            )

        shelf = self.get_shelf(shelfname)

        if shelf is None:
            raise errors.InternalServerError(
                logger=logger,
                failure_details=failure_details
            )

        return shelf

    def delete_by_shelfname(self, shelfname: str, logger: gluetool.log.ContextAdapter) -> None:
        from ...tasks.remove_shelf import remove_shelf

        failure_details = {
            'shelfname': shelfname
        }

        with self.db.get_session() as session:
            r_shelf = artemis_db.SafeQuery \
                .from_session(session, artemis_db.GuestShelf) \
                .filter(artemis_db.GuestShelf.shelfname == shelfname) \
                .one_or_none()

            if r_shelf.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_shelf.unwrap_error(),
                    failure_details=failure_details
                )

            shelf = r_shelf.unwrap()

            if shelf is None:
                raise errors.NoSuchEntityError(
                    logger=logger,
                    failure_details=failure_details
                )

            query = sqlalchemy.update(artemis_db.GuestShelf.__table__) \
                .where(artemis_db.GuestShelf.shelfname == shelfname) \
                .values(state=GuestState.CONDEMNED)

            r_state = artemis_db.execute_db_statement(logger, session, query)

            if r_state.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_state.unwrap_error(),
                    failure_details=failure_details
                )

            logger.info('condemned')

            r_task = artemis_db.TaskRequest.create(logger, session, remove_shelf, shelfname)

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            log_dict_yaml(
                logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(remove_shelf, shelfname, task_request_id=task_request_id).serialize()
            )

    def preprovision(
        self,
        shelfname: str,
        preprovisioning_request: PreprovisioningRequest,
        ownername: str,
        logger: gluetool.log.ContextAdapter,
        environment_schema: JSONSchemaType
    ) -> None:
        from ...tasks.preprovision import preprovision

        failure_details = {
            'shelfname': shelfname,
            'raw_keyname': preprovisioning_request.guest.keyname,
            'raw_environment': preprovisioning_request.guest.environment,
            'raw_shelfname': preprovisioning_request.guest.shelfname,
            'raw_user_data': preprovisioning_request.guest.user_data,
            'raw_post_install_script': preprovisioning_request.guest.post_install_script,
            'raw_log_types': preprovisioning_request.guest.log_types
        }

        with self.db.get_session() as session:
            preprovisioning_request.guest = _validate_guest_request(
                logger,
                session,
                preprovisioning_request.guest,
                ownername,
                environment_schema,
                failure_details
            )

            guest_template = json.dumps(dataclasses.asdict(preprovisioning_request.guest))

            r_task = artemis_db.TaskRequest.create(
                logger,
                session,
                preprovision,
                shelfname,
                guest_template,
                str(preprovisioning_request.count)
            )

            if r_task.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_task.unwrap_error(),
                    failure_details=failure_details
                )

            task_request_id = r_task.unwrap()

            log_dict_yaml(
                logger.info,
                f'requested task #{task_request_id}',
                TaskCall.from_call(
                    preprovision,
                    shelfname,
                    guest_template,
                    str(preprovisioning_request.count),
                    task_request_id=task_request_id
                ).serialize()
            )


class SnapshotRequestManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    def get_snapshot(self, guestname: str, snapshotname: str) -> Optional[SnapshotResponse]:
        with self.db.get_session() as session:
            r_snapshot_request_record = artemis_db.SafeQuery.from_session(session, artemis_db.SnapshotRequest) \
                .filter(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .filter(artemis_db.SnapshotRequest.guestname == guestname) \
                .one_or_none()

            if r_snapshot_request_record.is_error:
                raise errors.InternalServerError(caused_by=r_snapshot_request_record.unwrap_error())

            snapshot_request_record = r_snapshot_request_record.unwrap()

            if snapshot_request_record is None:
                return None

            return SnapshotResponse.from_db(snapshot_request_record)

    def create_snapshot(
        self,
        guestname: str,
        snapshot_request: SnapshotRequest,
        logger: gluetool.log.ContextAdapter
    ) -> SnapshotResponse:
        snapshotname = str(uuid.uuid4())

        failure_details = {
            'guestname': guestname,
            'snapshotname': snapshotname
        }

        snapshot_logger = get_snapshot_logger('create-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            perform_safe_db_change(
                snapshot_logger,
                session,
                sqlalchemy.insert(artemis_db.SnapshotRequest.__table__).values(
                    snapshotname=snapshotname,
                    guestname=guestname,
                    poolname=None,
                    state=GuestState.PENDING,
                    start_again=snapshot_request.start_again
                ),
                conflict_error=errors.InternalServerError,
                failure_details=failure_details
            )

            artemis_db.GuestRequest.log_event_by_guestname(
                snapshot_logger,
                session,
                guestname,
                'created',
                snapshotname=snapshotname
            )

        sr = self.get_snapshot(guestname, snapshotname)

        if sr is None:
            # Now isn't this just funny... We just created the record, how could it be missing? There's probably
            # no point in trying to clean up what we started - if the guest is missing, right after we created it,
            # then things went south. At least it would get logged.
            raise errors.InternalServerError(
                logger=snapshot_logger,
                failure_details=failure_details
            )

        return sr

    def delete_snapshot(self, guestname: str, snapshotname: str, logger: gluetool.log.ContextAdapter) -> None:
        from ...tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            query = sqlalchemy \
                .update(artemis_db.SnapshotRequest.__table__) \
                .where(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .where(artemis_db.SnapshotRequest.guestname == guestname) \
                .values(state=GuestState.CONDEMNED)

            # Unline guest requests, here seem to be no possibility of conflict or relationships we must
            # preserve. Given the query, snapshot request already being removed seems to be the only option
            # here - what else could cause the query *not* marking the record as condemned?
            perform_safe_db_change(snapshot_logger, session, query, conflict_error=errors.NoSuchEntityError)

            artemis_db.GuestRequest.log_event_by_guestname(
                snapshot_logger,
                session,
                guestname,
                'snapshot-condemned'
            )

    def restore_snapshot(
        self,
        guestname: str,
        snapshotname: str,
        logger: gluetool.log.ContextAdapter
    ) -> SnapshotResponse:
        from ...tasks import get_snapshot_logger

        snapshot_logger = get_snapshot_logger('delete-snapshot-request', logger, guestname, snapshotname)

        with self.db.get_session() as session:
            query = sqlalchemy \
                .update(artemis_db.SnapshotRequest.__table__) \
                .where(artemis_db.SnapshotRequest.snapshotname == snapshotname) \
                .where(artemis_db.SnapshotRequest.guestname == guestname) \
                .where(artemis_db.SnapshotRequest.state != GuestState.CONDEMNED) \
                .values(state=GuestState.RESTORING)

            # Similarly to guest request removal, two options exist: either the snapshot is already gone,
            # or it's marked as condemned. Again, we cannot tell which of these happened. "404 Not Found"
            # would better express the former, but sticking with "409 Conflict" to signal user there's a
            # conflict of some kind, and after resolving it - e.g. by inspecting the snapshot request - user
            # should decide how to proceed.
            perform_safe_db_change(snapshot_logger, session, query)

            snapshot_response = self.get_snapshot(guestname, snapshotname)

            assert snapshot_response is not None

            return snapshot_response


class KnobManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_get_knobs(
        manager: 'KnobManager',
        logger: gluetool.log.ContextAdapter
    ) -> List[KnobResponse]:
        return manager.get_knobs(logger)

    @staticmethod
    def entry_get_knob(
        manager: 'KnobManager',
        knobname: str,
        logger: gluetool.log.ContextAdapter
    ) -> KnobResponse:
        response = manager.get_knob(logger, knobname)

        if response is None:
            raise errors.NoSuchEntityError()

        return response

    @staticmethod
    def entry_set_knob(
        manager: 'KnobManager',
        knobname: str,
        payload: KnobUpdateRequest,
        logger: gluetool.log.ContextAdapter
    ) -> KnobResponse:
        manager.set_knob(knobname, payload.value, logger)

        response = manager.get_knob(logger, knobname)

        if response is None:
            raise errors.NoSuchEntityError()

        return response

    @staticmethod
    def entry_delete_knob(
        manager: 'KnobManager',
        logger: gluetool.log.ContextAdapter,
        knobname: str
    ) -> None:
        manager.delete_knob(logger, knobname)

        return None

    def get_knobs(self, logger: gluetool.log.ContextAdapter) -> List[KnobResponse]:
        knobs: Dict[str, KnobResponse] = {}

        # First, collect all known knobs.
        for knobname, knob in Knob.ALL_KNOBS.items():
            knobs[knobname] = KnobResponse(
                name=knobname,
                value=knob.static_value,
                cast=knob.cast_name,
                help=knob.help,
                editable=False
            )

        # Second, update editable knobs.
        for knobname, knob in Knob.DB_BACKED_KNOBS.items():
            assert knobname in knobs

            knobs[knobname].editable = True

        # Then, get the actual DB records, and update what we collected in the previous step:
        #
        # * knobs we already saw may need a value update since the DB record is the source with higher priority;
        # * knobs we haven't seen yet shall be added to the list. These are the per-pool knobs - each per-pool DB
        #   record does not have its own knob variable - the knob name in the record does not match any existing
        #   static knob, since `$poolname` placeholder in the name is replaced with the actual pool name. For these
        #   records, we must find their "parent" knob, because we need to know its casting function (which applies
        #   to all "child" records of the given per-pool-capable knob).
        with self.db.get_session() as session:
            r_knobs = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .all()

            if r_knobs.is_error:
                raise errors.InternalServerError(caused_by=r_knobs.unwrap_error())

            for record in r_knobs.unwrap():
                if record.knobname not in knobs:
                    parent_knob = Knob.get_per_entity_parent(logger, record.knobname)

                    if parent_knob is None:
                        raise errors.InternalServerError(
                            message='cannot find parent knob',
                            failure_details={
                                'knobname': record.knobname
                            }
                        )

                    knobs[record.knobname] = KnobResponse(
                        name=record.knobname,
                        value=record.value,
                        cast=parent_knob.cast_name,
                        help=knob.help,
                        editable=True
                    )

                else:
                    knobs[record.knobname].value = record.value

        return list(knobs.values())

    def get_knob(self, logger: gluetool.log.ContextAdapter, knobname: str) -> Optional[KnobResponse]:
        with self.db.get_session() as session:
            r_knob = artemis_db.SafeQuery.from_session(session, artemis_db.Knob) \
                .filter(artemis_db.Knob.knobname == knobname) \
                .one_or_none()

            if r_knob.is_error:
                raise errors.InternalServerError(caused_by=r_knob.unwrap_error())

            knob_record = r_knob.unwrap()

            if knob_record is None:
                value = None

            else:
                value = knob_record.value

            if knobname in Knob.DB_BACKED_KNOBS:
                knob = Knob.DB_BACKED_KNOBS[knobname]

                return KnobResponse(
                    name=knobname,
                    value=value,
                    help=knob.help,
                    editable=True,
                    cast=knob.cast_name
                )

            if knobname in Knob.ALL_KNOBS:
                knob = Knob.ALL_KNOBS[knobname]

                return KnobResponse(
                    name=knobname,
                    value=value,
                    help=knob.help,
                    editable=False,
                    cast=knob.cast_name
                )

            parent_knob = Knob.get_per_entity_parent(logger, knobname)

            if parent_knob is None:
                raise errors.InternalServerError(
                    message='cannot find parent knob',
                    failure_details={
                        'knobname': knobname
                    }
                )

            return KnobResponse(
                name=knobname,
                value=value,
                cast=parent_knob.cast_name,
                help=parent_knob.help,
                editable=True
            )

    def set_knob(self, knobname: str, value: str, logger: gluetool.log.ContextAdapter) -> None:
        failure_details = {
            'knobname': knobname
        }

        with self.db.get_session() as session:
            knob = Knob.DB_BACKED_KNOBS.get(knobname)

            if knob is None:
                # If the knob is not backed by DB but it's in the list of all knobs, then it must be a knob
                # that's not editable.
                if knobname in Knob.ALL_KNOBS:
                    raise errors.MethodNotAllowedError(
                        message='Cannot modify non-editable knob',
                        failure_details=failure_details
                    )

                # Try to find the parent knob for this one which is apparently a per-pool knob.
                knob = Knob.get_per_entity_parent(logger, knobname)

            if knob is None:
                raise errors.NoSuchEntityError(logger=logger)

            assert knob is not None
            assert knob.cast_from_str is not None

            try:
                casted_value = knob.cast_from_str(value)

            except Exception as exc:
                raise errors.BadRequestError(
                    message='Cannot convert value to type expected by the knob',
                    logger=logger,
                    caused_by=Failure.from_exc('cannot cast knob value', exc),
                    failure_details=failure_details
                )

            artemis_db.upsert(
                logger,
                session,
                artemis_db.Knob,
                {
                    # using `knobname`, i.e. changing the original knob, not the parent
                    artemis_db.Knob.knobname: knobname
                },
                insert_data={
                    artemis_db.Knob.value: casted_value
                },
                update_data={
                    'value': casted_value
                }
            )

        logger.info(f'knob changed: {knobname} = {casted_value}')

    def delete_knob(self, logger: gluetool.log.ContextAdapter, knobname: str) -> None:
        with self.db.get_session() as session:
            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.delete(artemis_db.Knob.__table__).where(artemis_db.Knob.knobname == knobname)
            )


class URLLogger(gluetool.log.ContextAdapter):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        url: str
    ) -> None:
        super().__init__(logger, {
            'ctx_url': (10, url)
        })

    @property
    def url(self) -> str:
        return cast(str, self._contexts['url'][1])


class CacheManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    def refresh_pool_object_infos(
        self,
        logger: gluetool.log.ContextAdapter,
        request: Request,
        poolname: str,
        actor: Actor
    ) -> None:
        # request.url is of starlette.datastructures.URL type
        logger = URLLogger(logger, request.url.path)

        # We don't really need the pool object, but we'd like to avoid triggering tasks for pools that don't exist.
        # The race condition still exists though, because we don't try too hard :) The pool may be gone after our
        # check and before the dispatch, but we don't aim for consistency here, rather the user experience. The task
        # is safe: if the pool is gone in that sensitive period of time, task will report an error and won't ask for
        # reschedule. If we can avoid some of the errors with a trivial DB query, let's do so.
        with self.db.get_session() as session:
            _ = self._get_pool(logger, session, poolname)

        from ...tasks import dispatch_task

        r_dispatch = dispatch_task(logger, actor, poolname)

        if r_dispatch.is_error:
            raise errors.InternalServerError(caused_by=r_dispatch.unwrap_error(), logger=logger)

        return None

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_pool_image_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Response:
        return manager.get_pool_image_info(logger, poolname)

    @staticmethod
    def entry_pool_flavor_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        poolname: str
    ) -> Response:
        return manager.get_pool_flavor_info(logger, poolname)

    @staticmethod
    def entry_refresh_pool_image_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        request: Request,
        poolname: str
    ) -> None:
        from ...tasks import refresh_pool_image_info

        return manager.refresh_pool_object_infos(logger, request, poolname, refresh_pool_image_info)

    @staticmethod
    def entry_refresh_pool_flavor_info(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        request: Request,
        poolname: str
    ) -> None:
        from ...tasks import refresh_pool_flavor_info

        return manager.refresh_pool_object_infos(logger, request, poolname, refresh_pool_flavor_info)

    def _get_pool(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        poolname: str
    ) -> PoolDriver:
        r_pool = PoolDriver.load_or_none(logger, session, poolname)

        if r_pool.is_error:
            raise errors.InternalServerError(
                logger=logger,
                caused_by=r_pool.unwrap_error(),
                failure_details={
                    'poolname': poolname
                }
            )

        pool = r_pool.unwrap()

        if pool is None:
            raise errors.NoSuchEntityError(
                logger=logger,
                failure_details={
                    'poolname': poolname
                }
            )

        return pool

    def _get_pool_object_infos(self, logger: gluetool.log.ContextAdapter, poolname: str, method_name: str) -> Response:
        with self.db.get_session() as session:
            pool = self._get_pool(logger, session, poolname)

            method = getattr(pool, method_name, None)

            if method is None:
                raise errors.NoSuchEntityError(message='Pool does not support this type of information')

            r_infos = method()

            if r_infos.is_error:
                raise errors.InternalServerError(
                    logger=logger,
                    caused_by=r_infos.unwrap_error(),
                    failure_details={
                        'poolname': poolname
                    }
                )

            return Response(
                status_code=status.HTTP_200_OK,
                content=gluetool.log.format_dict({
                    info.name: info.serialize()
                    for info in r_infos.unwrap()
                }),
                headers={'Content-Type': 'application/json'}
            )

    def get_pool_image_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_image_infos')

    def get_pool_flavor_info(self, logger: gluetool.log.ContextAdapter, poolname: str) -> Response:
        return self._get_pool_object_infos(logger, poolname, 'get_cached_pool_flavor_infos')


class UserManager:
    """
    Manager class for operations involving management of user accounts.
    """

    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    @staticmethod
    def entry_get_users(manager: 'UserManager') -> List[UserResponse]:
        with manager.db.get_session() as session:
            return [
                UserResponse.from_db(user)
                for user in manager.get_users(session)
            ]

    @staticmethod
    def entry_get_user(manager: 'UserManager', username: str) -> UserResponse:
        with manager.db.get_session() as session:
            return UserResponse.from_db(manager.get_user(session, username))

    @staticmethod
    def entry_create_user(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str,
        user_request: CreateUserRequest
    ) -> UserResponse:
        try:
            actual_role = artemis_db.UserRoles(user_request.role)

        except ValueError:
            raise errors.BadRequestError(
                failure_details={
                    'username': username,
                    'role': user_request.role
                }
            )

        manager.create_user(logger, username, actual_role)

        with manager.db.get_session() as session:
            return UserResponse.from_db(manager.get_user(session, username))

    @staticmethod
    def entry_delete_user(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str
    ) -> None:
        manager.delete_user(logger, username)

        return None

    @staticmethod
    def entry_reset_token(
        manager: 'UserManager',
        logger: gluetool.log.ContextAdapter,
        username: str,
        tokentype: str
    ) -> TokenResetResponse:
        try:
            actual_tokentype = TokenTypes(tokentype)

        except ValueError:
            raise errors.BadRequestError(
                failure_details={
                    'username': username,
                    'tokentype': tokentype
                }
            )

        return manager.reset_token(logger, username, actual_tokentype)

    #
    # Actual API workers
    #
    def get_users(self, session: sqlalchemy.orm.session.Session) -> List[artemis_db.User]:
        r_users = artemis_db.SafeQuery.from_session(session, artemis_db.User).all()

        if r_users.is_error:
            raise errors.InternalServerError(caused_by=r_users.unwrap_error())

        return r_users.unwrap()

    def get_user(
        self,
        session: sqlalchemy.orm.session.Session,
        username: str,
    ) -> artemis_db.User:
        r_user = artemis_db.SafeQuery.from_session(session, artemis_db.User) \
            .filter(artemis_db.User.username == username) \
            .one_or_none()

        if r_user.is_error:
            raise errors.InternalServerError(caused_by=r_user.unwrap_error())

        user = r_user.unwrap()

        if not user:
            raise errors.NoSuchEntityError()

        return user

    def create_user(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str,
        role: artemis_db.UserRoles
    ) -> None:
        with self.db.get_session() as session:
            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.insert(artemis_db.User.__table__).values(
                    username=username,
                    role=role.value
                )
            )

    def delete_user(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str
    ) -> None:
        with self.db.get_session() as session:
            # Provides nicer error when the user does not exist
            _ = self.get_user(session, username)

            perform_safe_db_change(
                logger,
                session,
                sqlalchemy.delete(artemis_db.User.__table__).where(
                    artemis_db.User.username == username
                ),
                failure_details={
                    'username': username
                }
            )

    def reset_token(
        self,
        logger: gluetool.log.ContextAdapter,
        username: str,
        tokentype: TokenTypes
    ) -> TokenResetResponse:
        with self.db.get_session() as session:
            # Provides nicer error when the user does not exist
            user = self.get_user(session, username)

            token, token_hash = artemis_db.User.generate_token()

            query = sqlalchemy.update(artemis_db.User.__table__) \
                .where(artemis_db.User.username == username)

            if tokentype == TokenTypes.ADMIN:
                query = query \
                    .where(artemis_db.User.admin_token == user.admin_token) \
                    .values(admin_token=token_hash)

            elif tokentype == TokenTypes.PROVISIONING:
                query = query \
                    .where(artemis_db.User.provisioning_token == user.provisioning_token) \
                    .values(provisioning_token=token_hash)

            else:
                assert False, 'Unreachable'

            perform_safe_db_change(
                logger,
                session,
                query,
                failure_details={
                    'username': username,
                    'tokentype': tokentype.value
                }
            )

        return TokenResetResponse(
            tokentype=tokentype,
            token=token
        )


class StatusManager:
    def __init__(self, db: Annotated[artemis_db.DB, Depends(get_db)]) -> None:
        self.db = db

    #
    # Entry points hooked to routes
    #
    @staticmethod
    def entry_workers_traffic(
        manager: 'CacheManager',
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Response:
        from ...middleware import WorkerTraffic

        tasks: List[Dict[str, Any]] = []

        for task_key in iter_cache_keys(logger, cache, WorkerTraffic.KEY_WORKER_TASK_PATTERN):
            value = get_cache_value(logger, cache, task_key.decode())

            if not value:
                continue

            tasks.append(json.loads(value.decode()))

        return Response(
            status_code=status.HTTP_200_OK,
            content=gluetool.log.format_dict(tasks),
            headers={'Content-Type': 'application/json'}
        )


# NOTE(ivasilev) No idea why how to make mypy happy, muting for now
def get_guest_request_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: GuestRequestManager,
    logger: gluetool.log.ContextAdapter,
    guest_log_response_model: Type[GuestLogResponseType] = GuestLogResponse  # type: ignore[assignment]
) -> GuestLogResponseType:
    from ...tasks import get_guest_logger

    failure_details = {
        'guestname': guestname
    }

    guest_logger = get_guest_logger('create-guest-request-log', logger, guestname)

    with manager.db.get_session() as session:
        r_log = artemis_db.SafeQuery.from_session(session, artemis_db.GuestLog) \
            .filter(artemis_db.GuestLog.guestname == guestname) \
            .filter(artemis_db.GuestLog.logname == logname) \
            .filter(artemis_db.GuestLog.contenttype == artemis_db.GuestLogContentType(contenttype)) \
            .one_or_none()

        if r_log.is_error:
            raise errors.InternalServerError(
                logger=guest_logger,
                caused_by=r_log.unwrap_error(),
                failure_details=failure_details
            )

        log = r_log.unwrap()

        if log is None:
            raise errors.NoSuchEntityError(logger=guest_logger)

        if log.is_expired:
            raise errors.ConflictError(
                message='guest log has expired',
                logger=guest_logger
            )

        return guest_log_response_model.from_db(log)


def create_guest_request_log(
    guestname: str,
    logname: str,
    contenttype: str,
    manager: GuestRequestManager,
    logger: gluetool.log.ContextAdapter
) -> None:
    from ...tasks import get_guest_logger, update_guest_log

    failure_details = {
        'guestname': guestname
    }

    guest_logger = get_guest_logger('create-guest-request-log', logger, guestname)

    with manager.db.get_session() as session:
        r_upsert = artemis_db.upsert(
            guest_logger,
            session,
            artemis_db.GuestLog,
            primary_keys={
                artemis_db.GuestLog.guestname: guestname,
                artemis_db.GuestLog.logname: logname,
                artemis_db.GuestLog.contenttype: artemis_db.GuestLogContentType(contenttype)
            },
            insert_data={
                artemis_db.GuestLog.state: artemis_db.GuestLogState.PENDING
            }
        )

        if r_upsert.is_error:
            raise errors.InternalServerError(
                logger=guest_logger,
                caused_by=r_upsert.unwrap_error(),
                failure_details=failure_details
            )

        if r_upsert.unwrap() is not True:
            raise errors.ConflictError(
                message='guest log already exists',
                logger=guest_logger
            )

        r_task = artemis_db.TaskRequest.create(
            guest_logger,
            session,
            update_guest_log,
            guestname,
            logname,
            contenttype
        )

        if r_task.is_error:
            raise errors.InternalServerError(
                logger=guest_logger,
                caused_by=r_task.unwrap_error(),
                failure_details=failure_details
            )

        task_request_id = r_task.unwrap()

        log_dict_yaml(
            guest_logger.info,
            f'requested task #{task_request_id}',
            TaskCall.from_call(
                update_guest_log,
                guestname,
                logname,
                contenttype,
                task_request_id=task_request_id
            ).serialize()
        )

        artemis_db.GuestRequest.log_event_by_guestname(
            guest_logger,
            session,
            guestname,
            'guest-log-requested',
            **{
                'logname': logname,
                'contenttype': contenttype
            }
        )

    return None


def get_metrics(
    request: Request,
    db: artemis_db.DB,
    metrics_tree: 'metrics.Metrics',
    logger: gluetool.log.ContextAdapter
) -> Response:
    LOGGER.set(logger)
    DATABASE.set(db)

    r_metrics = metrics_tree.render_prometheus_metrics()

    if r_metrics.is_error:
        raise errors.InternalServerError(caused_by=r_metrics.unwrap_error())

    with global_env.METRICS_LOCK:
        return Response(
            status_code=status.HTTP_200_OK,
            content=r_metrics.unwrap().decode('utf-8'),
            headers={
                "content-type": "text/plain; charset=utf-8"
            }
        )


def get_about(request: Request) -> AboutResponse:
    """
    Some docs.
    """

    return AboutResponse(
        package_version=__VERSION__,
        image_digest=os.getenv('ARTEMIS_IMAGE_DIGEST'),
        image_url=os.getenv('ARTEMIS_IMAGE_URL'),
        artemis_deployment=KNOB_DEPLOYMENT.value,
        artemis_deployment_environment=KNOB_DEPLOYMENT_ENVIRONMENT.value,
        api_versions=[
            version
            for version, _ in global_env.API_MILESTONES
        ]
    )


def define_openapi_schema(app: fastapi.FastAPI) -> Dict[str, str]:
    openapi_schema = fastapi.openapi.utils.get_openapi(
        title=global_env.OPENAPI_METADATA['title'],
        version=global_env.OPENAPI_METADATA['version'],
        summary=global_env.OPENAPI_METADATA.get('summary'),
        description=global_env.OPENAPI_METADATA.get('description'),
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


def create_guest_request(
    api_version: str,
    guest_request: GuestRequestType,
    manager: GuestRequestManager,
    request: Request,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter,
    response_model: Type[GuestResponseType] = GuestResponse  # type: ignore[assignment]
) -> GuestResponseType:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = global_env.DEFAULT_GUEST_REQUEST_OWNER

    r_schemas = global_env.get_environment_schemas()
    if r_schemas.is_error:
        raise errors.InternalServerError(caused_by=r_schemas.unwrap_error())
    schemas = r_schemas.unwrap()

    return manager.create(guest_request, ownername, logger, schemas[api_version], response_model=response_model)


# XXX FIXME NOTE(ivasilev) Not yet tested, can't figure out how to do that with artemis-cli
def preprovision_guest(
    api_version: str,
    shelfname: str,
    preprovisioning_request: PreprovisioningRequest,
    manager: GuestShelfManager,
    auth: AuthContext,
    logger: gluetool.log.ContextAdapter,
) -> None:
    # TODO: drop is_authenticated when things become mandatory: bare fact the authentication is enabled
    # and we got so far means user must be authenticated.
    if auth.is_authentication_enabled and auth.is_authenticated:
        assert auth.username

        ownername = auth.username

    else:
        ownername = global_env.DEFAULT_GUEST_REQUEST_OWNER

    r_schemas = global_env.get_environment_schemas()
    if r_schemas.is_error:
        raise errors.InternalServerError(caused_by=r_schemas.unwrap_error())
    schemas = r_schemas.unwrap()

    manager.preprovision(
        shelfname,
        preprovisioning_request,
        ownername,
        logger,
        schemas[api_version]
    )

    return None
