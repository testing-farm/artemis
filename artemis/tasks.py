import asyncio
import json
import sys
import threading

import dramatiq
import gluetool.log
import sqlalchemy
import sqlalchemy.orm.exc
import sqlalchemy.orm.session
from gluetool.result import Result, Ok, Error

import artemis
import artemis.db
import artemis.guest
import artemis.drivers.openstack

from artemis import Failure, safe_call
from artemis.db import Guest

from typing import cast, Any, Callable, Dict, Optional


# There is a very basic thing we must be aware of: a task - the Python function below - can run multiple times,
# sequentialy or in parallel. It's like multithreading application above a database, without any locks available.
# Tasks must be aware of this and carefully plan their workflow, to employ database queries to help with the
# synchronization, and tasks must be always ready to rollback their changes as much as possible.
#
#   "Ask for forgiveness, not for permission."
#
# Stick to the basic principles:
#
# * a task *must be* idenpotent.
# * a task *must be* atomic.
# * a task must not wait for other tasks to complete.
# * a task should not return any result - we're using database to store the state.
# * no complex object as task parameters, always use primitive data types.
#
# In the case of doubts, let's examine the checklist and discuss: https://devchecklists.com/celery-tasks-checklist/
#

#
# How we're running our tasks
#
# dramatiq will start a task by executing its corresponding function in the context of a thread within a worker
# process - let's call it thread A. This thread runs the task's function, and it will be send asynchronous exceptions
# such as TimeLimitExceeded or Shutdown. Given that our tasks must be able to rollback any changes they perform in the
# case of an error, they have to somehow keep their progress inernally, and mark down actions they need to unroll when
# the time comes. However, in the environment where the task can be interrupted by an *asynchronous* exception, it is
# not possible to implement this rollback consistently *in a readable fashion*. The opportunity for a race condition
# between the action and unroll note could be solved by wrapping each action with try-catch, catching these
# asynchronous exceptions, taking necessary steps in except/finally branches. This would of course make the code
# hard to read, with all that exception handling, leaving us with spagetti code everywhere.
#
# So, asyncio to the rescue! Let's cheat a bit. Thread A will spawn - with the help of asyncio, futures and event
# loop - new thread, B, which will run the actual code of the task. In thread A we'll have the event loop code, which,
# when receiving the asynchronous exceptions, would set "cancel?" event which was passed to the task in thread B.
# After that, thread A would continue running the event loop, waiting for thread B to finish.
#
# Thread B started running the task, and will check "canceled?" event from time to time. Should the event become set,
# it can safely unroll & quit. Asynchronous exceptions are delivered to the thread A, no need to fear them in thread B.
# We don't need to *kill* thread B when asynchronous exception arrived to thread A, we just need to tell it to quit
# as soon as possible.
#
# When thread B finishes, successfully or by raising an exception, its "return value" is "picked up" by thread A,
# possibly raising the original exception raised in thread B, giving thread A a chance to react to them even more.

#
# TODO:
# - support queue name when sending messages - we want our tasks to use different queues.
# - allow retries modification and tweaking
# - "lazy actor" wrapper to avoid the necessity of initializing dramatiq at the import time

_ = artemis.get_broker()


POOL_DRIVERS = {
    'openstack': artemis.drivers.openstack.OpenStackDriver
}


def run_doer(
    logger: gluetool.log.ContextAdapter,
    fn: Callable[..., None],
    *args: Any,
    **kwargs: Any
) -> None:
    try:
        cancel = threading.Event()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        doer_task: asyncio.Task = loop.create_task(fn(*args, **kwargs))

        loop.run_until_complete(doer_task)

    except dramatiq.middleware.Interrupt as exc:
        if isinstance(exc, dramatiq.middleware.TimeLimitExceeded):
            logger.error('time depleted')

        elif isinstance(exc, dramatiq.middleware.Shutdown):
            logger.error('killed')

        else:
            assert False, 'Unhandled interrupt exception'

        cancel.set()

        pending = asyncio.Task.all_tasks(loop)

        if not pending:
            return

        finish_future = asyncio.gather(*pending)

        loop.run_until_complete(finish_future)

        assert doer_task.done()

    return doer_task.result()


def _dispatch_task(
    logger: gluetool.log.ContextAdapter,
    task: Callable[..., None],
    *args: Any,
    **kwargs: Any
) -> Result[None, Exception]:
    r = safe_call(task.send, *args, **kwargs)

    if r.is_ok:
        return Ok(None)

    logger.error('failed to submit task "{}"'.format(task), exc_info=r.error)

    return Error(r.error)


def _get_guest_by_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    state: artemis.guest.GuestState
) -> Optional[artemis.db.Guest]:
    query = session \
            .query(Guest) \
            .filter(Guest.guestname == guestname) \
            .filter(Guest.state == state.value)

    r_query = safe_call(query.one)

    if r_query.is_ok:
        return r_query.unwrap()

    failure = cast(Failure, r_query.value)

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(state.value))
        return None

    raise failure.exception


def _update_guest_state(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    guestname: str,
    current: artemis.guest.GuestState,
    new: artemis.guest.GuestState,
    set_values: Optional[Dict[str, Any]] = None
) -> bool:
    if set_values:
        values = set_values
        values.update({
            'state': new.value
        })

    else:
        values = {
            'state': new.value
        }

    query = sqlalchemy \
        .update(Guest) \
        .where(Guest.guestname == guestname) \
        .where(Guest.state == current.value) \
        .values(**values)

    logger.warning('query: {}'.format(str(query)))

    r = safe_call(session.execute, query)

    if r.is_ok:
        return True

    failure = cast(Failure, r.value)

    if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
        logger.warning('not in {} state anymore'.format(current.value))
        return False

    raise failure.exception


def _get_pool(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    poolname: str
) -> artemis.drivers.PoolDriver:
    try:
        pool_record = session \
                    .query(artemis.db.Pool) \
                    .filter(artemis.db.Pool.poolname == poolname) \
                    .one()

    except sqlalchemy.orm.exc.NoResultFound:
        raise Exception('no such pool "{}"'.format(poolname))

    pool_driver_class = POOL_DRIVERS[pool_record.driver]

    return pool_driver_class(logger, json.loads(pool_record.parameters))


def _get_master_key(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session
) -> artemis.db.SSHKey:
    try:
        return cast(
            artemis.db.SSHKey,
            session.query(artemis.db.SSHKey).filter(
                artemis.db.SSHKey.ownername == 'artemis',
                artemis.db.SSHKey.keyname == 'master-key'
            ).one()
        )

    except sqlalchemy.orm.exc.NoResultFound:
        raise Exception('no master key')


async def do_release_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str
) -> None:
    with db.get_session() as session:
        gr = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.CONDEMNED)
        if not gr:
            return

        if not gr.poolname:
            raise Exception('guest record without a pool')

        pool = _get_pool(logger, session, gr.poolname)

        if cancel.is_set():
            return

        r_guest = pool.guest_factory(gr)
        if r_guest.is_error:
            cast(Failure, r_guest.value).log(logger.error, label='failed to locate')
            return

        r_release = pool.release_guest(r_guest.unwrap())

        if r_release.is_error:
            cast(Failure, r_release.value).log(logger.error, label='failed to locate')
            return

        query = sqlalchemy \
            .delete(Guest) \
            .where(Guest.guestname == guestname) \
            .where(Guest.state == artemis.guest.GuestState.CONDEMNED.value)

        logger.warning('query: {}'.format(str(query)))

        r_condemn = safe_call(session.execute, query)

        if r_condemn.is_ok:
            return

        failure = cast(Failure, r_condemn.error)

        if isinstance(failure.exception, sqlalchemy.orm.exc.NoResultFound):
            logger.warning('not in CONDEMNED state anymore')
            return

        raise failure.exception


@dramatiq.actor(min_backoff=15, max_backoff=16)
def release_guest_request(guestname: str) -> None:
    root_logger = artemis.get_logger()
    db = artemis.get_db(root_logger)

    logger = artemis.guest.GuestLogger(root_logger, guestname)

    cancel = threading.Event()

    try:
        run_doer(logger, do_release_guest_request, logger, db, cancel, guestname)

    except sqlalchemy.exc.SQLAlchemyError as exc:
        logger.error('unhandled DB error: {}'.format(exc), exc_info=sys.exc_info())

        raise

    except Exception as exc:
        logger.error('unhandled error: {}'.format(exc), exc_info=sys.exc_info())

        raise


async def do_acquire_guest(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str,
    poolname: str
) -> None:
    with db.get_session() as session:
        def _undo_guest_acquire(guest: Guest) -> None:
            r = pool.release_guest(guest)

            if r.is_ok:
                return

            raise Exception(r.error)

        gr = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.PROVISIONING)
        if not gr:
            return

        pool = _get_pool(logger, session, poolname)
        master_key = _get_master_key(logger, session)

        environment = artemis.environment.Environment.unserialize_from_json(json.loads(gr.environment))

        if cancel.is_set():
            return

        result = pool.acquire_guest(logger, environment, master_key)

        if result.is_error:
            raise Exception('failed to acquire: {}'.format(result.error))

        guest = result.unwrap()

        if cancel.is_set():
            _undo_guest_acquire(guest)
            return

        # We have a guest, we can move the guest record to the next state. We must atomicaly add guest's address
        # while making sure nobody else did it before us.
        if _update_guest_state(
            logger,
            session,
            guestname,
            artemis.guest.GuestState.PROVISIONING,
            artemis.guest.GuestState.READY,
            set_values={
                'address': guest.address,
                'poolname': poolname,
                'pool_data': guest.pool_data_to_db()
            }
        ):
            logger.info('successfully acquired')
            return

        # Failed to change the state means somebody else already did the provisioning. Or even canceled the request.
        # Again, we must undo and forget about the guest request.
        _undo_guest_acquire(guest)


@dramatiq.actor(min_backoff=15, max_backoff=16)
def acquire_guest(guestname: str, poolname: str) -> None:
    root_logger = artemis.get_logger()
    db = artemis.get_db(root_logger)

    logger = artemis.guest.GuestLogger(root_logger, guestname)

    cancel = threading.Event()

    try:
        run_doer(logger, do_acquire_guest, logger, db, cancel, guestname, poolname)

    except sqlalchemy.exc.SQLAlchemyError as exc:
        logger.error('unhandled DB error: {}'.format(exc), exc_info=sys.exc_info())

        raise

    except Exception as exc:
        logger.error('unhandled error: {}'.format(exc), exc_info=sys.exc_info())

        raise


async def do_route_guest_request(
    logger: gluetool.log.ContextAdapter,
    db: artemis.db.DB,
    cancel: threading.Event,
    guestname: str
) -> None:
    root_logger = artemis.get_logger()
    db = artemis.get_db(root_logger)

    logger = artemis.guest.GuestLogger(root_logger, guestname)

    with db.get_session() as session:
        def _undo_guest_in_provisioning() -> None:
            if _update_guest_state(
                logger,
                session,
                guestname,
                artemis.guest.GuestState.PROVISIONING,
                artemis.guest.GuestState.ROUTING
            ):
                return

            # We should never ever end up here, because:
            #
            # - undo worked => _update_guest_state returns True and we leave right above this comment
            # - undo failed because of unspecified exception -> the exception is reraised in _update_guest_state
            # - undo failed because there was no such record in db -> _update_guest_state returns False, which is not
            # possible...
            #
            # We are the only instance of this task that got this far. We were the only instance that managed to move
            # guest to PROVISIONING state, any other instance should see it alread has that state (or they fail to
            # change it), stopping their execution at that point. We should be the only instance that has anything to
            # undo.
            #
            # So, what changed the guest state if it haven't been any other instance of this task, and if we failed to
            # dispatch any provisioning task??
            assert False, 'unreachable'

        # First, pick up our assigned guest request. Make sure it hasn't been
        # processed yet.
        guest = _get_guest_by_state(logger, session, guestname, artemis.guest.GuestState.ROUTING)

        if not guest:
            return

        if cancel.is_set():
            return

        # Do stuff, examine request, pick the provisioner, and send it a message.
        #
        # Be aware that while the request was free to take, it may be being processed by multiple instances of this
        # task at once - we didn't acquire any lock! We could either introduce locking, or we can continue and make
        # sure the request didn't change when we start commiting changes. And since asking or forgiveness is simpler
        # than asking for permission, let's continue but be prepared to clean up if someone else did the work instead
        # of us.

        logger.info('finding suitable provisioner')
        # ...

        if cancel.is_set():
            return

        # Mark request as suitable for provisioning.
        if not _update_guest_state(
            logger,
            session,
            guestname,
            artemis.guest.GuestState.ROUTING,
            artemis.guest.GuestState.PROVISIONING
        ):
            # We failed to move guest to PROVISIONING state which means some other instance of this task changed
            # guest's state instead of us, which means we should throw everything away because our decisions no
            # longer matter.
            return

        if cancel.is_set():
            _undo_guest_in_provisioning()

            return

        # Fine, the query succeeded, which means we are the first instance of this task to move this far. For any other
        # instance, the state change will fail and they will bail while we move on and try to dispatch the provisioning
        # task.
        r = _dispatch_task(logger, acquire_guest, guestname, 'baseosci-openstack')

        if r.is_ok:
            return

        # We failed to dispatch the task, but we already marked the request as suitable for provisioning, which means
        # that any subsequent run of this task would not be able to evaluate it again since it's no longer in ROUTING
        # state. We should undo this change.
        #
        # On the other hand, we just cannot chain undos of undos indefinitely, so if this attempt fails, let's give up
        # and let humans solve the problems.
        _undo_guest_in_provisioning()


@dramatiq.actor
def route_guest_request(guestname: str) -> None:
    root_logger = artemis.get_logger()
    db = artemis.get_db(root_logger)

    logger = artemis.guest.GuestLogger(root_logger, guestname)

    cancel = threading.Event()

    try:
        run_doer(logger, do_route_guest_request, logger, db, cancel, guestname)

    except sqlalchemy.exc.SQLAlchemyError as exc:
        logger.error('unhandled DB error: {}'.format(exc), exc_info=sys.exc_info())

        raise

    except Exception as exc:
        logger.error('unhandled error: {}'.format(exc), exc_info=sys.exc_info())

        raise
