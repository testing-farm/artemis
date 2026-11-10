# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
import dataclasses
from typing import Any
from unittest import mock

import gluetool.log
import pytest
import sqlalchemy.orm.session
from returns.result import Result as _Result, Success as _Ok

from tft.artemis import Failure
from tft.artemis.drivers import (
    PoolDriver,
    PoolResourcesIDs,
    Resource,
    ResourceCreationOutcome,
    ResourceCreationRequest,
    ResourceManager,
)
from tft.artemis.drivers.naming import LookupMethod, NameConstraints, NamingStrategy

GUESTNAME = 'dummy-guest'


@dataclasses.dataclass
class DummyResource(Resource):
    state: str = 'ready'

    @property
    def is_pending(self) -> bool:
        return self.state == 'pending'

    @property
    def is_ready(self) -> bool:
        return self.state == 'ready'

    @property
    def is_error(self) -> bool:
        return self.state == 'error'

    def to_pool_resource_ids(self) -> PoolResourcesIDs:
        return PoolResourcesIDs()


@dataclasses.dataclass
class Backend:
    resources: list[DummyResource] = dataclasses.field(default_factory=list)
    created: list[str] = dataclasses.field(default_factory=list)
    reused: list[str] = dataclasses.field(default_factory=list)

    def list_resources(self, *args: Any) -> _Result[list[DummyResource], Failure]:
        return _Ok(self.resources)

    def create_resource_request(self, *args: Any) -> _Result[ResourceCreationRequest, Failure]:
        return _Ok(ResourceCreationRequest())

    def create_resource(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: Any,
        name: str,
        request: ResourceCreationRequest,
    ) -> _Result[ResourceCreationOutcome[DummyResource], Failure]:
        self.created.append(name)

        return _Ok(ResourceCreationOutcome(resource=DummyResource(name=name, state='pending')))

    def reuse_resource(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: Any,
        request: ResourceCreationRequest,
        resource: DummyResource,
    ) -> _Result[ResourceCreationOutcome[DummyResource], Failure]:
        self.reused.append(resource.name)

        return _Ok(ResourceCreationOutcome(resource=resource))


@pytest.fixture(name='pool')
def fixture_pool(logger: gluetool.log.ContextAdapter) -> mock.MagicMock:
    pool = mock.MagicMock(name='pool')
    pool.poolname = 'dummy-pool'
    pool.render_resource_name = lambda session, guest_request, naming: PoolDriver.render_resource_name(
        pool, session, guest_request, naming
    )

    return pool


def _acquire(
    logger: gluetool.log.ContextAdapter,
    pool: mock.MagicMock,
    backend: Backend,
    naming: NamingStrategy,
) -> _Result[ResourceCreationOutcome[DummyResource], Failure]:
    guest_request = mock.MagicMock(name='guest_request')
    guest_request.guestname = GUESTNAME

    manager: ResourceManager[DummyResource, ResourceCreationRequest, ResourceCreationOutcome[DummyResource]] = (
        ResourceManager(
            logger=logger,
            pool=pool,
            resource_type='dummy',
            list_resources=backend.list_resources,
            naming=naming,
            create_resource_request=backend.create_resource_request,
            create_resource=backend.create_resource,
            reuse_resource=backend.reuse_resource,
        )
    )

    return manager.acquire(logger, guest_request, mock.MagicMock(), mock.MagicMock())


def test_create(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    backend = Backend()

    _acquire(logger, pool, backend, NamingStrategy('dummy')).unwrap()

    assert backend.created == [f'artemis-{GUESTNAME}']
    pool.dispatch_resource_cleanup.assert_not_called()


def test_reuse(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    backend = Backend(resources=[DummyResource(name=f'artemis-{GUESTNAME}', state='pending')])

    _acquire(logger, pool, backend, NamingStrategy('dummy')).unwrap()

    assert backend.created == []
    assert backend.reused == [f'artemis-{GUESTNAME}']


def test_ignore_foreign(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    # A resource of another guest whose name starts with the expected name must be left alone.
    backend = Backend(resources=[DummyResource(name=f'artemis-{GUESTNAME}-another', state='error')])

    _acquire(logger, pool, backend, NamingStrategy('dummy')).unwrap()

    assert backend.created == [f'artemis-{GUESTNAME}']
    pool.dispatch_resource_cleanup.assert_not_called()


def test_ignore_foreign_backend_lookup(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    # With backend lookup, names are not checked: whatever the backend reports belongs to the guest request.
    backend = Backend(resources=[DummyResource(name='whatever', state='pending')])

    _acquire(logger, pool, backend, NamingStrategy('dummy', lookup=LookupMethod.BACKEND)).unwrap()

    assert backend.reused == ['whatever']


def test_postfix(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    backend = Backend(
        resources=[
            DummyResource(name=f'artemis-{GUESTNAME}', state='error'),
            DummyResource(name=f'artemis-{GUESTNAME}-1', state='error'),
        ]
    )

    _acquire(logger, pool, backend, NamingStrategy('dummy')).unwrap()

    assert backend.created == [f'artemis-{GUESTNAME}-2']
    assert pool.dispatch_resource_cleanup.call_count == 2


def test_postfix_exhausted(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    backend = Backend(
        resources=[DummyResource(name=f'artemis-{GUESTNAME}', state='error')]
        + [DummyResource(name=f'artemis-{GUESTNAME}-{i}', state='error') for i in range(1, 7)]
    )

    r_outcome = _acquire(logger, pool, backend, NamingStrategy('dummy'))

    assert r_outcome.failure().message == 'Too many leftover resources'
    assert backend.created == []


def test_postfix_within_length_limit(logger: gluetool.log.ContextAdapter, pool: mock.MagicMock) -> None:
    # The expected name uses the whole length limit, the postfix makes room for itself by shortening the name.
    expected_name = f'artemis-{GUESTNAME}'
    naming = NamingStrategy('dummy', constraints=NameConstraints(max_length=len(expected_name)))

    backend = Backend()
    _acquire(logger, pool, backend, naming).unwrap()

    assert backend.created == [expected_name]

    backend = Backend(resources=[DummyResource(name=expected_name, state='error')])
    _acquire(logger, pool, backend, naming).unwrap()

    postfixed_name = f'{expected_name[:-2]}-1'

    assert backend.created == [postfixed_name]

    # The shortened, postfixed resource is recognized as belonging to the guest request.
    backend = Backend(
        resources=[
            DummyResource(name=expected_name, state='error'),
            DummyResource(name=postfixed_name, state='pending'),
        ]
    )
    _acquire(logger, pool, backend, naming).unwrap()

    assert backend.created == []
    assert backend.reused == [postfixed_name]


def test_name_independent_of_resources_limit(
    logger: gluetool.log.ContextAdapter, pool: mock.MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Changing the limit must not rename resources of guest requests in flight.
    naming = NamingStrategy('dummy', constraints=NameConstraints(max_length=len(f'artemis-{GUESTNAME}')))

    names = []

    for limit in ('7', '10', '100'):
        monkeypatch.setenv('ARTEMIS_POOL_RESOURCES_PER_REQUEST_LIMIT', limit)

        backend = Backend()
        _acquire(logger, pool, backend, naming).unwrap()

        names += backend.created

    assert names == [f'artemis-{GUESTNAME}'] * 3
