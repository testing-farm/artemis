# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock

import gluetool.log
import pytest

import tft.artemis.drivers
from tft.artemis.api.models import GuestRequest
from tft.artemis.tasks import Workspace

from . import DummyPool


@pytest.fixture(name='dummy_guest_request')
def fixture_dummy_guest_request(workspace: Workspace) -> MagicMock:
    workspace.gr = MagicMock(name='dummy-guest-request')

    return workspace.gr


@pytest.fixture(name='dummy_pool')
def fixture_dummy_pool(
    logger: gluetool.log.ContextAdapter, workspace: Workspace, dummy_guest_request: GuestRequest
) -> tft.artemis.drivers.PoolDriver:
    assert workspace.gr

    workspace.gr.poolname = 'dummy-pool'
    workspace.pool = DummyPool(logger, 'dummy-pool', {})

    return workspace.pool


@pytest.fixture(name='dummy_master_key')
def fixture_master_key(workspace: Workspace) -> MagicMock:
    workspace.master_key = MagicMock(name='dummy-master-key')

    return workspace.master_key
