# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
from unittest import mock

import gluetool.log
import sqlalchemy.orm.session
from gluetool.result import Ok

from tft.artemis.drivers.azure import AzureDriver, ResourceGroupCreationRequest


def _guest_request(guestname: str = 'dummy-guest') -> mock.MagicMock:
    guest_request = mock.MagicMock(name='guest_request')
    guest_request.guestname = guestname

    return guest_request


def test_create_resource_group_request(azure_pool: AzureDriver, logger: gluetool.log.ContextAdapter) -> None:
    r_request = azure_pool._create_resource_group_request(
        logger, mock.MagicMock(spec=sqlalchemy.orm.session.Session), mock.MagicMock(), _guest_request()
    )

    assert r_request.unwrap() == ResourceGroupCreationRequest(name='artemis-dummy-guest')


def test_create_resource_group_request_shared(azure_pool: AzureDriver, logger: gluetool.log.ContextAdapter) -> None:
    azure_pool.pool_config['guest-resource-group'] = 'shared-group'

    r_request = azure_pool._create_resource_group_request(
        logger, mock.MagicMock(spec=sqlalchemy.orm.session.Session), mock.MagicMock(), _guest_request()
    )

    assert r_request.unwrap() == ResourceGroupCreationRequest(name='shared-group')


@mock.patch('tft.artemis.drivers.azure.AzureSession')
def test_create_resource_group_uses_given_name(
    mock_az_session: mock.MagicMock, azure_pool: AzureDriver, logger: gluetool.log.ContextAdapter
) -> None:
    # The resource manager may pick a postfixed name when the expected one is held by a leftover resource group.
    # The given name must win over the one stored in the creation request.
    az_session = mock_az_session.return_value.__enter__.return_value
    az_session.run.return_value = Ok({'name': 'artemis-dummy-guest-1'})

    r_outcome = azure_pool._create_resource_group(
        logger,
        mock.MagicMock(spec=sqlalchemy.orm.session.Session),
        _guest_request(),
        'artemis-dummy-guest-1',
        ResourceGroupCreationRequest(name='artemis-dummy-guest'),
    )

    outcome = r_outcome.unwrap()

    assert outcome.resource.name == 'artemis-dummy-guest-1'
    assert outcome.resource.is_shared is False

    command = az_session.run.call_args.args[1]

    assert command[command.index('--name') + 1] == 'artemis-dummy-guest-1'
