# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
import uuid
from typing import Any, Dict, Optional

import gluetool.log
import gluetool.utils
import requests
import requests.exceptions
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
from ..knobs import KNOB_DISABLE_CERT_VERIFICATION, KNOB_HTTP_TIMEOUT
from ..metrics import PoolResourcesMetrics
from . import (
    CanAcquire,
    GuestLogUpdateProgress,
    PoolCapabilities,
    PoolData,
    PoolDriver,
    PoolResourcesIDs,
    ProvisioningProgress,
    ProvisioningState,
    ReleasePoolResourcesState,
    SerializedPoolResourcesIDs,
    guest_log_updater,
)


@dataclasses.dataclass
class FlasherPoolData(PoolData):
    flasher_id: Optional[str] = None


@dataclasses.dataclass
class FlasherPoolResourcesIDs(PoolResourcesIDs):
    flasher_id: Optional[str] = None
    guestname: Optional[str] = None


class FlasherDriver(PoolDriver):
    drivername = 'flasher'  # PoolDriver needs this. See __init__.py

    pool_data_class = FlasherPoolData

    def __init__(self, logger: gluetool.log.ContextAdapter, poolname: str, pool_config: Dict[str, Any]) -> None:
        super().__init__(logger, poolname, pool_config)
        self.url = self.pool_config['url']

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supports_hostnames = True
        capabilities.supported_guest_logs = [
            ('console:dump', GuestLogContentType.BLOB),
            ('flasher-event:dump', GuestLogContentType.BLOB),
        ]
        return Ok(capabilities)

    def can_acquire(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        if guest_request.environment.has_ks_specification:
            return Ok(CanAcquire.cannot('kickstart not supported'))

        return Ok(CanAcquire(can_acquire=True))

    def acquire_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
        )

        body = {
            'image': guest_request._environment['os']['compose'],
            'hostname': (guest_request._environment.get('hw', {}).get('constraints') or {}).get('hostname'),
            'metadata': json.dumps(
                {'user_data': guest_request.user_data, 'Artemis_guestname': guest_request.guestname}
            ),
        }

        try:
            response = requests.post(
                f'{self.url}/loan/{self.poolname}',
                json=body,
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value,
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('acquire_guest request failed', exc))

        if response.status_code != 202:
            return Error(Failure(message=response.text, recoverable=self._is_recoverable(response.status_code)))

        flasher_id = response.text
        try:
            uuid.UUID(flasher_id, version=4)
        except (ValueError, TypeError):
            return Error(Failure('no UUID in acquire_guest response', response=flasher_id))

        return Ok(
            ProvisioningProgress(
                state=self._http_code_to_status(response.status_code),
                pool_data=FlasherPoolData(flasher_id=flasher_id),
                address=None,
            )
        )

    def update_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        pool_data = guest_request.pool_data.mine(self, FlasherPoolData)

        try:
            response = requests.get(
                f'{self.url}/loan/{pool_data.flasher_id}',
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value,
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('update_guest request failed', exc))

        return Ok(
            ProvisioningProgress(
                state=self._http_code_to_status(response.status_code),
                pool_data=pool_data,
                address=response.text or None,
            )
        )

    def release_guest(
        self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session, guest_request: GuestRequest
    ) -> Result[None, Failure]:
        """
        Release resources allocated for the guest back to the pool infrastructure.
        """

        pool_data = guest_request.pool_data.mine_or_none(self, FlasherPoolData)

        if not pool_data:
            return Ok(None)

        return self.dispatch_resource_cleanup(
            logger,
            session,
            FlasherPoolResourcesIDs(flasher_id=pool_data.flasher_id, guestname=guest_request.guestname),
            guest_request=guest_request,
        )

    def release_pool_resources(
        self, logger: gluetool.log.ContextAdapter, raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        pool_resources = FlasherPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        url = f'{self.url}/loan/{pool_resources.flasher_id}'

        try:
            response = requests.delete(
                url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('release_pool_resources request failed', exc))

        if response.status_code == 204:
            return Ok(ReleasePoolResourcesState.RELEASED)
        if response.status_code == 404:
            logger.warning(
                f"flasher request '{pool_resources.flasher_id}' with guestname \
                    '{pool_resources.guestname}' does not exist or already returned"
            )
            return Ok(ReleasePoolResourcesState.RELEASED)

        return Error(Failure('unexpected response', url=url, status_code=response.status_code, body=response.text))

    def fetch_pool_resources_metrics(
        self, logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()
        url = f'{self.url}/{self.poolname}/summary/metrics'

        try:
            response = requests.get(
                url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('fetch_pool_resources_metrics request failed', exc))

        if response.status_code != 200:
            return Error(Failure('unexpected response', url=url, status_code=response.status_code, body=response.text))

        data = response.json()
        try:
            resources.usage.instances = int(data['borrowed'])
            resources.limits.instances = int(data['enabled'])
        except ValueError as exc:
            return Error(Failure.from_exc('invalid metrics from pool', exc))

        return Ok(resources)

    def trigger_reboot(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[None, Failure]:
        pool_data = guest_request.pool_data.mine_or_none(self, FlasherPoolData)

        if not pool_data:
            return Ok(None)

        url = f'{self.url}/loan/reboot/{pool_data.flasher_id}'

        try:
            response = requests.put(
                url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('trigger_reboot request failed', exc))

        if response.status_code == 204:
            return Ok(None)

        return Error(
            Failure(
                'unexpected response',
                url=url,
                status_code=response.status_code,
                body=response.text,
                recoverable=self._is_recoverable(response.status_code),
            )
        )

    @guest_log_updater('flasher', 'flasher-event:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_event_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        This log contains explicit logging output and does not contain much debug output. It will show the flow of
        events taking place while provisioning a guest. It can be compared to the Artemis guest event log and is a good
        place to look for where the problem occurred.
        """
        return self._update_guest_log_blob(logger, guest_log, guest_request, 'event')

    @guest_log_updater('flasher', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_blob(
        self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest, guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_blob(logger, guest_log, guest_request, 'console')

    def _is_recoverable(self, response_code: int) -> bool:
        if response_code == 500:
            return False  # Service is down.
        if response_code == 509:
            return True  # Request cancelled, but can be retried.
        if response_code == 400:
            return False  # Problem with request.
        if response_code == 404:
            return False  # Guest or host doesn't exist.
        if response_code == 503:
            return True  # Service temporarily unavailable - no capacity
        return True  # default to retrying (recoverable)

    def _http_code_to_status(self, response_code: int) -> ProvisioningState:
        if response_code == 202:
            return ProvisioningState.PENDING
        if response_code == 200:
            return ProvisioningState.COMPLETE
        if response_code == 509:
            return ProvisioningState.CANCEL
        return ProvisioningState.CANCEL

    def _update_guest_log_blob(
        self, logger: gluetool.log.ContextAdapter, guest_log: GuestLog, guest_request: GuestRequest, log_name: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        GET the data at the URL, return it with the state to signal that more data is available.
        """
        pool_data = guest_request.pool_data.mine(self, FlasherPoolData)

        if not pool_data.flasher_id:
            return Ok(GuestLogUpdateProgress(state=GuestLogState.IN_PROGRESS))

        url = f'{self.url}/{self.poolname}/getlog/{pool_data.flasher_id}/{log_name}'

        try:
            response = requests.get(
                url, verify=not KNOB_DISABLE_CERT_VERIFICATION.value, timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('_update_guest_log_blob request failed', exc, url=url))

        if response.status_code != 200:
            return Error(Failure('unexpected response', url=url, status_code=response.status_code, body=response.text))

        return Ok(GuestLogUpdateProgress.from_unabridged(logger, guest_log, response.text))


PoolDriver._drivers_registry['flasher'] = FlasherDriver
