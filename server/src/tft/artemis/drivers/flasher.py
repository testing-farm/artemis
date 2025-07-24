# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
from typing import Any, Dict, Optional

import gluetool.log
import gluetool.utils
import requests
import requests.exceptions
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import GuestLog, GuestLogContentType, GuestRequest
from ..knobs import KNOB_DISABLE_CERT_VERIFICATION, KNOB_HTTP_TIMEOUT
from ..metrics import PoolResourcesMetrics
from . import (
    KNOB_UPDATE_GUEST_REQUEST_TICK,
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
    flasher_id: str


@dataclasses.dataclass
class FlasherPoolResourcesIDs(PoolResourcesIDs):
    flasher_id: Optional[str] = None
    guestname: Optional[str] = None


class FlasherDriver(PoolDriver):
    pool_data_class = FlasherPoolData

    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:
        super().__init__(logger, poolname, pool_config)
        self.url = self.pool_config["url"]

    def adjust_capabilities(self, capabilities: PoolCapabilities) -> Result[PoolCapabilities, Failure]:
        capabilities.supported_guest_logs = [
            ('console:dump', GuestLogContentType.BLOB),
            ('flasher-event:dump', GuestLogContentType.BLOB)
        ]
        return Ok(capabilities)

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        if guest_request.environment.has_ks_specification:
            return Ok(CanAcquire.cannot('kickstart not supported'))

        payload = {
            "image": guest_request._environment["os"]["compose"],
            "hostname": (guest_request._environment.get("hw", {}).get("constraints") or {}).get("hostname"),
            "metadata": json.dumps({"user_data": guest_request.user_data, "Artemis_guestname": guest_request.guestname})
        }

        try:
            response = requests.post(
                f"{self.url}/preck/{self.poolname}",
                json=payload,
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to query acquisition', exc))

        can_acquire = False
        reason = None
        if response.status_code == 200:
            can_acquire = True
        else:
            reason = Failure(message=response.content, recoverable=self._is_recoverable(response))

        return Ok(CanAcquire(can_acquire=can_acquire, reason=reason))

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        '''
        Response
        """"""""

        .. code-block:: json

           {
            "state": ["pending"|"complete"|"cancel"],
            "flasher_id": string,
            "address": optional[string]
           }
        '''
        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
        )

        payload = {
            "image": guest_request._environment["os"]["compose"],
            "hostname": (guest_request._environment.get("hw", {}).get("constraints") or {}).get("hostname"),
            "metadata": json.dumps({"user_data": guest_request.user_data, "Artemis_guestname": guest_request.guestname})
        }

        try:
            response = requests.post(
                f"{self.url}/loan/{self.poolname}",
                json=payload,
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to acquire guest', exc))

        response.raise_for_status()

        data = response.json()

        flasher_id = data.get("guest_id")
        if not flasher_id:
            return Error(Failure(
                'no guest ID in response',
                payload=data
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState[data.get("state").upper()],
            pool_data=FlasherPoolData(flasher_id=flasher_id),
            address=data.get("address"),
        ))

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        '''
        Response
        """"""""

        .. code-block:: json

           {
            "state": ["pending"|"complete"|"cancel"],
            "address": optional[string]
           }
        '''
        r_delay = KNOB_UPDATE_GUEST_REQUEST_TICK.get_value(entityname=self.poolname)

        if r_delay.is_error:
            return Error(r_delay.unwrap_error())

        pool_data = guest_request.pool_data.mine(self, FlasherPoolData)

        try:
            response = requests.get(
                f"{self.url}/loan/{pool_data.flasher_id}",
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to update guest', exc))

        response.raise_for_status()

        data = response.json()

        state = ProvisioningState[data.get("state").upper()]
        address = data.get("address")

        return Ok(ProvisioningProgress(
            state=state,
            pool_data=pool_data,
            address=address,
            delay_update=r_delay.unwrap(),
        ))

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
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
            FlasherPoolResourcesIDs(
                flasher_id=pool_data.flasher_id,
                guestname=guest_request.guestname
            ),
            guest_request=guest_request
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[ReleasePoolResourcesState, Failure]:
        pool_resources = FlasherPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        try:
            response = requests.delete(
                f"{self.url}/loan/{pool_resources.flasher_id}",
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to release guest', exc))

        response.raise_for_status()

        return Ok(ReleasePoolResourcesState.RELEASED)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        '''
        Response
        """"""""

        .. code-block:: json

           {
             "usage": {
                "instances": integer,
                "cores": integer,
                "memory": integer
             }
           }
        '''

        r_resources = super().fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        try:
            response = requests.get(
                f"{self.url}/{self.poolname}/pool_resources_metrics",
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to fetch pool resources metrics', exc))

        response.raise_for_status()

        data = response.json()
        resources.usage.instances = data["usage"]["instances"]
        resources.usage.cores = 0
        resources.usage.memory = 0
        resources.limits.instances = data["limits"]["instances"]
        resources.limits.cores = 0
        resources.limits.memory = 0

        return Ok(resources)

    def _is_recoverable(self, response: requests.Response) -> bool:
        code = response.status_code
        if code == 500:
            return False
        if code == 501:
            return False
        if code == 400:
            return False
        if code == 404:
            return True
        if code == 503:
            return True
        response.raise_for_status()

    def _get_guest_log_url(
        self,
        guest_request: GuestRequest,
        log_name: str
    ) -> str:
        """
        Create location (URL) of guest log.

        :param guest_request: a request whose logs to look for.
        :param log_name: a name of the log as known to backend (e.g. ``cmd/latest``).
        :returns: log URL.
        """

        pool_data = guest_request.pool_data.mine(self, FlasherPoolData)

        return f"{self.url}/{self.poolname}/getlog/{pool_data.flasher_id}/{log_name}"

    def _update_guest_log_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_log: GuestLog,
        url: str
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        GET the data at the URL, return it with the state to signal that more data is available.
        """
        assert url is not None

        try:
            response = requests.get(url,
                                    verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                                    timeout=KNOB_HTTP_TIMEOUT.value)
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to fetch flasher log', exc, url=url))

        response.raise_for_status()

        return Ok(GuestLogUpdateProgress.from_unabridged(
            logger,
            guest_log,
            response.text
        ))

    @guest_log_updater('flasher', 'flasher-event:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_event_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        This log contains explicit logging output and does not contain much debug output. It will show the flow of
        events taking place while provisioning a guest. It can be compared to the Artemis guest event log and is a good
        place to look for where the problem occurred. Why the problem occurred could be discovered in the 'cmd' log,
        which contains output of the underlying commands being executed to provision the guest.
        """
        return self._update_guest_log_blob(
            logger,
            guest_log,
            self._get_guest_log_url(guest_request, 'event')
        )

    @guest_log_updater('flasher', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_console_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Console output cannot be grouped. So all data is always returned and there is no need for '/lastest' and '/all'
        endpoints.
        """
        return self._update_guest_log_blob(
            logger,
            guest_log,
            self._get_guest_log_url(guest_request, 'console')
        )

    def trigger_reboot(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[None, Failure]:
        pool_data = guest_request.pool_data.mine_or_none(self, FlasherPoolData)

        if not pool_data:
            return Ok(None)

        try:
            response = requests.put(
                f"{self.url}/loan/reboot/{pool_data.flasher_id}",
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc('failed to trigger guest reboot', exc))

        response.raise_for_status()

        return Ok(None)


PoolDriver._drivers_registry['flasher'] = FlasherDriver
