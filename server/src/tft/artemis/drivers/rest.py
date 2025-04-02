# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import base64
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
from ..db import GuestLog, GuestLogContentType, GuestLogState, GuestRequest
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
    SerializedPoolResourcesIDs,
    guest_log_updater,
)

ARTEMIS_GUESTNAME_HEADER = "Artemis-guestname"


@dataclasses.dataclass
class RestPoolData(PoolData):
    guest_id: str


@dataclasses.dataclass
class RestPoolResourcesIDs(PoolResourcesIDs):
    guest_id: Optional[str] = None
    guestname: Optional[str] = None


class RestDriver(PoolDriver):
    '''
    A generic driver that communicates with REST-based middleman.
    '''

    drivername = 'rest'

    pool_data_class = RestPoolData

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
            ('flasher-debug:dump', GuestLogContentType.URL),
            ('flasher-event:dump', GuestLogContentType.URL),
            ('flasher-debug:dump', GuestLogContentType.BLOB),
            ('flasher-event:dump', GuestLogContentType.BLOB)
        ]

        return Ok(capabilities)

    def _get_headers(self, guestname: Optional[str] = None) -> Dict[str, str]:
        """
        Prepares HTTP headers for backend requests.
        """
        if guestname is not None:
            return {ARTEMIS_GUESTNAME_HEADER: guestname}
        return {}

    def can_acquire(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[CanAcquire, Failure]:
        '''
        Request
        """""""

        .. code-block:: json

           GET /guests

           {
             "environment": guest request environment
           }

        Response
        """"""""

        .. code-block:: json

           {
             "result": boolean,
             "reason": optional[string]
           }
        '''
        r_answer = super().can_acquire(logger, session, guest_request)

        if r_answer.is_error:
            return Error(r_answer.unwrap_error())

        if r_answer.unwrap().can_acquire is False:
            return r_answer

        if guest_request.environment.has_ks_specification:
            return Ok(CanAcquire.cannot('kickstart not supported'))

        payload = {
            "environment": base64.b64encode(json.dumps(guest_request._environment).encode()),
        }

        try:
            response = requests.get(
                f"{self.url}/guests",
                params=payload,
                headers=self._get_headers(guestname=guest_request.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to query acquisition',
                exc
            ))

        data = response.json()

        result = data.get("result")
        reason = data.get("reason", None)

        return Ok(CanAcquire(can_acquire=result, reason=Failure(reason) if reason else None))

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        '''
        Request
        """""""

        .. code-block:: json

           POST /guests

           {
             "environment": guest request environment
           }

        Response
        """"""""

        .. code-block:: json

           {
            "state": ["pending"|"complete"|"cancel"],
            "guest_id": string,
            "address": optional[string]
           }
        '''
        self.log_acquisition_attempt(
            logger,
            session,
            guest_request,
        )

        payload = {
            "environment": guest_request._environment,
        }

        try:
            response = requests.post(
                f"{self.url}/guests",
                json=payload,
                headers=self._get_headers(guestname=guest_request.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to acquire guest',
                exc
            ))

        data = response.json()

        guest_id = data.get("guest_id")
        if not guest_id:
            return Error(Failure(
                'REST backend responded with no guest ID',
                payload=data
            ))

        return Ok(ProvisioningProgress(
            state=ProvisioningState[data.get("state").upper()],
            pool_data=RestPoolData(guest_id=guest_id),
            address=data.get("address", None),
        ))

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest
    ) -> Result[ProvisioningProgress, Failure]:
        '''
        Request
        """""""

        .. code-block:: json

           GET /guests/{guest_id}

           {
             "environment": guest request environment,
           }

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

        pool_data = RestPoolData.unserialize(guest_request)

        payload = {
            "environment": guest_request._environment,
        }

        try:
            response = requests.get(
                f"{self.url}/guests/{pool_data.guest_id}",
                json=payload,
                headers=self._get_headers(guestname=guest_request.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to update guest',
                exc
            ))

        data = response.json()

        state = ProvisioningState[data.get("state").upper()]
        address = data.get("address", None)

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

        if RestPoolData.is_empty(guest_request):
            return Ok(None)

        pool_data = RestPoolData.unserialize(guest_request)

        return self.dispatch_resource_cleanup(
            logger,
            session,
            RestPoolResourcesIDs(
                guest_id=pool_data.guest_id,
                guestname=guest_request.guestname
            ),
            guest_request=guest_request
        )

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        '''
        Request
        """""""

        .. code-block:: json

           DELETE /guests/{guest_id}

        Response
        """"""""

        The response is expected to be empty.
        '''
        pool_resources = RestPoolResourcesIDs.unserialize_from_json(raw_resource_ids)
        try:
            response = requests.delete(
                f"{self.url}/guests/{pool_resources.guest_id}",
                headers=self._get_headers(guestname=pool_resources.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to release guest',
                exc
            ))

        return Ok(None)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        '''
        Request
        """""""

        .. code-block:: json

           GET /pool_resources_metrics

           The payload is empty.

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
                f"{self.url}/pool_resources_metrics",
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to fetch pool resources metrics',
                exc
            ))

        data = response.json()
        resources.usage.instances = data["usage"]["instances"]
        resources.usage.cores = 0
        resources.usage.memory = 0
        resources.limits.instances = data["limits"]["instances"]
        resources.limits.cores = 0
        resources.limits.memory = 0

        return Ok(resources)

    def _get_guest_log_url(
        self,
        guest_request: GuestRequest,
        log_name: str
    ) -> str:
        """
        Create location (URL) of guest log.

        :param logger: logger to use for logging.
        :param guest_request: a request whose logs to look for.
        :param log_name: a name of the log as known to backend (e.g. ``cmd/latest``).
        :returns: log URL.
        """

        pool_data = RestPoolData.unserialize(guest_request)

        return f"{self.url}/getlog/{pool_data.guest_id}/{log_name}"

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
            response.raise_for_status()

        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to fetch flasher log',
                exc,
                url=url
            ))

        return Ok(GuestLogUpdateProgress.from_unabridged(
            logger,
            guest_log,
            response.text
        ))

    @guest_log_updater('rest', 'flasher-debug:dump', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_cmd_all_url(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        url = self._get_guest_log_url(guest_request, 'cmd/all')
        return Ok(GuestLogUpdateProgress(state=GuestLogState.COMPLETE, url=url))

    @guest_log_updater('rest', 'flasher-event:dump', GuestLogContentType.URL)  # type: ignore[arg-type]
    def _update_guest_log_event_url(
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
        url = self._get_guest_log_url(guest_request, 'event')
        return Ok(GuestLogUpdateProgress(state=GuestLogState.COMPLETE, url=url))

    @guest_log_updater('rest', 'flasher-debug:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_cmd_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        """
        Artemis will store the log, replacing the exsting log data with data from newer requests to the log endpoint.
        So it doesn't make sense to have Artemis store the '/latest' data, which would exclude older data.
        """
        return self._update_guest_log_blob(
            logger,
            guest_log,
            self._get_guest_log_url(guest_request, 'cmd/all')
        )

    @guest_log_updater('rest', 'flasher-event:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
    def _update_guest_log_event_blob(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        guest_log: GuestLog
    ) -> Result[GuestLogUpdateProgress, Failure]:
        return self._update_guest_log_blob(
            logger,
            guest_log,
            self._get_guest_log_url(guest_request, 'event')
        )

    @guest_log_updater('rest', 'console:dump', GuestLogContentType.BLOB)  # type: ignore[arg-type]
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
        '''
        Request
        """""""

        .. code-block:: json

        POST /guests/{guest_id}/reboot

        Response
        """"""""

        The response is expected to be empty.
        '''
        pool_data = RestPoolData.unserialize(guest_request)

        try:
            response = requests.post(
                f"{self.url}/guests/{pool_data.guest_id}/reboot",
                headers=self._get_headers(guestname=guest_request.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value,
                timeout=KNOB_HTTP_TIMEOUT.value
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as exc:
            return Error(Failure.from_exc(
                'failed to trigger guest reboot',
                exc
            ))

        return Ok(None)


PoolDriver._drivers_registry['rest'] = RestDriver
