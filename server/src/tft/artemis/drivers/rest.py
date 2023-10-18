# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import base64
import dataclasses
import json
import threading
from typing import Any, Dict, Optional, Tuple

import gluetool.log
import gluetool.utils
import requests
import requests.exceptions
import sqlalchemy.orm.session
from gluetool.result import Error, Ok, Result

from .. import Failure
from ..db import GuestRequest
from ..knobs import KNOB_DISABLE_CERT_VERIFICATION
from ..metrics import PoolResourcesMetrics
from . import KNOB_UPDATE_GUEST_REQUEST_TICK, PoolData, PoolDriver, PoolResourcesIDs, ProvisioningProgress, \
    ProvisioningState, SerializedPoolResourcesIDs

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
    ) -> Result[Tuple[bool, Optional[str]], Failure]:
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

        if r_answer.unwrap()[0] is False:
            return r_answer

        payload = {
            "environment": base64.b64encode(json.dumps(guest_request._environment).encode()),
        }

        try:
            response = requests.get(
                f"{self.url}/guests",
                params=payload,
                headers=self._get_headers(guestname=guest_request.guestname),
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value
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

        return Ok((result, reason))

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
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
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value
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
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
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
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value
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
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        if RestPoolData.is_empty(guest_request):
            return Ok(True)

        r_job_cancel = self._dispatch_resource_cleanup(
            logger,
            guest_id=RestPoolData.unserialize(guest_request).guest_id,
            guest_request=guest_request
        )

        if r_job_cancel.is_error:
            return Error(r_job_cancel.unwrap_error())

        return Ok(True)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_id: Optional[str],
        guest_request: Optional[GuestRequest]
    ) -> Result[None, Failure]:
        resource_ids = RestPoolResourcesIDs(guest_id=guest_id)

        if guest_request is not None:
            resource_ids.guestname = guest_request.guestname

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

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
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value
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
                verify=not KNOB_DISABLE_CERT_VERIFICATION.value
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


PoolDriver._drivers_registry['rest'] = RestDriver
