# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
from typing import Optional

from ... import db as artemis_db


@dataclasses.dataclass
class GuestLogResponse_v0_0_69:  # noqa: N801
    state: artemis_db.GuestLogState
    contenttype: artemis_db.GuestLogContentType

    url: Optional[str]
    blob: Optional[str]

    updated: Optional[datetime.datetime]
    expires: Optional[datetime.datetime]

    @classmethod
    def from_db(cls, log: artemis_db.GuestLog) -> 'GuestLogResponse_v0_0_69':
        blob_components: list[str] = []

        for blob in log.blobs:
            blob_components.append(f'# Captured at {blob.ctime}')
            blob_components.append(blob.content)
            blob_components.append('')

        return cls(
            state=artemis_db.GuestLogState(log.state),
            contenttype=artemis_db.GuestLogContentType(log.contenttype),
            url=log.url,
            blob='\n'.join(blob_components),
            updated=log.updated,
            expires=log.expires,
        )
