# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0
from typing import Annotated

import gluetool.log
import redis
from fastapi import Depends, Request
from prometheus_client import CollectorRegistry

from .. import get_cache as get_artemis_cache
from .. import get_db as get_artemis_db
from .. import get_logger as get_artemis_logger
from .. import metrics
from ..db import DB
from .models import AuthContext


def get_logger() -> gluetool.log.ContextAdapter:
    return get_artemis_logger()


def get_db(logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]) -> DB:
    return get_artemis_db(logger, application_name='artemis-api-server')


def get_cache(logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]) -> 'redis.Redis':
    return get_artemis_cache(logger)


def get_auth_context(request: Request,
                     logger: Annotated[gluetool.log.ContextAdapter, Depends(get_logger)]) -> AuthContext:
    r_ctx = AuthContext.extract(request)

    # If the context does not exist, it means we have a handler that requests it, by adding
    # corresponding parameter, but auth middleware did not create it - the most likely chance
    # is the handler takes care of path that is marked as "auth not needed".
    if r_ctx.is_error:
        failure = r_ctx.unwrap_error()

        failure.handle(logger)

        # We cannot continue: handler requires auth context, and we don't have any. It's not possible to
        # recover.
        raise Exception(failure.message)

    return r_ctx.unwrap()


def get_metrics_tree() -> metrics.Metrics:
    metrics_tree = metrics.Metrics()
    metrics_tree.register_with_prometheus(CollectorRegistry())
    return metrics_tree
