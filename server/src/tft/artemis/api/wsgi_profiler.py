# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, cast

# No relative import here - this file is used by gunicorn directly, not imported by our code.
from tft.artemis import get_logger
from tft.artemis.api import KNOB_API_PROFILE_LIMIT
from tft.artemis.profile import Profiler


def pre_request(worker: Any, request: Any) -> None:
    worker.profiler = Profiler()
    worker.profiler.start()


def post_request(worker: Any, request: Any, *args: Any) -> None:
    profiler = cast(Profiler, worker.profiler)

    profiler.stop()
    profiler.log(get_logger(), f'profiled "{request.method} {request.uri}"', limit=KNOB_API_PROFILE_LIMIT.value)
