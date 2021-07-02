from typing import Any, cast

# No relative import here - this file is used by gunicorn directly, not imported by our code.
# This will fool mypy into thinking we can't import them, but we really can.
from tft.artemis import get_logger  # type: ignore
from tft.artemis.api import KNOB_API_PROFILE_LIMIT  # type: ignore
from tft.artemis.profile import Profiler  # type: ignore


def pre_request(worker: Any, request: Any) -> None:
    worker.profiler = Profiler()
    worker.profiler.start()


def post_request(worker: Any, request: Any, *args: Any) -> None:
    profiler = cast(Profiler, worker.profiler)  # type: ignore  # mypy reports redundant cast, it's a mypy issue

    profiler.stop()
    profiler.log(get_logger(), f'profiled "{request.method} {request.uri}"', limit=KNOB_API_PROFILE_LIMIT.value)
