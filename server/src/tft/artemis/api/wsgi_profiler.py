import cProfile
import io
import pstats
import time
from typing import Any

from gluetool.log import log_blob

# No relative import here - this file is used by gunicorn directly, not imported by our code.
# This will fool mypy into thinking we can't import them, but we really can.
from tft.artemis import get_logger  # type: ignore
from tft.artemis.api import KNOB_API_PROFILE_LIMIT  # type: ignore


def pre_request(worker: Any, request: Any) -> None:
    worker.start_time = time.time()

    worker.profile = cProfile.Profile()
    worker.profile.enable()


def post_request(worker: Any, request: Any, *args: Any) -> None:
    worker.profile.disable()

    worker.elapsed_time = time.time() - worker.start_time

    logger = get_logger()

    s = io.StringIO()

    ps = pstats.Stats(worker.profile, stream=s).sort_stats('time', 'cumulative')
    ps.print_stats(KNOB_API_PROFILE_LIMIT.value)

    log_blob(logger.info, '"{} {}", spent {:.3}'.format(request.method, request.uri, worker.elapsed_time), s.getvalue())
