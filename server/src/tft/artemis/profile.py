# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Helpers for profiling code.
"""

import cProfile
import io
import pstats
import time
from typing import List, Optional, Tuple, TypeVar

import gluetool.log
import pyinstrument

T = TypeVar('T')


class Profiler:
    """
    Bundles together various parameters and helpers for profiling a code.
    """

    def __init__(self) -> None:
        """
        Bundles together various parameters and helpers for profiling a code.
        """

        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None

        self._profiler: Optional[cProfile.Profile] = None
        self._callstack_profiler: Optional[pyinstrument.Profiler] = None

    @property
    def elapsed_time(self) -> Optional[float]:
        """
        Return a time elapsed between start and stop events.

        :returns: elapsed time between calls of :py:meth:`start` and :py:meth:`stop`, or ``None`` if either
            one of them did not happen yet.
        """

        if self.start_time is None or self.stop_time is None:
            return None

        return self.stop_time - self.start_time

    def start(self) -> None:
        """
        Begin profiling.
        """

        self.start_time = time.time()

        self._profiler = cProfile.Profile()
        self._callstack_profiler = pyinstrument.Profiler()

        self._profiler.enable()
        self._callstack_profiler.start()

    def stop(self) -> None:
        """
        Terminate profiling.
        """

        if self._callstack_profiler:
            self._callstack_profiler.stop()

        if self._profiler:
            self._profiler.disable()

        self.stop_time = time.time()

    def format(
        self,
        sort_stats: Tuple[str, str] = ('cumulative', 'time'),
        limit: int = 30
    ) -> str:
        """
        Format captured profiling data report.

        :param sort_stats: arguments describing how statistics should be sorted. All are passed to
            for :py:meth:`pstats.Stats.sort_stats`.
        :param limit: how many entries should be reported in the summary.
        :returns: nicely formatted profiling report.
        """
        lines: List[str] = []

        if self.elapsed_time is not None:
            lines.append(f'elapsed time: {self.elapsed_time:3}')

        if self._profiler is not None:
            s = io.StringIO()

            ps = pstats.Stats(self._profiler, stream=s).sort_stats(*sort_stats)
            ps.print_stats(limit)

            # TODO: this could be done in a better way - splitlines() just to get them merged
            # by `\n` one the next line?
            lines += s.getvalue().splitlines()
            lines += ['']

        if self._callstack_profiler is not None:
            lines += self._callstack_profiler.output_text(unicode=False, color=True).splitlines()
            lines += ['']

        return '\n'.join(lines)

    def log(
        self,
        logger: gluetool.log.ContextAdapter,
        label: str,
        sort_stats: Tuple[str, str] = ('cumulative', 'time'),
        limit: int = 30
    ) -> None:
        """
        Log captured profiling data report.

        :param logger: logger to use for logging.
        :param label: header to emit before the report.
        :param sort_stats: arguments describing how statistics should be sorted. All are passed to
            for :py:meth:`pstats.Stats.sort_stats`.
        :param limit: how many entries should be reported in the summary.
        """

        gluetool.log.log_blob(logger.info, label, self.format(sort_stats=sort_stats, limit=limit))  # noqa: FS002
