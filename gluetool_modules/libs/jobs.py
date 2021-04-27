# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Simplyfies access to concurrently running jobs. Based on ``concurrent.futures``, letting user
to use callbacks to step into the whole process, it should take care of the heavy lifting.
"""

import concurrent.futures

import gluetool
import gluetool.log

from six import reraise

# Type annotations
from typing import cast, Any, Callable, Dict, List, NamedTuple, Optional, Tuple  # noqa


#: A job to run.
#:
#: :param gluetool.log.ContextAdapter logger: logger to use when logging events related to the job.
#: :param callable target: function to call to perform the job.
#: :param tuple args: positional arguments of ``target``.
#: :param dict kwargs: keyword arguments of ``target``.
Job = NamedTuple('Job', (
    ('logger', gluetool.log.ContextAdapter),
    ('name', str),
    ('target', Callable[..., Any]),
    ('args', Tuple[Any, ...]),
    ('kwargs', Dict[str, Any])
))


JobErrorType = Tuple[Job, gluetool.log.ExceptionInfoType]


def handle_job_errors(errors, exception_message, logger=None):
    # type: (List[JobErrorType], str, Optional[gluetool.log.ContextAdapter]) -> None
    """
    Take care of reporting exceptions gathered from futures, and re-raise one of them - or a new,
    generic one - to report a process, performed by jobs, failed.

    :param list(tuple(Job, exception info)) errors: jobs and the errors they raised.
    :param str exception_message: a message used when raising generic exception.
    :param ContextAdapter logger: top-level logger to use when logging things related to all errors.
    """

    logger = logger or gluetool.log.Logging.get_logger()

    logger.debug('at least one job failed')

    # filter exceptions using given ``check`` callback, and raise the first suitable one - or return back
    def _raise_first(check):
        # type: (Callable[[gluetool.log.ExceptionInfoType], bool]) -> None

        for _, exc_info in errors:
            if not check(exc_info):
                continue

            reraise(*exc_info)

    # Soft errors have precedence - the let user know something bad happened, which is better
    # than just "infrastructure error".
    _raise_first(lambda exc: isinstance(exc[1], gluetool.SoftGlueError))

    # Then common CI errors
    _raise_first(lambda exc: isinstance(exc[1], gluetool.GlueError))

    # Ok, no custom exception, maybe just some Python ones - kill the pipeline.
    raise gluetool.GlueError(exception_message)


class JobEngine(object):
    def __init__(self,
                 logger=None,  # type: Optional[gluetool.log.ContextAdapter]
                 max_workers=None,  # type: Optional[int]
                 worker_name_prefix='worker',  # type: str
                 on_job_start=None,  # type: Optional[Callable[..., None]]
                 on_job_complete=None,  # type: Optional[Callable[..., None]]
                 on_job_error=None,  # type: Optional[Callable[..., None]]
                 on_job_done=None  # type: Optional[Callable[..., None]]
                ):  # noqa
        # type: (...) -> None

        self.logger = logger or gluetool.log.Logging.get_logger()

        self._jobs = []  # type: List[Job]
        self._executor = None  # type: Optional[concurrent.futures.ThreadPoolExecutor]
        self._futures = {}  # type: Dict[Any, Any]
        self.errors = []  # type: List[JobErrorType]

        self.max_workers = max_workers
        self.worker_name_prefix = worker_name_prefix

        self.on_job_start = on_job_start  # type: Optional[Callable[..., None]]
        self.on_job_complete = on_job_complete  # type: Optional[Callable[..., None]]
        self.on_job_error = on_job_error  # type: Optional[Callable[..., None]]
        self.on_job_done = on_job_done  # type: Optional[Callable[..., None]]

    def _log_futures(self, label):
        # type: (str) -> None

        table = [
            ['Future', 'Job']
        ] + [
            [future, job.name] for future, job in self._futures.iteritems()
        ]

        gluetool.log.log_table(self.logger.debug, label, table, headers='firstrow', tablefmt='psql')

    def _start_job(self, job):
        # type: (Job) -> None
        """
        Submit a job to the execution. Takes care of logging and calling `on_job_start` callback.

        :param Job job: job to submit.
        """

        if self.on_job_start:
            self.on_job_start(*job.args, **job.kwargs)

        assert self._executor is not None

        future = self._executor.submit(job.target, *job.args, **job.kwargs)
        self._futures[future] = job

        job.logger.debug("job '{}' scheduled".format(job.name))
        self._log_futures("job '{}' scheduled".format(job.name))

    def enqueue_jobs(self, *jobs):
        # type: (*Job) -> None
        """
        Add new jobs to the queue. If the engine is already running, jobs are immediately handed over
        to the internal executor.

        :param list(Job) jobs: jobs to execute.
        """

        for job in jobs:
            self._jobs.append(job)

            if self._executor:
                self._start_job(job)

    def run(self):
        # type: () -> None

        max_workers = self.max_workers or len(self._jobs)

        gluetool.log.log_dict(
            self.logger.debug,
            'running {} jobs with {} workers'.format(len(self._jobs), max_workers),
            self._jobs
        )

        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=self.worker_name_prefix
        )

        self.logger.debug('job executor created')

        # `on_*`` handlers can schedule new jobs. `as_completed` freezes futures its called with, therefore
        # it doesn't "see" any new futures in `self._futures`. Therefore we quit after the first future yielded
        # by `as_completed`, using it again as long as `self._futures` is not empty. So:
        #
        # - as long as there are any futures in `self._futures`, we call `_handle_finished_futures` to wait for
        # the first future to finish
        # - handlers called by `_handle_finished_futures` can schedule new futures, making `self._futures` not
        # empty - imagine last future finished but one of its handlers scheduled a new one. `_handle_finished_futures`
        # is done with handling the finished one, and is called once again because `self._futures` is no longer empty.
        # - we could wait for all futures from `self._futures` to finish, and start againg, but there's a trap,
        # Imagine futures A and B. A finishes, schedules new future C, but we're still waiting for B to complete.
        # When it does, we would start new round of `_handle_finished_futures` and only after that we would notice
        # future C.

        def _handle_finished_futures():
            # type: () -> None

            future = next(concurrent.futures.as_completed(self._futures))

            job = self._futures.pop(future)

            job.logger.debug("job '{}' finished".format(job.name))
            self._log_futures("job '{}' finished".format(job.name))

            if future.exception() is None:
                job.logger.debug("job '{}' completed".format(job.name))

                if self.on_job_complete:
                    self.on_job_complete(future.result(), *job.args, **job.kwargs)

            else:
                job.logger.debug("job '{}' crashed".format(job.name))

                exc_info = future.exception_info()

                # Exception info returned by future does not contain exception class while the info returned
                # by sys.exc_info() does and all users of it expect the first item to be exception class.
                full_exc_info = (exc_info[0].__class__, exc_info[0], exc_info[1])

                self.errors.append((job, full_exc_info))

                if self.on_job_error:
                    self.on_job_error(full_exc_info, *job.args, **job.kwargs)

            job.logger.debug("job '{}' done".format(job.name))

            if self.on_job_done:
                self.on_job_done(len(self._futures), *job.args, **job.kwargs)

        import pdb

        with self._executor:
            for job in self._jobs:
                self._start_job(job)

            # If we leave context here, the rest of our code would run after all futures finished - context would
            # block in its __exit__ on executor's state. That'd be generaly fine but we'd like to inform user about
            # our progress, and that we can do be checking futures as they complete, one by one, not waiting for the
            # last one before we start checking them. This thread *will* sleep from time to time, when there's no
            # complete future available, but that's fine. We'll get our hands on each complete one as soon as
            # possible, letting user know about the progress.

            pdb.set_trace()
            done, not_done = concurrent.futures.wait(self._futures, timeout=0)

            try:
                while not_done:
                    pdb.set_trace()
                    freshly_done, not_done = concurrent.futures.wait(not_done, timeout=5)
                    if freshly_done:
                        _handle_finished_futures()

            except KeyboardInterrupt:
                # only futures that are not done will prevent exiting
                for future in not_done:
                    # cancel() returns False if it's already done or currently running,
                    # and True if was able to cancel it; we don't need that return value
                    _ = future.cancel()
                # wait for running futures that the above for loop couldn't cancel (note timeout)
                _ = concurrent.futures.wait(not_done, timeout=None)

            # while self._futures:
            #    _handle_finished_futures()

        self.logger.debug('job executor removed')

        self._executor = None

        gluetool.log.log_dict(
            self.logger.debug,
            'jobs produced errors',
            self.errors
        )


def run_jobs(jobs,  # type: List[Job]
             logger=None,  # type: Optional[gluetool.log.ContextAdapter]
             max_workers=None,  # type: Optional[int]
             worker_name_prefix='worker',  # type: str
             on_job_start=None,  # type: Optional[Callable[..., None]]
             on_job_complete=None,  # type: Optional[Callable[..., None]]
             on_job_error=None,  # type: Optional[Callable[..., None]]
             on_job_done=None  # type: Optional[Callable[..., None]]
            ):  # noqa
    # type: (...) -> List[JobErrorType]
    """
    Run jobs in parallel.

    :param list(Job) jobs: list of jobs to run.
    :param ContextAdapter logger: logger to use global events.
    :param int max_workers: maximal number of workers running at the same time. If not set, length of the
        job list is used.
    :param str worker_name_prefix: if set, it is used as a prefix of workers' names.
    :param callable on_job_start: function to call when job is started. Called with job's arguments.
    :param callable on_job_complete: function to call when job successfully finishes. Called with the
        job's return value, followed by job's arguments.
    :param callable on_job_error: function to call when job finishes with an error. Called with the
        exception info tuple, followed by job's arguments.
    :param callable on_job_done: function to call when job finishes - called always, preceded by a call
        to ``on_job_complete`` or ``on_job_error``. Called with the number of remaining jobs, followed
        by job's arguments.
    :rtype: list(tuple(exc_info, job definition))
    :returns: errors produced by jobs. Represented as a list of tuples of two items: the exception info
        and job definition as given in ``jobs`` list.
    """

    engine = JobEngine(
        logger=logger, max_workers=max_workers, worker_name_prefix=worker_name_prefix,
        on_job_complete=on_job_complete,
        on_job_done=on_job_done,
        on_job_error=on_job_error,
        on_job_start=on_job_start
    )

    engine.enqueue_jobs(*jobs)

    engine.run()

    return engine.errors
