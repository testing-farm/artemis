import dataclasses
import os
import stat
import threading
from typing import Any, List, Optional

import bs4
import gluetool.log
import gluetool.utils
import sqlalchemy.orm.session
from gluetool.log import log_xml
from gluetool.result import Error, Ok, Result

from .. import Failure, Knob
from ..db import GuestRequest
from ..environment import Environment
from ..metrics import PoolResourcesMetrics
from ..script import hook_engine
from . import CLIOutput, PoolData, PoolDriver, PoolImageInfo, PoolResourcesIDs, ProvisioningProgress, \
    ProvisioningState, SerializedPoolResourcesIDs, create_tempfile, run_cli_tool

NodeRefType = Any


#: A time, in seconds, for which the guest would be initially reserved.
KNOB_RESERVATION_DURATION: Knob[int] = Knob(
    'beaker.reservation.duration',
    has_db=False,
    envvar='ARTEMIS_BEAKER_RESERVATION_DURATION',
    envvar_cast=int,
    default=86400
)

#: A delay, in seconds, between two calls of `update-guest-request` checking provisioning progress.
KNOB_UPDATE_TICK: Knob[int] = Knob(
    'beaker.update.tick',
    has_db=False,
    envvar='ARTEMIS_BEAKER_UPDATE_TICK',
    envvar_cast=int,
    default=300
)


@dataclasses.dataclass
class BeakerPoolData(PoolData):
    job_id: str


@dataclasses.dataclass
class BeakerPoolResourcesIDs(PoolResourcesIDs):
    job_id: Optional[str] = None


class BeakerDriver(PoolDriver):
    def _run_bkr(
        self,
        logger: gluetool.log.ContextAdapter,
        options: List[str]
    ) -> Result[CLIOutput, Failure]:
        """
        Run bkr command with additional options

        :param gluetool.log.ContextAdapter logger: logger to use for logging.
        :param List(str) options: options for the command
        :returns: either a valid result, :py:class:`CLIOutput` instance, or an error with a :py:class:`Failure`
            describing the problem.
        """

        if self.pool_config.get('username') and self.pool_config.get('password'):
            options.extend([
                '--username', self.pool_config['username'],
                '--password', self.pool_config['password']
            ])

        r_run = run_cli_tool(
            logger,
            ['bkr'] + options,
            json_output=False
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        return Ok(r_run.unwrap())

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = BeakerPoolResourcesIDs(job_id=job_id)

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        raw_resource_ids: SerializedPoolResourcesIDs
    ) -> Result[None, Failure]:
        resource_ids = BeakerPoolResourcesIDs.unserialize(raw_resource_ids)

        if resource_ids.job_id is not None:
            r_output = self._run_bkr(logger, ['job-cancel', resource_ids.job_id])

            if r_output.is_error:
                return Error(r_output.unwrap_error())

        return Ok(None)

    def map_image_name_to_image_info(
        self,
        logger: gluetool.log.ContextAdapter,
        imagename: str
    ) -> Result[PoolImageInfo, Failure]:
        # TODO: is it true that `name` is equal to `id` in Beaker? Is really each `name` we get from
        # the `compose` => `image name` mapping really the same as "ID" of the distro? I believe this
        # is indeed correct, but needs checking.
        #
        # The thing is: this could be true even for OpenStack and AWS, if user would use `compose` => `image ID` map.
        # We want the right-hand side to be human-readable and easy to follow, therefore OpenStack and AWS have this
        # extra level of dereference.

        return Ok(PoolImageInfo(
            name=imagename,
            id=imagename
        ))

    def _environment_to_image(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[PoolImageInfo, Failure]:
        r_engine = hook_engine('BEAKER_ENVIRONMENT_TO_IMAGE')

        if r_engine.is_error:
            return Error(r_engine.unwrap_error())

        engine = r_engine.unwrap()

        r_image: Result[PoolImageInfo, Failure] = engine.run_hook(
            'BEAKER_ENVIRONMENT_TO_IMAGE',
            logger=logger,
            pool=self,
            environment=environment
        )

        if r_image.is_error:
            failure = r_image.unwrap_error()
            failure.update(environment=environment)

            return Error(failure)

        return r_image

    def _create_job_xml(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Create job xml with bkr workflow-simple and environment variables

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bs4.BeautifulSoup, Failure]
        :returns: :py:class:`result.Result` with job xml, or specification of error.
        """

        r_distro = self._environment_to_image(logger, environment)

        if r_distro.is_error:
            return Error(r_distro.unwrap_error())

        distro = r_distro.unwrap()

        options = [
            'workflow-simple',
            '--dry-run',
            '--prettyxml',
            '--distro', distro.id,
            '--arch', environment.hw.arch,
            '--task', '/distribution/dummy',
            '--reserve',
            '--reserve-duration', str(KNOB_RESERVATION_DURATION.value)
        ]

        r_workflow_simple = self._run_bkr(logger, options)
        if r_workflow_simple.is_error:
            return Error(r_workflow_simple.unwrap_error())

        bkr_output = r_workflow_simple.unwrap()

        try:
            return Ok(bs4.BeautifulSoup(bkr_output.stdout, 'xml'))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse job XML',
                exc,
                command_output=bkr_output.process_output
            ))

    def _submit_job(
        self,
        logger: gluetool.log.ContextAdapter,
        job: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Submit a Beaker job.

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param xml job: A job to submit.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        log_xml(self.logger.debug, 'job to submit', job)

        with create_tempfile(
            file_contents=job.prettify(),
            prefix='beaker-job-',
            suffix='.xml'
        ) as job_filepath:
            # Temporary file has limited permissions, but we'd like to make the file inspectable.
            os.chmod(job_filepath, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

            r_job_submit = self._run_bkr(logger, ['job-submit', job_filepath])

        if r_job_submit.is_error:
            return Error(r_job_submit.unwrap_error())

        bkr_output = r_job_submit.unwrap()

        # Parse job id from output
        try:
            # Submitted: ['J:1806666']
            first_job_index = bkr_output.stdout.index('\'') + 1
            last_job_index = len(bkr_output.stdout) - bkr_output.stdout[::-1].index('\'') - 1

            # J:1806666
            job_id = bkr_output.stdout[first_job_index:last_job_index]

        except Exception as exc:
            return Error(Failure.from_exc(
                'cannot convert job-submit output to job ID',
                exc,
                command_output=bkr_output.process_output
            ))

        logger.info(f'Job submitted: {job_id}')

        return Ok(job_id)

    def _create_job(
        self,
        logger: gluetool.log.ContextAdapter,
        environment: Environment
    ) -> Result[str, Failure]:
        r_job_xml = self._create_job_xml(
            logger,
            environment
        )

        if r_job_xml.is_error:
            return Error(r_job_xml.unwrap_error())

        return self._submit_job(logger, r_job_xml.unwrap())

    def _reschedule_job(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: str,
        environment: Environment
    ) -> Result[str, Failure]:
        """
        Reschedule a Beaker job. Cancel the old job with `job_id`, create and
        submit a new job with `environment` specs and return new `job_id`.

        :param str job_id: Job id that will be rescheduled.
        :param Environment environment: An environment of a guest.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        r_job_cancel = self._dispatch_resource_cleanup(self.logger, job_id=job_id)

        if r_job_cancel.is_error:
            return Error(r_job_cancel.unwrap_error())

        return self._create_job(logger, environment)

    def _get_job_results(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: str
    ) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Run 'bkr job-results' comand and return job results.

        :param str job_id: Job id that will be rescheduled.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job results, or specification of error.
        """

        r_results = self._run_bkr(logger, ['job-results', job_id])

        if r_results.is_error:
            return Error(r_results.unwrap_error())

        bkr_output = r_results.unwrap()

        try:
            return Ok(bs4.BeautifulSoup(bkr_output.stdout, 'xml'))

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to parse job results XML',
                exc,
                command_output=bkr_output.process_output
            ))

    def _parse_job_status(
        self,
        logger: gluetool.log.ContextAdapter,
        job_results: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Parse job results and return job status

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job status, or specification of error.
        """

        if not job_results.find('job') or len(job_results.find_all('job')) != 1:
            return Error(Failure(
                'job results XML has unknown structure',
                job_results=job_results.prettify()
            ))

        if not job_results.find('job')['result']:
            return Error(Failure(
                'job results XML does not contain result attribute',
                job_results=job_results.prettify()
            ))

        return Ok(job_results.find('job')['result'])

    def _parse_guest_address(
        self,
        logger: gluetool.log.ContextAdapter,
        job_results: bs4.BeautifulSoup
    ) -> Result[str, Failure]:
        """
        Parse job results and return guest address

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with guest address, or specification of error.
        """

        if not job_results.find('recipe')['system']:
            return Error(Failure(
                'System element was not found in job results',
                job_results=job_results.prettify()
            ))

        return Ok(job_results.find('recipe')['system'])

    def update_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.

        :param BeakerGuest guest: Guest that will be updated.
        :param threading.Event cancelled: if set, method should cancel its operation, release resources, and return.
        :rtype: Result[BeakerGuest, Failure]
        :returns: :py:class:`result.Result` with guest, or specification of error.
        """

        r_job_results = self._get_job_results(logger, BeakerPoolData.unserialize(guest_request).job_id)

        if r_job_results.is_error:
            return Error(r_job_results.unwrap_error())

        job_results = r_job_results.unwrap()

        r_job_status = self._parse_job_status(logger, job_results)

        if r_job_status.is_error:
            return Error(r_job_status.unwrap_error())

        job_status = r_job_status.unwrap()

        logger.info(f'current job status {BeakerPoolData.unserialize(guest_request).job_id}:{job_status}')

        if job_status.lower() == 'pass':
            r_guest_address = self._parse_guest_address(logger, job_results)

            if r_guest_address.is_error:
                return Error(r_guest_address.unwrap_error())

            return Ok(ProvisioningProgress(
                state=ProvisioningState.COMPLETE,
                pool_data=BeakerPoolData.unserialize(guest_request),
                address=r_guest_address.unwrap()
            ))

        if job_status.lower() == 'new':
            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=BeakerPoolData.unserialize(guest_request),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        if job_status.lower() == 'fail':
            r_reschedule_job = self._reschedule_job(
                logger,
                BeakerPoolData.unserialize(guest_request).job_id,
                Environment.unserialize_from_str(guest_request.environment)
            )

            if r_reschedule_job.is_error:
                return Error(r_reschedule_job.unwrap_error())

            return Ok(ProvisioningProgress(
                state=ProvisioningState.PENDING,
                pool_data=BeakerPoolData(job_id=r_reschedule_job.unwrap()),
                delay_update=KNOB_UPDATE_TICK.value
            ))

        return Error(Failure(
            'unknown status',
            job_status=job_status,
            job_results=job_results.prettify()
        ))

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.

        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bool, Failure]
        :returns: Ok with True if guest can be acquired.
        """

        return super(BeakerDriver, self).can_acquire(environment)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        guest_request: GuestRequest,
        cancelled: Optional[threading.Event] = None
    ) -> Result[ProvisioningProgress, Failure]:
        """
        Acquire one guest from the pool. The guest must satisfy requirements specified
        by `environment`.

        :param Environment environment: environmental requirements a guest must satisfy.
        :param Key master_key: master key to upload to the guest.
        :param threading.Event cancelled: if set, method should cancel its operation, release
            resources, and return.
        :rtype: result.Result[Guest, str]
        :returns: :py:class:`result.Result` with either :py:class:`Guest` instance, or specification
            of error.
        """

        r_create_job = self._create_job(logger, Environment.unserialize_from_str(guest_request.environment))

        if r_create_job.is_error:
            return Error(r_create_job.unwrap_error())

        # The returned guest doesn't have address. The address will be added by executing `update_guest()`
        # after. The reason of this solution is slow beaker system provisioning. It can take hours and
        # we can't use a thread for so large amount of time.

        return Ok(ProvisioningProgress(
            state=ProvisioningState.PENDING,
            pool_data=BeakerPoolData(job_id=r_create_job.unwrap()),
            delay_update=KNOB_UPDATE_TICK.value
        ))

    def release_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest
    ) -> Result[bool, Failure]:
        """
        Release guest and its resources back to the pool.

        :param Guest guest: a guest to be destroyed.
        :rtype: result.Result[bool, str]
        """

        r_job_cancel = self._dispatch_resource_cleanup(
            logger,
            job_id=BeakerPoolData.unserialize(guest_request).job_id,
            guest_request=guest_request
        )

        if r_job_cancel.is_error:
            return Error(r_job_cancel.unwrap_error())

        return Ok(True)

    def fetch_pool_resources_metrics(
        self,
        logger: gluetool.log.ContextAdapter
    ) -> Result[PoolResourcesMetrics, Failure]:
        r_resources = super(BeakerDriver, self).fetch_pool_resources_metrics(logger)

        if r_resources.is_error:
            return Error(r_resources.unwrap_error())

        resources = r_resources.unwrap()

        r_query_instances = self._run_bkr(
            logger,
            ['system-list', '--mine']
        )

        if r_query_instances.is_error:
            failure = r_query_instances.unwrap_error()
            command_output = failure.details.get('command_output', None)

            if command_output and command_output.stderr \
               and command_output.stderr.decode('utf-8').strip().lower() == 'nothing matches':
                # This is a a valid result, meaning "0 machines". Setting our "raw output" to a corresponding value
                # instead of adding some special flag. Empty string has 0 lines, 0 machines...
                raw_machines = ''

            else:
                return Error(failure)

        else:
            raw_machines = r_query_instances.unwrap().stdout

        if raw_machines:
            resources.usage.instances = len(raw_machines.splitlines())

        else:
            # Not an error, just an empty list which means, hm, 0 instances.
            resources.usage.instances = 0

        # For the actual numbers of cores, memory and other metrics, we'd have to query each and every machine from
        # the list above. Is it worth it? At this moment it's not. But it can be done. Leaving them unspecified for
        # now.

        return Ok(resources)
