import bs4
import dataclasses
import os
import stat
import tempfile
import threading

import gluetool.log
from gluetool.result import Result, Ok, Error
from gluetool.log import log_xml

from . import PoolDriver, PoolCapabilities, run_cli_tool, PoolResourcesIDsType, PoolData, ProvisioningProgress
from .. import Failure
from ..db import GuestRequest, SSHKey
from ..environment import Environment

from typing import Any, Dict, Optional, List

NodeRefType = Any

DEFAULT_BEAKER_TICK = 60
DEFAULT_BEAKER_TIMEOUT = None
DEFAULT_RESERVE_DURATION = '86400'  # 24 hours


@dataclasses.dataclass
class BeakerPoolData(PoolData):
    job_id: str


class BeakerDriver(PoolDriver):
    def __init__(
        self,
        logger: gluetool.log.ContextAdapter,
        poolname: str,
        pool_config: Dict[str, Any]
    ) -> None:

        super(BeakerDriver, self).__init__(logger, poolname, pool_config)

    def _run_bkr(self, options: List[str]) -> Result[str, Failure]:
        """
        Run bkr command with additional options

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param List(str) options: options for the command
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with output, or specification of error.
        """
        if self.pool_config.get('username') and self.pool_config.get('password'):
            options.extend(['--username', self.pool_config['username'],
                            '--password', self.pool_config['password']])

        r_run = run_cli_tool(
            self.logger,
            ['bkr'] + options,
            json_output=False
        )

        if r_run.is_error:
            return Error(r_run.unwrap_error())

        output_stdout, _ = r_run.unwrap()

        return Ok(output_stdout)

    def _dispatch_resource_cleanup(
        self,
        logger: gluetool.log.ContextAdapter,
        job_id: Optional[str] = None,
        guest_request: Optional[GuestRequest] = None
    ) -> Result[None, Failure]:
        resource_ids = {}

        if job_id is not None:
            resource_ids['job_id'] = job_id

        return self.dispatch_resource_cleanup(logger, resource_ids, guest_request=guest_request)

    def release_pool_resources(
        self,
        logger: gluetool.log.ContextAdapter,
        resource_ids: PoolResourcesIDsType
    ) -> Result[None, Failure]:
        if 'job_id' in resource_ids:
            r_output = self._run_bkr(['job-cancel', resource_ids['job_id']])

            if r_output.is_error:
                return Error(r_output.unwrap_error())

        return Ok(None)

    def _create_job(self, environment: Environment) -> Result[bs4.BeautifulSoup, Failure]:
        """
        Create job xml with bkr workflow-simple and environment variables

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bs4.BeautifulSoup, Failure]
        :returns: :py:class:`result.Result` with job xml, or specification of error.
        """
        distro = None  # type: Optional[str]
        distro = environment.os.compose

        if not distro:
            return Error(Failure('No distro specified'))

        options = ['workflow-simple',
                   '--dry-run',
                   '--prettyxml',
                   '--distro', distro,
                   '--arch', environment.arch,
                   '--task', '/distribution/dummy',
                   '--reserve',
                   '--reserve-duration', DEFAULT_RESERVE_DURATION
                   ]

        r_workflow_simple = self._run_bkr(options)
        if r_workflow_simple.is_error and r_workflow_simple.error:
            return Error(r_workflow_simple.error)

        output = r_workflow_simple.unwrap()

        try:
            job_xml = bs4.BeautifulSoup(output, 'xml')
        except Exception as exc:
            return Error(Failure.from_exc('Failure during job_xml parsing', exc))

        return Ok(job_xml)

    def _submit_job(self, job: bs4.BeautifulSoup) -> Result[str, Failure]:
        """
        Submit a Beaker job.

        :param gluetool.log.ContextAdapter logger: parent logger whose methods will be used for logging.
        :param xml job: A job to submit.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        log_xml(self.logger.debug, 'job to submit', job)

        # Save the job description.
        try:
            with tempfile.NamedTemporaryFile(prefix='beaker-job-', suffix='.xml',
                                             dir=os.getcwd(), delete=False) as job_file:
                job_file.write(job.prettify(encoding='utf-8'))
                job_file.flush()

        except Exception as exc:
            return Error(Failure.from_exc('Failure during saving job description to a file', exc))

        # Temporary file has limited permissions, but we'd like to make the file inspectable.
        os.chmod(job_file.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

        r_job_submit = self._run_bkr(['job-submit', job_file.name])

        if r_job_submit.is_error and r_job_submit.error:
            return Error(r_job_submit.error)

        # Delete the job description
        try:
            os.remove(job_file.name)
        except Exception as exc:
            self.logger.warning('Cannot delete job description file: {}'.format(exc))

        output = r_job_submit.unwrap()

        if not isinstance(output, str):  # mypy needs it
            return Error(Failure('output is not str'))

        # Parse job id from output
        try:
            # Submitted: ['J:1806666']
            first_job_index = output.index('\'') + 1
            last_job_index = len(output) - output[::-1].index('\'') - 1

            # J:1806666
            job_id = output[first_job_index:last_job_index]

        except Exception as exc:
            return Error(Failure.from_exc('Cannot convert job-submit output to job ID: {}', exc))

        self.logger.info('Job submitted: {}'.format(job_id))

        return Ok(job_id)

    def _reschedule_job(self, job_id: str, environment: Environment) -> Result[str, Failure]:
        """
        Reschedule a Beaker job. Cancel the old job with `job_id`, create and
        submit a new job with `environment` specs and return new `job_id`.

        :param str job_id: Job id that will be rescheduled.
        :param Environment environment: An environment of a guest.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job id, or specification of error.
        """

        r_job_cancel = self._dispatch_resource_cleanup(self.logger, job_id=job_id)

        if r_job_cancel.is_error and r_job_cancel.error:
            return Error(r_job_cancel.error)

        r_create_job = self._create_job(environment)
        if r_create_job.is_error and r_create_job.error:
            return Error(r_create_job.error)

        job_id = r_create_job.unwrap()
        return Ok(job_id)

    def _get_job_results(self, job_id: str) -> Result[str, Failure]:
        """
        Run 'bkr job-results' comand and return job results.

        :param str job_id: Job id that will be rescheduled.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job results, or specification of error.
        """
        options = ['job-results', job_id]

        r_job_results = self._run_bkr(options)
        if r_job_results.is_error and r_job_results.error:
            return Error(r_job_results.error)

        return r_job_results

    def _parse_job_status(self, job_results: bs4.BeautifulSoup) -> Result[str, Failure]:
        """
        Parse job results and return job status

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with job status, or specification of error.
        """
        if not job_results.find('job') or len(job_results.find_all('job')) != 1:
            Error(Failure('Job results returned not known structure'))

        if not job_results.find('job')['result']:
            return Error(Failure('Job result xml does not contain result attribute'))

        return Ok(job_results.find('job')['result'])

    def _parse_guest_address(self, job_results: bs4.BeautifulSoup) -> Result[str, Failure]:
        """
        Parse job results and return guest address

        :param bs4.BeautifulSoup job_results: Job results in xml format.
        :rtype: result.Result[str, Failure]
        :returns: :py:class:`result.Result` with guest address, or specification of error.
        """
        if not job_results.find('recipe')['system']:
            return Error(Failure('System was not found in job results'))

        return Ok(job_results.find('recipe')['system'])

    def update_guest(self,
                     logger: gluetool.log.ContextAdapter,
                     guest_request: GuestRequest,
                     environment: Environment,
                     master_key: SSHKey,
                     cancelled: Optional[threading.Event] = None) -> Result[ProvisioningProgress, Failure]:
        """
        Called for unifinished guest. What ``acquire_guest`` started, this method can complete. By returning a guest
        with an address set, driver signals the provisioning is now complete. Returning a guest instance without an
        address would schedule yet another call to this method in the future.

        :param BeakerGuest guest: Guest that will be updated.
        :param threading.Event cancelled: if set, method should cancel its operation, release resources, and return.
        :rtype: Result[BeakerGuest, Failure]
        :returns: :py:class:`result.Result` with guest, or specification of error.
        """

        r_get_job_results = self._get_job_results(BeakerPoolData.unserialize(guest_request).job_id)
        if r_get_job_results.is_error and r_get_job_results.error:
            return Error(r_get_job_results.error)

        job_results = r_get_job_results.unwrap()

        # parse xml
        job_results_xml = bs4.BeautifulSoup(job_results, 'xml')

        r_parse_job_status = self._parse_job_status(job_results_xml)
        if r_parse_job_status.is_error and r_parse_job_status.error:
            return Error(r_parse_job_status.error)

        job_status = r_parse_job_status.unwrap()

        logger.info('current job status {}:{}'.format(
            BeakerPoolData.unserialize(guest_request).job_id,
            job_status
        ))

        if job_status == 'Pass':
            r_parse_guest_address = self._parse_guest_address(job_results_xml)
            if r_parse_guest_address.is_error and r_parse_guest_address.error:
                return Error(r_parse_guest_address.error)

            return Ok(ProvisioningProgress(
                is_acquired=True,
                pool_data=BeakerPoolData.unserialize(guest_request),
                address=r_parse_guest_address.unwrap()
            ))

        if job_status == 'New':
            return Ok(ProvisioningProgress(
                is_acquired=False,
                pool_data=BeakerPoolData.unserialize(guest_request)
            ))

        if job_status == 'Fail':
            r_reschedule_job = self._reschedule_job(BeakerPoolData.unserialize(guest_request).job_id, environment)
            if r_reschedule_job.is_error and r_reschedule_job.error:
                return Error(r_reschedule_job.error)

            return Ok(ProvisioningProgress(
                is_acquired=False,
                pool_data=BeakerPoolData(job_id=r_reschedule_job.unwrap())
            ))

        return Error(Failure('Unknown status'))

    def can_acquire(self, environment: Environment) -> Result[bool, Failure]:
        """
        Find our whether this driver can provision a guest that would satisfy
        the given environment.

        :param Environment environment: environmental requirements a guest must satisfy.
        :rtype: result.Result[bool, Failure]
        :returns: Ok with True if guest can be acquired.
        """
        if environment.arch not in self.pool_config['available-arches']:
            return Ok(False)

        return Ok(True)

    def acquire_guest(
        self,
        logger: gluetool.log.ContextAdapter,
        guest_request: GuestRequest,
        environment: Environment,
        master_key: SSHKey,
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
        r_create_job = self._create_job(environment)
        if r_create_job.is_error:
            return Error(r_create_job.value)
        job = r_create_job.unwrap()

        # Run submit beaker job
        r_submit_job = self._submit_job(job)
        if r_submit_job.is_error and r_submit_job.error:
            return Error(r_submit_job.error)
        job_id = r_submit_job.unwrap()

        # The returned guest doesn't have address. The address will be added by executing `update_guest()`
        # after. The reason of this solution is slow beaker system provisioning. It can take hours and
        # we can't use a thread for so large amount of time.

        return Ok(ProvisioningProgress(
            is_acquired=False,
            pool_data=BeakerPoolData(job_id=job_id)
        ))

    def release_guest(self, logger: gluetool.log.ContextAdapter, guest_request: GuestRequest) -> Result[bool, Failure]:
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

        if r_job_cancel.is_error and r_job_cancel.error:
            return Error(r_job_cancel.error)

        return Ok(True)

    def capabilities(self) -> Result[PoolCapabilities, Failure]:
        result = super(BeakerDriver, self).capabilities()

        if result.is_error:
            return result

        capabilities = result.unwrap()
        capabilities.supports_snapshots = True

        return Ok(capabilities)
