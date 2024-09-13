# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Re-install the guest OS using the provided custom kickstart script.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import configparser
import functools
import glob
import os
import threading
from tempfile import TemporaryDirectory
from typing import Any, Callable, Dict, List, TypeVar, cast

import gluetool.log
import jinja2
import jinja2.filters
import sqlalchemy.orm.session

from .. import Failure
from ..db import DB
from ..drivers import copy_from_remote, copy_to_remote, create_tempfile, run_cli_tool, run_remote
from ..guest import GuestState
from ..knobs import Knob
from . import _ROOT_LOGGER, DoerReturnType, DoerType, ProvisioningTailHandler
from . import Workspace as _Workspace
from . import get_guest_logger, step, task, task_core

TASK_NAME = 'prepare-kickstart'

KS_DST = '/tmp/kickstart.ks'
KS_TPL = 'files/kickstart.ks.j2'
SCRIPT_DST = '/tmp/do-kexec.sh'
SCRIPT_SRC = 'files/do-kexec.sh'

REPOS_GLOB = 'etc/yum.repos.d/*'

FILES_TO_FETCH = [
    '/' + REPOS_GLOB,
    '/etc/cloud/cloud.cfg',
    '/root/.ssh/*'
]

KNOB_PREPARE_KICKSTART_SSH_TIMEOUT: Knob[int] = Knob(
    'actor.kickstart.ssh-timeout',
    'Kickstart installation SSH connection timeout.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_KICKSTART_SSH_TIMEOUT',
    cast_from_str=int,
    default=15
)

WorkspaceBound = TypeVar('WorkspaceBound', bound='Workspace')


def kickstart_step(
    fn: Callable[[WorkspaceBound], None]
) -> Callable[[WorkspaceBound], WorkspaceBound]:
    """
    Wrap a task step to be able to bypass already performed steps in case the task was already executed.

    :param fn: The wrapped function.
    """

    @functools.wraps(fn)
    def wrapper(workspace: WorkspaceBound) -> WorkspaceBound:
        """
        Wrapper for the decorated function.

        :param workspace: workspace used with the decorated function.
        """

        if workspace.finished:
            return workspace

        return step(fn)(workspace)

    return wrapper


class Workspace(_Workspace):
    """
    Workspace for executing kickstart using kexec.
    """

    finished: bool = False
    repos: Dict[str, Dict[str, str]]
    packages: List[str]
    files: Dict[str, str]
    files_tmp_dir: TemporaryDirectory[Any]
    ssh_timeout: int

    def _begin(self) -> None:
        """
        Begin by loading the guest request.
        """

        assert self.guestname

        super()._begin()

        self.load_guest_request(self.guestname, state=GuestState.PREPARING)
        self.load_gr_pool()
        self.load_master_ssh_key()

    @step
    def load_ssh_timeout(self) -> None:
        """
        Load the SSH timeout value.
        """

        assert self.pool

        r = KNOB_PREPARE_KICKSTART_SSH_TIMEOUT.get_value(session=self.session, entityname=self.pool.poolname)

        if r.is_error:
            return self._error(r, 'failed to obtain SSH timeout value')

        self.ssh_timeout = r.unwrap()

    @step
    def check_if_ran(self) -> None:
        """
        Check if the guest had the ks script executed already.
        """

        assert self.gr
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        # Check whether ks installation had already been performed
        r = run_remote(
            self.logger,
            self.gr,
            ['/bin/ls', '/.ksinstall'],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart.check-if-ran'
        )

        if not r.is_error:
            # If the command succeeded, the file exists on the remote host and
            # installation must have already finished.
            # TODO: Verify *why* the command failed.
            self._event('already-reinstalled')
            self.finished = True
            return

    @kickstart_step
    def fetch_files(self) -> None:
        """
        Fetch preserved files from the guest.
        """

        assert self.gr
        assert self.master_key
        assert self.pool
        assert self.ssh_timeout

        self.files_tmp_dir = TemporaryDirectory()

        for pattern in FILES_TO_FETCH:
            dst_dir = os.path.join(self.files_tmp_dir.name, os.path.dirname(os.path.relpath(pattern, '/')))

            try:
                os.makedirs(dst_dir, mode=0o700, exist_ok=True)
            except Exception as exc:
                return self._fail(Failure.from_exc(
                    'failed to create a local destination directory',
                    exc
                ), 'failed to create a local destination directory')
                return

            r_copy = copy_from_remote(
                self.logger,
                self.gr,
                pattern,
                os.path.join(self.files_tmp_dir.name, os.path.dirname(os.path.relpath(pattern, '/'))),
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=self.ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.fetch-files'
            )

            if r_copy.is_error:
                # We can continue, just log the error
                # TODO: Should we error out? Probably as it may not be just non-existent file
                return self._error(r_copy, 'failed to fetch a file from remote')

        self.files = {}

        for root, _, files in os.walk(self.files_tmp_dir.name):
            for file in files:
                file_path = os.path.join(root, file)

                # Fix permissions for reading
                os.chmod(file_path, 0o644)

                with open(file_path) as f:
                    self.files[os.path.relpath(file_path, self.files_tmp_dir.name)] = f.read()

    @kickstart_step
    def parse_enabled_repos(self) -> None:
        """
        Parse yum repos and select enabled ones for the installer.
        """

        assert self.files_tmp_dir

        # TODO: Is there a way to disable configparser's DEFAULT section altogether?
        try:
            _repos = configparser.ConfigParser()
            _repos.read(glob.glob(os.path.abspath(os.path.join(self.files_tmp_dir.name, REPOS_GLOB))))

            self.repos = {
                name: dict(vals) for name, vals in _repos.items()
                if name != 'DEFAULT' and vals['enabled'] == '1'
            }
        except Exception as exc:
            r = Failure.from_exc(
                'failed to parse enabled repos',
                exc
            )

            return self._fail(r, 'failed to parse enabled repos')

    @kickstart_step
    def get_installed_pkgs(self) -> None:
        """
        Get list of installed packages and package groups.
        """

        assert self.gr
        assert self.master_key
        assert self.pool

        # The installation will fail if any package was installed from a disabled
        # repo or a local .rpm file
        r_kexec = run_remote(
            self.logger,
            self.gr,
            ['/usr/bin/rpm', '-qa', '--queryformat', '%{NAME}.%{ARCH}\n'],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart.installed-pkgs'
        )

        if r_kexec.is_error:
            return self._error(r_kexec, 'failed to fetch the list of installed packages')

        self.packages = r_kexec.unwrap().stdout.split()

    @kickstart_step
    def generate_kickstart(self) -> None:
        """
        Generate kickstart configuration for the Anaconda installer.
        """

        assert self.gr
        assert self.pool
        assert self.master_key
        assert self.ssh_timeout
        assert self.repos is not None
        assert self.packages is not None
        assert self.files is not None

        # Template kickstart
        loader = jinja2.FileSystemLoader(os.path.dirname(os.path.abspath(__file__)))
        env = jinja2.Environment(loader=loader)
        tpl = env.get_template(KS_TPL)
        kickstart = tpl.render(
            install_tree=self.repos['rhel-BaseOS']['baseurl'],
            repos=self.repos,
            packages=self.packages,
            files=self.files,
            script=self.gr.environment.kickstart.script,
            pre_install=self.gr.environment.kickstart.pre_install,
            post_install=self.gr.environment.kickstart.post_install
        )
        # TODO: Consider not using global delimiters to enable unchanged tpls
        # to work even when a custom delims are set
        # r_kickstart = render_template(
        #     os.path.join(os.path.dirname(os.path.abspath(__file__)), KS_TPL),
        #     repos=self.repos,
        #     packages=self.packages,
        #     files={}
        # )

        # if r_kickstart.is_error:
        #     return self._error(r_kickstart, 'Failed to prepare kickstart file')
        #     return

        # Copy to guest
        # with create_tempfile(file_contents=r_kickstart.unwrap()) as kickstart_filepath:
        with create_tempfile(file_contents=kickstart) as kickstart_filepath:
            # Validate the generated ks
            # TODO: Validate against concrete kickstart version? (ksvalidator -v VERSION ...)
            r_validator = run_cli_tool(
                self.logger,
                ['ksvalidator', kickstart_filepath],
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.validate-kickstart'
            )

            if r_validator.is_error:
                # Maybe turn into warning for now?
                return self._error(r_validator, 'rendered kickstart validation failed')

            r_upload = copy_to_remote(
                self.logger,
                self.gr,
                kickstart_filepath,
                KS_DST,
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=self.ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.copy-script'
            )

            if r_upload.is_error:
                return self._error(r_upload, 'failed to copy the kickstart install initiation script')

        self.logger.debug('copied rendered kickstart template to the guest')

    @kickstart_step
    def copy_files(self) -> None:
        """
        Copy files required to initiate the kickstart installation.
        """

        assert self.gr
        assert self.pool
        assert self.master_key

        r_upload = copy_to_remote(
            self.logger,
            self.gr,
            os.path.join(os.path.dirname(os.path.abspath(__file__)), SCRIPT_SRC),
            SCRIPT_DST,
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart.copy-script'
        )

        if r_upload.is_error:
            return self._error(r_upload, 'failed to copy the kickstart install initiation script')

        self.logger.debug('copied installer initiation script to the guest')

    @kickstart_step
    def kexec(self) -> None:
        """
        Fetch images and boot the netinstall using kexec.
        """

        assert self.gr
        assert self.pool
        assert self.master_key

        r_kexec = run_remote(
            self.logger,
            self.gr,
            [
                '/bin/bash',
                self.repos['rhel-BaseOS']['baseurl'],
                KS_DST,
                self.gr.environment.kickstart.kernel_options or ''
            ],
            key=self.master_key,
            ssh_options=self.pool.ssh_options,
            ssh_timeout=self.ssh_timeout,
            poolname=self.pool.poolname,
            commandname='prepare-kickstart.kexec'
        )

        if r_kexec.is_error:
            return self._error(r_kexec, 'failed to run the installer')

        self.logger.debug('successfuly executed the installer')

    @step
    def dispatch_followup(self) -> None:
        """
        Schedule followup.
        """

        assert self.guestname

        from .prepare_finalize_pre_connect import prepare_finalize_pre_connect

        # TODO: We might want to wait for the setup to complete and verify SSH connection again
        # TODO: Parametrize the delay (Right now we will wait 5 mins, which may or may not be enough)

        self.request_task(
            prepare_finalize_pre_connect,
            self.guestname,
            delay=60 * 5
        )

    def run(self) -> 'Workspace':
        """
        Run task steps within a single transaction.
        """

        with self.transaction():
            return self.load_ssh_timeout() \
                .check_if_ran() \
                .fetch_files() \
                .parse_enabled_repos() \
                .get_installed_pkgs() \
                .generate_kickstart() \
                .copy_files() \
                .kexec() \
                .dispatch_followup()

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        return cls(logger, session, cancel, db=db, guestname=guestname, task=TASK_NAME)

    @classmethod
    def prepare_kickstart(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        cancel: threading.Event,
        guestname: str
    ) -> DoerReturnType:
        """
        Perform a kickstart installation.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param cancel: when set, task is expected to cancel its work and undo changes it performed.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, cancel, guestname) \
            .begin() \
            .run() \
            .complete() \
            .final_result


@task(tail_handler=ProvisioningTailHandler(GuestState.PREPARING, GuestState.ERROR))
def prepare_kickstart(guestname: str) -> None:
    """
    Re-install the guest using provided kickstart.

    :param guestname: name of the request to process.
    """

    task_core(
        cast(DoerType, Workspace.prepare_kickstart),
        logger=get_guest_logger(TASK_NAME, _ROOT_LOGGER, guestname),
        doer_args=(guestname,)
    )
