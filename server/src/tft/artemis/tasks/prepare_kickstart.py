# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Re-install the guest OS using the provided custom kickstart script.

.. note::

   Task MUST be aware of the possibility of another task performing the same job at the same time. All changes
   MUST preserve consistent and restartable state.
"""

import configparser
import glob
import os
from tempfile import TemporaryDirectory
from typing import cast

import gluetool.log
import sqlalchemy.orm.session

from .. import Failure, render_template
from ..db import DB, GuestLog, GuestLogContentType, GuestLogState, SafeQuery
from ..drivers import (
    GuestLogBlob,
    copy_from_remote,
    copy_to_remote,
    create_tempfile,
    run_cli_tool,
    run_remote,
)
from ..drivers.hooks import KNOB_CACHE_PATTERN_MAPS, get_pattern_map
from ..guest import GuestState
from ..knobs import KNOB_CONFIG_DIRPATH, Knob
from . import (
    _ROOT_LOGGER,
    DoerReturnType,
    DoerType,
    ProvisioningTailHandler,
    Workspace as _Workspace,
    get_guest_logger,
    step,
    task,
    task_core,
)

TASK_NAME = 'prepare-kickstart'

KS_DST = '/tmp/kickstart.ks'
SCRIPT_DST = '/tmp/do-kexec.sh'

REPOS_GLOB = 'etc/yum.repos.d/*'

FILES_TO_FETCH = [
    '/' + REPOS_GLOB,
    '/etc/cloud/cloud.cfg',
    '/root/.ssh/*'
]

KS_LOGNAME = 'ks.cfg:dump'

KNOB_PREPARE_KICKSTART_SSH_TIMEOUT: Knob[int] = Knob(
    'actor.kickstart.ssh-timeout',
    'Kickstart installation SSH connection timeout.',
    per_entity=True,
    has_db=True,
    envvar='ARTEMIS_PREPARE_KICKSTART_SSH_TIMEOUT',
    cast_from_str=int,
    default=15
)

KNOB_PREPARE_KICKSTART_COMPOSE_REPO_MAPPING_FILEPATH: Knob[str] = Knob(
    'actor.kickstart.compose-repo-mapping',
    'Map of compose names to source repo name for installation.',
    per_entity=False,
    has_db=False,
    envvar='ARTEMIS_PREPARE_KICKSTART_COMPOSE_REPO_MAPPING_FILEPATH',
    cast_from_str=str,
    default='artemis-kickstart-compose-repo-map.yaml'
)

KNOB_PREPARE_KICKSTART_TEMPLATE_FILEPATH: Knob[str] = Knob(
    'actor.kickstart.template',
    'Kickstart config template path.',
    per_entity=False,
    has_db=False,
    envvar='ARTEMIS_PREPARE_KICKSTART_TEMPLATE_FILEPATH',
    cast_from_str=str,
    default='artemis-kickstart.ks.j2'
)

KNOB_PREPARE_KICKSTART_BOOT_INSTALLER_SCRIPT_FILEPATH: Knob[str] = Knob(
    'actor.kickstart.boot-installer-script-filepath',
    'Script to prepare and boot the installer image.',
    per_entity=False,
    has_db=False,
    envvar='ARTEMIS_PREPARE_KICKSTART_BOOT_INSTALLER_SCRIPT_FILEPATH',
    cast_from_str=str,
    default='artemis-kickstart-kexec.sh'
)


class Workspace(_Workspace):
    """
    Workspace for executing kickstart using kexec.
    """

    @step
    def run(self, ks_dst: str = KS_DST, script_dst: str = SCRIPT_DST) -> None:
        """
        Execute the task in a transaction.
        """

        from .prepare_kickstart_wait import KNOB_PREPARE_KICKSTART_WAIT_INITIAL_DELAY, prepare_kickstart_wait

        assert self.guestname

        with self.transaction():
            # Load GR and associated info
            self.load_guest_request(self.guestname, state=GuestState.PREPARING)
            self.load_gr_pool()
            self.load_master_ssh_key()

            if self.result:
                return

            assert self.gr
            assert self.pool
            assert self.master_key

            # Load the SSH timeout value
            r_ssh_timeout = KNOB_PREPARE_KICKSTART_SSH_TIMEOUT.get_value(
                session=self.session,
                entityname=self.pool.poolname
            )

            if r_ssh_timeout.is_error:
                return self._error(r_ssh_timeout, 'failed to obtain SSH timeout value')

            ssh_timeout = r_ssh_timeout.unwrap()

            # Check whether ks installation had already been performed
            r_check = run_remote(
                self.logger,
                self.gr,
                ['/bin/ls', '/.ksinstall'],
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.check-if-ran'
            )

            if r_check.is_ok:
                # If the command succeeded, the file exists on the remote host and
                # installation must have already finished.
                return self._guest_request_event('already-reinstalled')

            # Verify the error is due to the file missing, which indicates the installer had not run yet
            failure = r_check.unwrap_error()
            stderr = failure.details['command_output'].stderr if 'command_output' in failure.details else None

            if stderr is not None and 'cannot access \'/.ksinstall\': No such file or directory' not in stderr:
                return self._fail(failure, 'could not verify whether kickstart installation was already started')

            # Fetch preserved files from the guest
            files_tmp_dir = TemporaryDirectory()
            for pattern in FILES_TO_FETCH:
                dst_dir = os.path.join(files_tmp_dir.name, os.path.dirname(os.path.relpath(pattern, '/')))

                try:
                    os.makedirs(dst_dir, mode=0o700, exist_ok=True)
                except Exception as exc:
                    return self._fail(Failure.from_exc(
                        'failed to create a local destination directory',
                        exc
                    ), 'failed to create a local destination directory')

                r_copy = copy_from_remote(
                    self.logger,
                    self.gr,
                    pattern,
                    os.path.join(files_tmp_dir.name, os.path.dirname(os.path.relpath(pattern, '/'))),
                    key=self.master_key,
                    ssh_options=self.pool.ssh_options,
                    ssh_timeout=ssh_timeout,
                    poolname=self.pool.poolname,
                    commandname='prepare-kickstart.fetch-files'
                )

                if r_copy.is_error:
                    # Error out if we fail to copy the file
                    # TODO: Should we error out or continue if the file is missing?
                    return self._error(r_copy, 'failed to fetch a file from remote')

            files = {}

            for root, _, local_files in os.walk(files_tmp_dir.name):
                for file in local_files:
                    file_path = os.path.join(root, file)

                    # Fix permissions for reading
                    os.chmod(file_path, 0o644)

                    with open(file_path) as f:
                        files[os.path.relpath(file_path, files_tmp_dir.name)] = f.read()

            # Parse enabled yum repos and select enabled ones for the installer
            # TODO: Is there a way to disable configparser's DEFAULT section altogether?
            try:
                _repos = configparser.ConfigParser()
                _repos.read(glob.glob(os.path.abspath(os.path.join(files_tmp_dir.name, REPOS_GLOB))))

                repos = {
                    name: dict(vals) for name, vals in _repos.items()
                    if name != 'DEFAULT' and vals['enabled'] == '1'
                }
            except Exception as exc:
                return self._fail(
                    Failure.from_exc('failed to parse enabled repos', exc),
                    'failed to parse enabled repos'
                )

            # Fetch the list of installed packages
            r_pkg_list = run_remote(
                self.logger,
                self.gr,
                ['/usr/bin/rpm', '-qa', '--queryformat', '%{NAME}.%{ARCH}\n'],  # noqa: FS003
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.installed-pkgs'
            )

            if r_pkg_list.is_error:
                return self._error(r_pkg_list, 'failed to fetch the list of installed packages')

            packages = r_pkg_list.unwrap().stdout.split()

            # Get installer url from the repo
            r_cache_enabled = KNOB_CACHE_PATTERN_MAPS.get_value(entityname=self.pool.poolname)

            if r_cache_enabled.is_error:
                return self._error(r_cache_enabled, 'could not determine whether to use cache for repo mapping')

            r_pattern_map = get_pattern_map(
                self.logger,
                os.path.join(KNOB_CONFIG_DIRPATH.value, KNOB_PREPARE_KICKSTART_COMPOSE_REPO_MAPPING_FILEPATH.value),
                use_cache=r_cache_enabled.unwrap()
            )

            if r_pattern_map.is_error:
                return self._error(r_pattern_map, 'could not load compose installer repo name mapping')

            try:
                repo_name = r_pattern_map.unwrap().match(self.gr.environment.os.compose)
            except gluetool.glue.GlueError as exc:
                # TODO: Switch guest to error as there is nothing else we can do
                return self._fail(
                    Failure.from_exc('failed to match the compose', exc, recoverable=False),
                    'failed to match compose'
                )

            repo = None

            if repo_name in repos:
                repo = repos[repo_name].get('baseurl', None)

            if not repo:
                return self._fail(Failure(
                    f'the guest does not contain a repo named {repo_name} that would provide base url for the installer',  # noqa: E501
                    recoverable=False
                ), 'installer source repo is not valid')

            # Template kickstart
            try:
                metadata = self.gr.environment.kickstart.metadata or ''

                with open(os.path.join(
                    KNOB_CONFIG_DIRPATH.value,
                    KNOB_PREPARE_KICKSTART_TEMPLATE_FILEPATH.value
                )) as f:
                    r_kickstart = render_template(
                        f.read(),
                        install_tree=repo,
                        repos=repos,
                        packages=packages,
                        files=files,
                        script=self.gr.environment.kickstart.script,
                        pre_install=self.gr.environment.kickstart.pre_install,
                        post_install=self.gr.environment.kickstart.post_install,
                        kernel_options_post=self.gr.environment.kickstart.kernel_options_post,
                        metadata={
                            tag[0]: tag[1] if len(tag) > 1 else None
                            for tag in [m.split('=', maxsplit=1) for m in metadata.split()]
                        }
                    )
            except OSError as exc:
                return self._fail(
                    Failure.from_exc('failed to read the kickstart template', exc),
                    'failed to read the kickstart template'
                )

            if r_kickstart.is_error:
                return self._error(r_kickstart, 'failed to render kickstart script')

            kickstart_script = r_kickstart.unwrap()
            blob = GuestLogBlob.from_content(kickstart_script)

            r_guest_log = SafeQuery.from_session(self.session, GuestLog) \
                .filter(GuestLog.guestname == self.gr.guestname) \
                .filter(GuestLog.logname == KS_LOGNAME) \
                .filter(GuestLog.contenttype == GuestLogContentType.BLOB) \
                .one_or_none()

            if r_guest_log.is_error:
                # Failing to log the generated kickstart is not a critical error but may make debugging installation
                # issues more difficult.
                self._error(r_guest_log, f'failed to load the log {KS_LOGNAME}', no_effect=True)

            log = r_guest_log.unwrap()

            if log is not None:
                r_store_log = log.update(
                    self.logger,
                    self.session,
                    GuestLogState.COMPLETE
                )

                if r_store_log.is_error:
                    self._fail(r_store_log.unwrap_error(), 'failed to update the kickstart script log', no_effect=True)
            else:
                r_create_log = GuestLog.create(
                    self.logger,
                    self.session,
                    self.gr.guestname,
                    KS_LOGNAME,
                    GuestLogContentType.BLOB,
                    GuestLogState.COMPLETE
                )

                if r_create_log.is_error:
                    self._error(r_create_log, 'failed to create log entry for the kickstart script', no_effect=True)

                log = r_create_log.unwrap()

            r_store_blob = blob.save(self.logger, self.session, log, overwrite=True)

            if r_store_blob.is_error:
                self._error(r_store_blob, 'failed to store the kickstart script log blob', no_effect=True)

            # Copy the templated kickstart script to guest
            with create_tempfile(file_contents=kickstart_script) as kickstart_filepath:
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

                r_ks_upload = copy_to_remote(
                    self.logger,
                    self.gr,
                    kickstart_filepath,
                    ks_dst,
                    key=self.master_key,
                    ssh_options=self.pool.ssh_options,
                    ssh_timeout=ssh_timeout,
                    poolname=self.pool.poolname,
                    commandname='prepare-kickstart.copy-kickstart'
                )

                if r_ks_upload.is_error:
                    return self._error(r_ks_upload, 'failed to copy the kickstart script to the guest')

            self.logger.debug('copied rendered kickstart template to the guest')

            # Copy files required to initiate the kickstart installation.
            r_script_upload = copy_to_remote(
                self.logger,
                self.gr,
                os.path.join(
                    KNOB_CONFIG_DIRPATH.value,
                    KNOB_PREPARE_KICKSTART_BOOT_INSTALLER_SCRIPT_FILEPATH.value
                ),
                script_dst,
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.copy-script'
            )

            if r_script_upload.is_error:
                return self._error(r_script_upload, 'failed to copy the kickstart install initiation script')

            self.logger.debug('copied installer initiation script to the guest')

            # Execute the script to fetch images and boot the netinstall using kexec.
            r_kexec = run_remote(
                self.logger,
                self.gr,
                [
                    '/bin/bash',
                    '-x',
                    script_dst,
                    repo,
                    ks_dst,
                    self.gr.environment.kickstart.kernel_options or ''
                ],
                key=self.master_key,
                ssh_options=self.pool.ssh_options,
                ssh_timeout=ssh_timeout,
                poolname=self.pool.poolname,
                commandname='prepare-kickstart.kexec'
            )

            if r_kexec.is_error:
                return self._error(r_kexec, 'failed to run the installer')

            self.logger.debug('successfuly executed the installer')

            r_delay = KNOB_PREPARE_KICKSTART_WAIT_INITIAL_DELAY.get_value(
                session=self.session,
                entityname=self.pool.poolname
            )

            if r_delay.is_error:
                return self._error(r_delay, 'failed to load the delay for installation check task')

            self.request_task(
                prepare_kickstart_wait,
                self.guestname,
                delay=r_delay.unwrap()
            )

    @classmethod
    def create(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> 'Workspace':
        """
        Create workspace.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: newly created workspace.
        """

        return cls(logger, session, db=db, guestname=guestname, task=TASK_NAME)

    @classmethod
    def prepare_kickstart(
        cls,
        logger: gluetool.log.ContextAdapter,
        db: DB,
        session: sqlalchemy.orm.session.Session,
        guestname: str
    ) -> DoerReturnType:
        """
        Perform a kickstart installation.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :param session: DB session to use for DB access.
        :param guestname: name of the request to process.
        :returns: task result.
        """

        return cls.create(logger, db, session, guestname) \
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
