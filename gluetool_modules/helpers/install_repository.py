import os
import gluetool
from gluetool.action import Action
from gluetool.result import Ok, Error

from gluetool_modules.libs.guest_setup import guest_setup_log_dirpath, GuestSetupOutput, GuestSetupStage
from gluetool_modules.libs.sut_installation import SUTInstallation

# accepted artifact types from testing farm request
TESTING_FARM_ARTIFACT_TYPES = ['repository']

# Default path to downloading the packages
DEFAULT_DOWNLOAD_PATH = "/var/share/test-artifacts"


class InstallRepository(gluetool.Module):
    """
    Installs packages from specified artifact repository on given guest.
    Downloads all RPMs to a given path (default is {}) and installs them.
    """.format(DEFAULT_DOWNLOAD_PATH)

    name = 'install-repository'
    description = 'Install packages from a given test artifacts repository'

    shared_functions = ('setup_guest',)

    options = {
        'log-dir-name': {
            'help': 'Name of directory where outputs of installation commands will be stored (default: %(default)s).',
            'type': str,
            'default': 'artifact-installation'
        },
        'download-path': {
            'help': 'Path of the directory where all the packages will be downloaded to (default: %(default)s).',
            'type': str,
            'default': DEFAULT_DOWNLOAD_PATH
        },
    }

    def __init__(self, *args, **kwargs):
        super(InstallRepository, self).__init__(*args, **kwargs)
        self.request = None
        self.request_artifacts = None

    def setup_guest(self, guest, stage=GuestSetupStage.PRE_ARTIFACT_INSTALLATION, log_dirpath=None, **kwargs):
        download_path = self.option('download-path')

        self.require_shared('evaluate_instructions')

        log_dirpath = guest_setup_log_dirpath(guest, log_dirpath)

        r_overloaded_guest_setup_output = self.overloaded_shared(
            'setup_guest',
            guest,
            stage=stage,
            log_dirpath=log_dirpath,
            **kwargs
        )

        if r_overloaded_guest_setup_output is None:
            r_overloaded_guest_setup_output = Ok([])

        if r_overloaded_guest_setup_output.is_error:
            return r_overloaded_guest_setup_output

        if stage != GuestSetupStage.ARTIFACT_INSTALLATION:
            return r_overloaded_guest_setup_output

        # no artifacts to test
        if not self.request_artifacts:
            return r_overloaded_guest_setup_output

        guest_setup_output = r_overloaded_guest_setup_output.unwrap() or []

        installation_log_dirpath = os.path.join(
            log_dirpath,
            '{}-{}'.format(self.option('log-dir-name'), guest.name)
        )

        sut_installation = SUTInstallation(self, installation_log_dirpath, self.request, logger=guest)
        sut_installation.add_step('Create artifacts directory', 'mkdir -p {}'.format(download_path),
                                  ignore_exception=True)
        for repository_url in self.request_artifacts:
            repo_id = repository_url['id']
            sut_installation.add_step(
                'Download artifacts',
                (
                    'cd {} && '
                    'dnf repoquery -q --queryformat "%{{name}}" --repofrompath artifacts-repo,{} '
                    '              --disablerepo="*" --enablerepo="artifacts-repo" --location | '
                    'xargs -n1 curl -sO'
                ).format(download_path, repo_id)
            )

        packages = '{}/*[^.src].rpm'.format(download_path)

        # note: library does the magic in using DNF is needed \o/
        sut_installation.add_step('Reinstall packages', 'yum -y reinstall {}'.format(packages), ignore_exception=True)
        sut_installation.add_step('Downgrade packages', 'yum -y downgrade {}'.format(packages), ignore_exception=True)
        sut_installation.add_step('Update packages', 'yum -y update {}'.format(packages), ignore_exception=True)
        sut_installation.add_step('Install packages', 'yum -y install {}'.format(packages), ignore_exception=True)

        sut_installation.add_step(
            'Verify all packages installed',
            "ls {} | sed 's/.rpm$//' | xargs rpm -q".format(packages)
        )

        with Action(
                'installing rpm artifacts',
                parent=Action.current_action(),
                logger=guest.logger,
                tags={
                    'guest': {
                        'hostname': guest.hostname,
                        'environment': guest.environment.serialize_to_json()
                    },
                    'artifact-id': self.request.id,
                    'artifact-type': self.request.ARTIFACT_NAMESPACE
                }
        ):
            sut_result = sut_installation.run(guest)

        guest_setup_output += [
            GuestSetupOutput(
                stage=stage,
                label='build installation',
                log_path=installation_log_dirpath,
                additional_data=sut_installation
            )
        ]

        if sut_result.is_error:
            assert sut_result.error is not None

            return Error((
                guest_setup_output,
                sut_result.error
            ))

        return Ok(guest_setup_output)

    def execute(self):
        if not self.has_shared('testing_farm_request'):
            return

        # extract ids from the request
        self.request = self.shared('testing_farm_request')

        if not self.request.environments_requested[0]['artifacts']:
            self.info("No repository artifacts found, skipping")
            return

        # TODO: environment should be coming from test scheduler later
        self.request_artifacts = [
            artifact for artifact in self.request.environments_requested[0]['artifacts']
            if artifact['type'] in TESTING_FARM_ARTIFACT_TYPES
        ]
