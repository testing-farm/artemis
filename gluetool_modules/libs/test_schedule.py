# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
import gluetool.log
from gluetool.log import LoggerMixin, log_table
import gluetool_modules.libs.guest_setup
import gluetool_modules.libs.sentry
from gluetool_modules.libs.artifacts import artifacts_location
from gluetool_modules.libs import GlueEnum

# Type annotations
from typing import TYPE_CHECKING, cast, Any, Dict, List, Optional, NamedTuple  # noqa

if TYPE_CHECKING:
    import bs4  # noqa
    from gluetool.log import LoggingFunctionType  # noqa
    import gluetool_modules.libs.guest  # noqa
    import gluetool_modules.libs.guest_setup  # noqa
    import gluetool_modules.libs.testing_environment  # noqa


# A mapping between guest setup stage and a list of guest setup outputs.
GuestSetupOutputsContainerType = Dict[
    gluetool_modules.libs.guest_setup.GuestSetupStage,
    List[gluetool_modules.libs.guest_setup.GuestSetupOutput]
]


# Helper - convert testing environment to a nice human-readable string.
# `serialize_to_string is not that nice, it adds field names and no spaces between fields,
# it is for machines mostly, and output of this function is supposed to be easily
# readable by humans.
def _env_to_str(testing_environment):
    # type: (Optional[gluetool_modules.libs.testing_environment.TestingEnvironment]) -> str

    if not testing_environment:
        return ''

    return '{} {} {}'.format(
        testing_environment.arch,
        testing_environment.compose,
        'S+' if testing_environment.snapshots else 'S-'
    )


# The same but for guests.
def _guest_to_str(guest):
    # type: (Optional[gluetool_modules.libs.guest.NetworkedGuest]) -> str

    if not guest:
        return ''

    return '{}\n{}'.format(_env_to_str(guest.environment), guest.name)


class EmptyTestScheduleError(gluetool_modules.libs.sentry.PrimaryTaskFingerprintsMixin, gluetool.SoftGlueError):
    def __init__(self, task):
        # type: (Any) -> None

        super(EmptyTestScheduleError, self).__init__(task, 'No tests were found for the component')

    @property
    def submit_to_sentry(self):
        # type: () -> bool

        return False


class InvalidTmtReferenceError(gluetool_modules.libs.sentry.PrimaryTaskFingerprintsMixin, gluetool.SoftGlueError):
    def __init__(self, task, tmt_reference):
        # type: (Any, str) -> None
        self.tmt_reference = tmt_reference
        super(InvalidTmtReferenceError, self).__init__(task, 'Incorrect TMT reference: {}'.format(tmt_reference))

    @property
    def submit_to_sentry(self):
        # type: () -> bool

        return False


class TestScheduleEntryStage(GlueEnum):
    """
    Enumerates different stages of a test schedule entry.

    During its lifetime, entry progress from one stage to another. Unlike :py:ref:`TestScheduleEntryState`,
    stage changes multiple times, and it may be even possible to return to previously visited stages.
    """

    #: Freshly created entry, nothing has happened yet to fulfil its goal.
    CREATED = 'created'

    #: An entry is ready for next stages of testing.
    READY = 'ready'

    #: A provisioning process started, to acquire a guest for the entry.
    GUEST_PROVISIONING = 'guest-provisioning'

    #: A guest has been provisioned.
    GUEST_PROVISIONED = 'guest-provisioned'

    #: A guest setup process started.
    GUEST_SETUP = 'guest-setup'

    #: The entry is prepared and tests can be executed.
    PREPARED = 'prepared'

    #: Test schedule runner began running tests of this entry.
    RUNNING = 'running'

    #: Tests are done, we now only release what must be released.
    CLEANUP = 'cleanup'

    #: Tests finished, there is nothing left to perform.
    COMPLETE = 'complete'


STAGES_ORDERED = [
    TestScheduleEntryStage.CREATED,
    TestScheduleEntryStage.READY,
    TestScheduleEntryStage.GUEST_PROVISIONING,
    TestScheduleEntryStage.GUEST_PROVISIONED,
    TestScheduleEntryStage.GUEST_SETUP,
    TestScheduleEntryStage.PREPARED,
    TestScheduleEntryStage.RUNNING,
    TestScheduleEntryStage.CLEANUP,
    TestScheduleEntryStage.COMPLETE
]


class TestScheduleEntryState(GlueEnum):
    """
    Enumerates different possible (final) states of a test schedule entry.

    Unlike :py:ref:`TestScheduleEntryStage`, state changes once and only once, representing
    the final state of the entry.
    """

    #: Everything went well.
    OK = 'ok'

    #: An error appeared while processing the entry.
    ERROR = 'error'


class TestScheduleResult(GlueEnum):
    """
    Enumerates different possible results of both the tests performed by the entry and the schedule as whole.
    """

    #: We can tell nothing better about the result, as we don't have any relevant information (yet).
    UNDEFINED = 'undefined'

    #: Special value, should be used for the schedule as a whole. Signals at least one crashed schedule entry.
    ERROR = 'error'

    PASSED = 'passed'
    FAILED = 'failed'
    INFO = 'info'
    NOT_APPLICABLE = 'not_applicable'


# TODO: incorporate guest-setup output, it's very similar but guest-setup output carries one extra field,
# the guest-setup stage.
TestScheduleEntryOutput = NamedTuple('TestScheduleEntryOutput', (
    ('stage', TestScheduleEntryStage),
    ('label', str),
    ('log_path', str),
    ('additional_data', Any)
))


class TestScheduleEntryAdapter(gluetool.log.ContextAdapter):
    def __init__(self, logger, entry_id):
        # type: (gluetool.log.ContextAdapter, str) -> None

        super(TestScheduleEntryAdapter, self).__init__(logger, {
            'ctx_schedule_entry_index': (200, entry_id)
        })


class TestScheduleEntry(LoggerMixin, object):
    """
    Internal representation of stuff to run, where to run it and other bits necessary for scheduling
    all things the module was asked to perform.

    :param logger: logger used as a parent of this entry's own logger.
    :param str entry_id: ID of the entry.
    :param str runner_capability: what runner capability is necessary to run the tests. Each runner
        supports some cabilities, and it is therefore able to take care of compatible entries only.
    :ivar str id: ID of the entry.
    :ivar str runner_capability: what runner capability is necessary to run the tests.
    :ivar TestScheduleEntryStage stage: current stage of the entry. It is responsibility of those
        who consume the entry to update its stage properly.
    :ivar TestScheduleEntryState state: current state of the entry. It is responsibility of those
        who consume the entry to update its state properly.
    :ivar TestScheduleResult result: result of the tests performed by the entry.
    :ivar TestingEnvironment testing_environment: environment required for the entry.
    :ivar NetworkedGuest guest: guest assigned to this entry.
    """

    def __init__(self, logger, entry_id, runner_capability):
        # type: (gluetool.log.ContextAdapter, str, str) -> None

        super(TestScheduleEntry, self).__init__(TestScheduleEntryAdapter(logger, entry_id))

        self.id = entry_id
        self.runner_capability = runner_capability

        self.stage = TestScheduleEntryStage.CREATED
        self.state = TestScheduleEntryState.OK
        self.result = TestScheduleResult.UNDEFINED

        self.testing_environment = None  # type: Optional[gluetool_modules.libs.testing_environment.TestingEnvironment]
        self.guest = None  # type: Optional[gluetool_modules.libs.guest.NetworkedGuest]

        # List of exceptions encountered while processing the entry
        self.exceptions = []  # type: List[gluetool.log.ExceptionInfoType]

        # List of outputs produced by different guest setup actions
        self.guest_setup_outputs = {}  # type: GuestSetupOutputsContainerType

        # List of test logs produced by tests.
        self.outputs = []  # type: List[TestScheduleEntryOutput]

        self.action = None  # type: Optional[gluetool.action.Action]

    @property
    def has_exceptions(self):
        # type: () -> bool

        return bool(self.exceptions)

    def log_entry(self, log_fn=None):
        # type: (Optional[LoggingFunctionType]) -> None

        log_fn = log_fn or self.debug

        log_fn('testing environment: {}'.format(self.testing_environment))
        log_fn('guest: {}'.format(self.guest))

    def log_guest_setup_outputs(self, module, log_fn=None):
        # type: (gluetool.Module, Optional[LoggingFunctionType]) -> None

        log_fn = log_fn or self.debug

        table = [
            ['Stage', 'Log', 'Location']
        ]

        for stage in gluetool_modules.libs.guest_setup.STAGES_ORDERED:
            outputs = self.guest_setup_outputs.get(stage, [])

            for output in outputs:
                table.append([
                    stage.value,
                    output.label,
                    artifacts_location(module, output.log_path, logger=self.logger)
                ])

        log_table(
            log_fn,
            'Guest setup logs',
            table,
            headers='firstrow', tablefmt='psql'
        )


class TestSchedule(List[TestScheduleEntry]):
    """
    Represents a test schedule - a list of entries, each describing what tests to run and the necessary
    environment. Based on a list, supports basic sequence operations while adding convenience logging
    helper.
    """

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None

        super(TestSchedule, self).__init__(*args, **kwargs)

        self.result = TestScheduleResult.UNDEFINED
        self.action = None  # type: Optional[gluetool.action.Action]

    def log(
        self,
        log_fn,
        label=None,
        include_errors=False,
        include_logs=False,
        include_connection_info=False,
        connection_info_docs_link=None,
        module=None
    ):
        # type: (LoggingFunctionType, Optional[str], bool, bool, bool, Optional[str], Optional[gluetool.Module]) -> None
        """
        Log a table giving a nice, user-readable overview of the test schedule.

        At this moment, public properties of schedule entries are logged - guest, environment, etc.
        in the future more information would be added (passed the setup, running tests, finished tests,
        etc., but that will require a bit more info being accessible via schedule entry, which is work
        for the future patches.

        :param callable log_fn: function to use for logging.
        :param str label: if set, it is used as a label of the logged table.
        """

        if include_logs and module is None:
            # We do not have access to `warning` logger :/
            log_fn('cannot log schedule logs with no access to coldstore helpers', sentry=True)

        label = label or 'test schedule'

        headers = [
            'SE', 'Stage', 'State', 'Result', 'Environment', 'Guest', 'Runner'
        ]

        rows = []

        for se in self:
            se_environment = _env_to_str(se.testing_environment)
            se_guest = _guest_to_str(se.guest)

            rows.append([
                se.id, se.stage.name, se.state.name, se.result.name, se_environment, se_guest, se.runner_capability
            ])

        log_table(log_fn, label, [headers] + rows,
                  tablefmt='psql', headers='firstrow')

        if include_errors:
            table = [
                ['SE', 'Error']
            ]

            for se in self:
                for _, exc, _ in se.exceptions:
                    table.append([
                        se.id,
                        exc.message if hasattr(exc, 'message') else str(exc)  # type: ignore  # handles even `None`
                    ])

            log_table(
                log_fn,
                'schedule errors',
                table,
                headers='firstrow', tablefmt='psql'
            )

        if include_logs and module is not None:
            table = [
                ['SE', 'Stage', 'Log', 'Location']
            ]

            # Collect all logs - guest-setup logs are in their own container, because those have their own substages.
            for se in self:
                for stage in STAGES_ORDERED:
                    for output in [_output for _output in se.outputs if _output.stage == stage]:
                        table.append([
                            se.id,
                            stage.value,
                            output.label,
                            artifacts_location(module, output.log_path, logger=module.logger)
                        ])

                    if stage == TestScheduleEntryStage.GUEST_SETUP:
                        for guest_setup_stage in gluetool_modules.libs.guest_setup.STAGES_ORDERED:
                            outputs = se.guest_setup_outputs.get(guest_setup_stage, [])

                            for guest_setup_output in outputs:
                                table.append([
                                    se.id,
                                    # pseudo-stage, to display both schedule stage and guest setup stage
                                    '{}.{}'.format(stage.value, guest_setup_stage.value),
                                    guest_setup_output.label,
                                    artifacts_location(module, guest_setup_output.log_path, logger=module.logger)
                                ])

            log_table(
                log_fn,
                'schedule logs',
                table,
                headers='firstrow', tablefmt='psql'
            )

        if include_connection_info:
            table = [
                ['SE', 'State', 'Result', 'Environment', 'SSH Command']
            ]

            for se in self:
                if se.guest is None:
                    ssh_command = 'not available'

                else:
                    ssh_command_stack = [
                        'ssh'
                    ]

                    if se.guest.username:
                        ssh_command_stack += [
                            '-l', se.guest.username
                        ]

                    if se.guest.port:
                        ssh_command_stack += [
                            '-p', str(se.guest.port)
                        ]

                    ssh_command_stack += [se.guest.hostname]

                    ssh_command = ' '.join(ssh_command_stack)

                table.append([
                    se.id,
                    se.state.name,
                    se.result.name,
                    _env_to_str(se.testing_environment),
                    ssh_command
                ])

            log_fn('NOTE: SSH is available only when machines were not returned by pipeline')

            if connection_info_docs_link is not None:
                log_fn('NOTE: see {} for documentation on machine reservation'.format(connection_info_docs_link))

            log_table(
                log_fn,
                'SSH instructions',
                table,
                headers='firstrow', tablefmt='psql'
            )
