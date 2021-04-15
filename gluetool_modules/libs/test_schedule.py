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
from typing import TYPE_CHECKING, cast, Any, Dict, List, Optional  # noqa

if TYPE_CHECKING:
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

    #: Tests finished, there is nothing left to perform.
    COMPLETE = 'complete'


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

        # List of outputs produced by different guest setup actions
        self.guest_setup_outputs = {}  # type: GuestSetupOutputsContainerType

        self.action = None  # type: Optional[gluetool.action.Action]

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

    def log(self, log_fn, label=None):
        # type: (LoggingFunctionType, Optional[str]) -> None
        """
        Log a table giving a nice, user-readable overview of the test schedule.

        At this moment, public properties of schedule entries are logged - guest, environment, etc.
        in the future more information would be added (passed the setup, running tests, finished tests,
        etc., but that will require a bit more info being accessible via schedule entry, which is work
        for the future patches.

        :param callable log_fn: function to use for logging.
        :param str label: if set, it is used as a label of the logged table.
        """

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
