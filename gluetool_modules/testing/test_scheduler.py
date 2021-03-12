import argparse

import gluetool
from gluetool import utils, GlueError, SoftGlueError
from gluetool.action import Action
from gluetool.log import log_dict

import gluetool_modules.libs
import gluetool_modules.libs.guest
import gluetool_modules.libs.sentry

import gluetool_modules.libs.artifacts
from gluetool_modules.libs import ANY, GlueEnum
from gluetool_modules.libs.testing_environment import TestingEnvironment

# Type annotations
from typing import TYPE_CHECKING, cast, Any, Dict, List, NamedTuple, Union  # noqa

if TYPE_CHECKING:
    from gluetool_modules.libs.test_schedule import TestSchedule, TestScheduleEntry  # noqa


class PatchAction(GlueEnum):
    NOP = 'nop'
    DROP = 'drop'
    PATCH_ARCH = 'patch-arch'


# Either `ANY` or a list of architectures.
AvailableArchesType = Union[gluetool_modules.libs._UniqObject, List[str]]

ProvisionerCapabilities = NamedTuple(
    'ProvisionerCapabilities',
    [
        ('available_arches', AvailableArchesType)
    ]
)


class NoTestableArtifactsError(gluetool_modules.libs.sentry.PrimaryTaskFingerprintsMixin, SoftGlueError):
    """
    Raised when the artifact we're given to test contains no usable RPMS we could actually test.
    E.g. when the artifact was build for arch A only, while our backend can handle just arches
    B and C.

    .. note::

       Now it's tightly coupled with our OpenStack backend, we cannot use our restraint modules
       e.g. in Beaker - yet. Hence the explicit list of supported arches in the message.
    """

    def __init__(self, task, supported_arches):
        # type: (Any, AvailableArchesType) -> None

        self.task_arches = task.task_arches.arches
        self.supported_arches = supported_arches

        message = 'Task does not have any testable artifact - {} arches are not supported'.format(
            ', '.join(self.task_arches)
        )

        super(NoTestableArtifactsError, self).__init__(task, message)

    @property
    def submit_to_sentry(self):
        # type: () -> bool
        return False


class TestScheduler(gluetool.Module):
    """
    Prepares "test schedule" for other modules to perform. A schedule is a list of "test schedule entries"
    (see :py:class:`libs.test_schdule.TestScheduleEntry`). To create the schedule,
    supporting modules are required, to extract test plans and package necessary information into
    test schedule entries. This module then provisions and sets up the necessary guests.

    Schedule creation has following phases:

        * scheduler prepares a set of `constraints` - what environments it is expected to run tests on;
        * test schedule entries are obtained by calling ``create_test_schedule`` shared function, which
          is given the constraints to be guided by them;
        * for every test schedule entry - and its environment - a guest is provisioned (processes all
          environments in parallel);
        * each guest is set up by calling ``setup_guest`` shared function indirectly (processes all guests
          in parallel as well).

    *Testing constraints patching*

    Sometimes the list of constraints needs to be updated before creating a schedule. Use ``--tec-patch-map``
    to do this. For each testing environment constraint, rules and actions are evaluated:

    .. code-block:: yaml

       ---

       # We don't want ever to provision i686 when testing some artifact types.
       - rule: >
           EXISTS('PRIMARY_TASK')
           and PRIMARY_TASK.ARTIFACT_NAMESPACE == 'foo'
           and TEC.arch == 'i686'

         # We can change the architecture to a more preferred one:
         patch-arch: x86_64

         # Or we can drop the constraint completely:
         # drop: yes
    """

    name = 'test-scheduler'
    description = 'Prepares "test schedule" for other modules to perform.'

    options = {
        'arch-compatibility-map': {
            'help': """
                    Mapping between artifact arches and the actual arches we can use to test them (e.g. i686
                    can be tested on both x86_64 and i686 boxes (default: %(default)s).
                    """,
            'metavar': 'FILE',
            'default': None
        },
        'tec-patch-map': {
            'help': 'Testing environment constraints patch map (default: %(default)s).',
            'metavar': 'FILE',
            'default': None
        },
        'use-snapshots': {
            'help': 'Enable or disable use of snapshots (if supported by guests) (default: %(default)s)',
            'default': 'no',
            'metavar': 'yes|no'
        },
    }

    shared_functions = ['test_schedule']

    _schedule = None  # type: TestSchedule

    @utils.cached_property
    def arch_compatibility_map(self):
        # type: () -> Dict[str, List[str]]

        if not self.option('arch-compatibility-map'):
            return {}

        return cast(
            Dict[str, List[str]],
            utils.load_yaml(self.option('arch-compatibility-map'), logger=self.logger)
        )

    @utils.cached_property
    def tec_patch_map(self):
        # type: () -> Dict[str, List[str]]

        if not self.option('tec-patch-map'):
            return {}

        return cast(
            Dict[str, List[str]],
            utils.load_yaml(self.option('tec-patch-map'), logger=self.logger)
        )

    @gluetool.utils.cached_property
    def use_snapshots(self):
        # type: () -> bool

        return utils.normalize_bool_option(self.option('use-snapshots'))

    def test_schedule(self):
        # type: () -> TestSchedule
        """
        Returns schedule for runners. It tells runner which recipe sets
        it should run on which guest.

        :returns: [(guest, <recipeSet/>), ...]
        """

        return self._schedule

    def execute(self):
        # type: () -> None

        self.require_shared('create_test_schedule', 'provisioner_capabilities', 'compose', 'evaluate_instructions')

        # Check whether we have *any* artifacts at all, before we move on to more fine-grained checks.
        # If there's no task, just move on - we cannot check it, but it's allowed to run pipeline
        # without a task.
        if self.has_shared('tasks'):
            gluetool_modules.libs.artifacts.has_artifacts(*self.shared('tasks'))

        # One day, all that arch constraint "guessing" would move into `guess-environment` (or similar module)
        # who would be responsible for generating testing environments transparently for all arches and provisioners.

        # To create a schedule, we need to set up few constraints. So far the only known is the list of architectures
        # we'd like to see being used. For that, we match architectures present in the artifact with a list of
        # architectures provisioner can provide, and we find out what architectures we need (or cannot get...).
        # And, for example, whether there's anything left to test.
        #
        # We need to account for architectures that are not support but which may be compatible with a supported
        # architecture as well.

        # These are arches which we'd use to constraint the schedule - we're going to add to this list later...
        constraint_arches = []  # type: List[str]

        provisioner_capabilities = cast(
            ProvisionerCapabilities,
            self.shared('provisioner_capabilities')
        )

        log_dict(self.debug, 'provisioner capabilities', provisioner_capabilities)

        # ... these are *valid* artifact arches - those supported by the provisioner...
        valid_arches = []  # type: List[str]

        # ... these are arches supported by the provisioner...
        supported_arches = provisioner_capabilities.available_arches if provisioner_capabilities else []
        log_dict(self.debug, 'supported arches', supported_arches)

        # ... and these are arches available in the artifact.
        if self.has_shared('primary_task'):
            artifact_arches = cast(
                List[str],
                self.shared('primary_task').task_arches.arches
            )

        else:
            artifact_arches = []

        log_dict(self.debug, 'artifact arches', artifact_arches)

        if not artifact_arches:
            if supported_arches is gluetool_modules.libs.ANY:
                # Not really sure what to test here - artifact tells us nothing. This will lead to constraint_arches
                # being empty, producing no test schedule constraints.
                self.warn('No artifact arches found and supported are ANY', sentry=True)

            else:
                self.warn('No artifact arches found, using all supported ones', sentry=True)

                # We know supported_arches must be a list - it can also be ANY, but that's handled by the positive
                # branch right above. The list is the only option left, but mypy doesn't see it.
                assert isinstance(supported_arches, list)

                artifact_arches = supported_arches

        log_dict(self.debug, 'final artifact arches', artifact_arches)

        # When provisioner's so bold that it supports *any* architecture, give him every architecture present
        # in the artifact, and watch it burn :)
        # Note that when the only artifact arch is `noarch`, it gets removed from constraints later, we have
        # an extra step dealing with `noarch`. because obviously we can't get `noarch` guest from provisioner.
        if supported_arches is ANY:
            valid_arches = artifact_arches
            constraint_arches = artifact_arches

        else:
            assert isinstance(supported_arches, list)

            for arch in artifact_arches:
                # artifact arch is supported directly
                if arch in supported_arches:
                    valid_arches.append(arch)
                    constraint_arches.append(arch)
                    continue

                # It may be possible to find compatible architecture, e.g. it may be fine to test
                # i686 artifacts on x86_64 boxes. Let's check the configuration.

                # Start with a list of arches compatible with `arch`.
                compatible_arches = self.arch_compatibility_map.get(arch, [])

                # Find which of these are supported.
                compatible_and_supported_arches = [
                    compatible_arch for compatible_arch in compatible_arches if compatible_arch in supported_arches
                ]

                # If there are any compatible & supported, add the original arch to the list of valid arches,
                # because we *can* test it, but use the compatible arches for constraints - we cannot ask
                # provisioner (yet) to provide use the original arch, because it already explicitely said
                # "not supported". We can test artifacts of this archtiecture, but using other arches as
                # the environment.
                if compatible_and_supported_arches:
                    # Warning, because nothing else submits to Sentry, and Sentry because
                    # problem of secondary arches doesn't fit well with nice progress of
                    # testing environments, and I'd really like to observe the usage of
                    # this feature, without grepping all existing logs :/ If it's being
                    # used frequently, we can always silence the Sentry submission.

                    self.warn("Artifact arch '{}' not supported but compatible with '{}'".format(
                        arch, ', '.join(compatible_and_supported_arches)
                    ), sentry=True)

                    valid_arches.append(arch)
                    constraint_arches += compatible_and_supported_arches

        log_dict(self.debug, 'valid artifact arches', valid_arches)
        log_dict(self.debug, 'constraint arches', constraint_arches)

        if not valid_arches:
            raise NoTestableArtifactsError(self.shared('primary_task'), supported_arches)

        # `noarch` is supported naturally on all other arches, so, when we encounter an artifact with just
        # the `noarch`, we "reset" the list of constraints to let scheduler plugin know we'd like to get all
        # arches possible. But we have to be careful and take into account what provisioner told us about itself,
        # because we could mislead the scheduler plugin into thinking that every architecture is valid - if
        # provisioner doesn't support "ANY" arch, we have to prepare constraints just for the supported arches.
        # We can use all of them, true, because it's `noarch`, but we have to limit the testing to just them.
        if valid_arches == ['noarch']:
            self.debug("'noarch' is the only valid arch")

            # If provisioner boldly promised anything was possible, empty list of valid arches would result
            # into us not placing any constraints on the environments, and we should get really everything.
            if supported_arches is ANY:
                constraint_arches = []

            # On the other hand, if provisioner can support just a limited set of arches, don't be greedy.
            else:
                assert isinstance(supported_arches, list)

                constraint_arches = supported_arches

        # When `noarch` is not the single valid arch, other arches dictate what constraints should we use.
        # Imagine an arch-specific "main" RPM, with noarch plugins - we cannot just throw in other supported
        # arches, because we'd not be able to test the "main" RPM, but thanks to "main" RPM, there should
        # be - and obviously are - other arches in the list, not just noarch. So, we do nothing, but, out
        # of curiosity, a warning would be nice to track this - it's a complicated topic, let's not get it
        # unnoticed, the assumption above might be completely wrong.
        elif 'noarch' in valid_arches:
            self.warn(
                "Artifact has 'noarch' bits side by side with regular bits ({})".format(', '.join(valid_arches)),
                sentry=True
            )

        log_dict(self.debug, 'constraint arches (noarch pruned)', constraint_arches)

        # Get rid of duplicities - when we found an unsupported arch, we added all its compatibles to the list.
        # This would lead to us limiting scheduler to provide arches A, B, C, C, C, ... and so on, because usualy
        # there's a primary arch A and secondary arch B, which is unsupported, leading to us having A in the list
        # two times.
        constraint_arches = list(set(constraint_arches))

        log_dict(self.debug, 'constraint arches (duplicities pruned)', constraint_arches)

        # Create constraints, for composes and arches
        composes = self.shared('compose')
        constraints = []  # type: List[TestingEnvironment]

        for compose in composes:
            for arch in constraint_arches:
                constraints += [
                    TestingEnvironment(
                        arch=arch,
                        compose=compose,
                        snapshots=self.use_snapshots
                    )
                ]

        log_dict(self.debug, 'testing environment constraints', constraints)

        patched_constraints = []

        for tec in constraints:
            context = gluetool.utils.dict_update(
                self.shared('eval_context'),
                {
                    'TEC': tec
                }
            )

            # Our container for instructions' actions.
            patch_action = argparse.Namespace(
                action=PatchAction.NOP,
                arch=None
            )

            # Callback for 'drop' command
            def _drop_callback(instruction, command, argument, context):
                # type: (Any, str, bool, Dict[str, Any]) -> None

                if argument is True:
                    patch_action.action = PatchAction.DROP

            def _patch_arch_callback(instruction, command, argument, context):
                # type: (Any, str, str, Dict[str, Any]) -> None

                patch_action.action = PatchAction.PATCH_ARCH
                patch_action.arch = argument

            self.shared(
                'evaluate_instructions',
                self.tec_patch_map,
                {
                    'drop': _drop_callback,
                    'patch-arch': _patch_arch_callback
                },
                context=context,
                default_rule='False'
            )

            if patch_action.action == PatchAction.DROP:
                self.debug('testing constraint {} dropped'.format(tec))

            else:
                patched_constraints.append(tec)

                if patch_action.action == PatchAction.PATCH_ARCH:
                    tec.arch = patch_action.arch

                    self.debug('testing constraint {} arch patched with {}'.format(tec, patch_action.arch))

        log_dict(self.debug, 'patched testing environment constraints', patched_constraints)

        # Remove duplicities
        duplicate_constraints = {
            str(tec): tec for tec in patched_constraints
        }

        final_constraints = duplicate_constraints.values()

        log_dict(self.debug, 'final testing environment constraints', final_constraints)

        # Call plugin to create the schedule
        with Action('creating test schedule', parent=Action.current_action(), logger=self.logger):
            schedule = self.shared('create_test_schedule', testing_environment_constraints=final_constraints)

        if not schedule:
            raise GlueError('Test schedule is empty')

        self._schedule = schedule
