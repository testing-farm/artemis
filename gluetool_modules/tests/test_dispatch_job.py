import pytest

from mock import MagicMock
import gluetool
import gluetool_modules.libs.dispatch_job

from . import assert_shared, create_module, patch_shared


class FakeJenkins(object):
    # pylint: disable=too-few-public-methods

    def __init__(self, **expected_build_params):
        self.expected_build_params = expected_build_params

    def invoke(self, build_params=None):
        assert self.expected_build_params == build_params

    def invoke_job(self, job_name, build_params):
        return None


@pytest.fixture(name='module')
def fixture_module():
    # pylint: disable=unused-argument

    class DummyDispatchModule(gluetool_modules.libs.dispatch_job.DispatchJenkinsJobMixin, gluetool.Module):
        name = 'dummy-job'

    return create_module(DummyDispatchModule)


def create_build_params(mod, **kwargs):
    """
    Initialize module configuration using provided options and their values.
    """

    params = {
        'testing_thread_id': 'deadbeef',
        'artifact_id': 17,
        'pipeline_prepend': 'some prepended options',
        'pipeline_append': 'some appended options',
        'notify_recipients_options': ['more', 'and', 'more', 'recipients'],
        'recipients': ['and some other', 'people, we, want,    to notify  '],
        'notify_email_options': 'email options',
        'timeout_duration': '79',
        'priority': 97,
        'pipeline_state_reporter_options': 'some pipeline-report options',
        'test_category': 'some-test-categorie',
        'test_type': 'some-test-type'
    }

    params.update(kwargs)

    for name, value in params.iteritems():
        # pylint: disable=protected-access
        mod._config[name.replace('_', '-')] = value

    # notify-recipients-options will be presented as a string
    if not params['notify_recipients_options']:
        params['notify_recipients_options'] = None

    else:
        params['notify_recipients_options'] = ' '.join([str(s) for s in params['notify_recipients_options']])

    if params['recipients']:
        recipients_option = ' '.join([
            '--recipients={}'.format(recipient)
            for recipient in gluetool.utils.normalize_multistring_option(params['recipients'])
            ])

        if params['notify_recipients_options']:
            params['notify_recipients_options'] = '{} {}'.format(
                params['notify_recipients_options'],
                recipients_option
            )

        else:
            params['notify_recipients_options'] = recipients_option

    params.pop('recipients', None)

    # test-category and test-type will be presented as string
    if params['test_category']:
        params['pipeline_state_reporter_options'] = '{} --test-category={}'.format(
            params['pipeline_state_reporter_options'],
            params['test_category']
        )

        params.pop('test_category')

    if params['test_type']:
        params['pipeline_state_reporter_options'] = '{} --test-type={}'.format(
            params['pipeline_state_reporter_options'],
            params['test_type']
        )

        params.pop('test_type')

    return params


def test_sanity(module):
    # pylint: disable=unused-argument
    pass


def test_required_options(module):
    _, mod = module

    assert mod.required_options == ('artifact-id',)


def test_no_jenkins(module_with_primary_task):
    mod = module_with_primary_task

    assert_shared('jenkins', mod.execute)


def test_build_params(module_with_primary_task):
    mod = module_with_primary_task

    expected_params = create_build_params(mod)

    assert mod.build_params == expected_params


def test_no_recipients(module_with_primary_task):
    mod = module_with_primary_task

    expected_params = create_build_params(mod, notify_recipients_options=None)

    assert mod.build_params == expected_params


def test_dispatch(module_with_primary_task, monkeypatch, job_name='ci-dummy'):
    mod = module_with_primary_task

    # Init options & build params
    expected_params = create_build_params(mod)

    # DispatchJenkinsJobModule does not have any build byt default, let's set use some dummy name
    mod.job_name = job_name

    patch_shared(monkeypatch, mod, {
        'jenkins': FakeJenkins(**expected_params),
        'primary_task': MagicMock(id=17),
    })

    mod.execute()
