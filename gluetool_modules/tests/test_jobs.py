# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import sys

import mock
import pytest
from mock import MagicMock

import gluetool
from gluetool_modules.libs.jobs import Job, handle_job_errors, run_jobs


@pytest.fixture(name='errors')
def fixture_errors():
    mock_logger = MagicMock()

    return [
        [
            Job(logger=mock_logger, name='dummy #1', target=None, args=None, kwargs=None),
            (None, None, None)
        ],
        [
            Job(logger=mock_logger, name='dummy #2', target=None, args=None, kwargs=None),
            (None, None, None)
        ],
        [
            Job(logger=mock_logger, name='dummy #3', target=None, args=None, kwargs=None),
            (None, None, None)
        ]
    ]


@pytest.fixture(name='soft_error')
def fixture_soft_error():
    try:
        raise gluetool.SoftGlueError('dummy soft error')

    except Exception as exc:
        return sys.exc_info()


@pytest.fixture(name='hard_error')
def fixture_hard_error():
    try:
        raise gluetool.GlueError('dummy hard error')

    except Exception as exc:
        return sys.exc_info()


def test_handle_errors_generic(log, errors):
    with pytest.raises(gluetool.GlueError, match=r'dummy error message'):
        handle_job_errors(errors, 'dummy error message')


def test_handle_errors_soft(log, errors, hard_error, soft_error):
    errors[0][1] = hard_error
    errors[1][1] = soft_error

    with pytest.raises(gluetool.SoftGlueError, match=r'dummy soft error'):
        handle_job_errors(errors, 'dummy error message')


def test_handle_errors_hard(log, errors, soft_error, hard_error):
    errors[0][1] = hard_error

    with pytest.raises(gluetool.GlueError, match=r'dummy hard error'):
        handle_job_errors(errors, 'dummy error message')


def test_run_jobs(log):
    mock_on_job_start = MagicMock()
    mock_on_job_complete = MagicMock()
    mock_on_job_error = MagicMock()
    mock_on_job_done = MagicMock()

    mock_job1 = Job(
        logger=MagicMock(),
        name='dummy #1',
        target=MagicMock(return_value=MagicMock()),
        args=(MagicMock(), MagicMock()),
        kwargs={'foo': MagicMock()}
    )

    mock_job2 = Job(
        logger=MagicMock(),
        name='dummy #2',
        target=MagicMock(side_effect=Exception('dummy exception')),
        args=(MagicMock(), MagicMock()),
        kwargs={'bar': MagicMock()}
    )

    errors = run_jobs([mock_job1, mock_job2],
                      on_job_start=mock_on_job_start,
                      on_job_complete=mock_on_job_complete,
                      on_job_error=mock_on_job_error,
                      on_job_done=mock_on_job_done)

    # General rule WRT call records: Pytests keeps call records in mock_call list, each
    # is preceded with a call named `__nonzero__`. Therefore when mock was called once,
    # the actual length of mock_calls is 2. Each call record is a tuple of 3 items: a name,
    # args and kwargs. So, to reach first argument of a single call, mock_calls[1][1][0] is
    # neccessary - 2nd entry on the list (1st is the __nonzero__ call), its 2nd property
    # (1st is the name), and 1st argument.

    mock_on_job_start.assert_any_call(*mock_job1.args, **mock_job1.kwargs)
    mock_on_job_start.assert_any_call(*mock_job2.args, **mock_job2.kwargs)

    mock_on_job_complete.assert_called_once_with(mock_job1.target.return_value, *mock_job1.args, **mock_job1.kwargs)

    # Assert call properties but replace traceback with ANY - we don't know it...
    mock_on_job_error.assert_called_once_with(
        (Exception, mock_job2.target.side_effect, mock.ANY),
        *mock_job2.args,
        **mock_job2.kwargs
    )

    # ... but store the actual exception info for later - it should be present in the list of errors.
    exc_info = mock_on_job_error.mock_calls[1][1][0]

    # The first argument is number of remaining jobs. We cannot determine the order in which jobs finish,
    # therefore when asserting, we use ANY.
    mock_on_job_done.assert_any_call(mock.ANY, *mock_job1.args, **mock_job1.kwargs)
    mock_on_job_done.assert_any_call(mock.ANY, *mock_job2.args, **mock_job2.kwargs)

    # Now we check the number of remaining jobs.
    assert mock_on_job_done.mock_calls[1][1][0] == 1  # 1st call
    assert mock_on_job_done.mock_calls[3][1][0] == 0  # 2nd call

    assert errors == [
        (mock_job2, exc_info)
    ]
