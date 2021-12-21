# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Optional

from mock import MagicMock

import tft.artemis.guest
from tft.artemis.tasks import DoerType, TaskLogger


def assert_task_core_call(
    task_core: MagicMock,
    taskname: str,
    doer: DoerType,
    *doer_args: Any,
    test_guest_logger: Optional[str] = None
) -> None:
    """
    Test properties of a mock representing :py:func:`tft.artemis.task.task_core`.

    The helper verifies several properties of the mock, assuming it has been used to dispatch a task doer.
    """

    # Right, should have been called already.
    task_core.assert_called_once()

    # We can't use `assert_called_once_with()` because we have no access to objects passed to the `task_core()` call.
    # Therefore unpacking the store call information, and testing call properties "manually".
    _, args, kwargs = task_core.mock_calls[0]

    # There's one positional argument only, and that's the given doer.
    assert args == (doer,)

    # Its arguments are given as a keyword argument...
    assert kwargs['doer_args'] == doer_args

    # ... and then there's a task logger object.
    assert isinstance(kwargs['logger'], TaskLogger)
    assert kwargs['logger'].taskname == taskname

    # Some tasks go even beyond task logger by creating a guest logger. If we were given a task name,
    # let's verify guest logger has been created correctly.
    if test_guest_logger:
        assert isinstance(kwargs['logger']._logger, tft.artemis.guest.GuestLogger)
        assert kwargs['logger']._logger.guestname == test_guest_logger
