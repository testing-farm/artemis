from mock import MagicMock
from gluetool.result import Ok, Error


def do_test_release_pool_resources_item(
    logger,
    monkeypatch,
    driver,
    resource_ids,
    raw_command_method_name,
    expected_raw_method_args=None,
    expected_raw_method_kwargs=None
):
    mock_raw_command = MagicMock(
        name='<Driver>._raw_command<mock>',
        return_value=Ok(None)
    )

    monkeypatch.setattr(driver, raw_command_method_name, mock_raw_command)

    r = driver.release_pool_resources(logger, resource_ids)

    assert r.is_ok

    if expected_raw_method_args is not None or expected_raw_method_kwargs is not None:
        expected_raw_method_args = expected_raw_method_args or tuple()
        expected_raw_method_kwargs = expected_raw_method_kwargs or dict()

        mock_raw_command.assert_called_once_with(*expected_raw_method_args, **expected_raw_method_kwargs)

    return mock_raw_command


def do_test_release_pool_resources_item_propagate_error(
    logger,
    monkeypatch,
    driver,
    resource_ids,
    raw_command_method_name
):
    mock_failure = MagicMock(
        name='Failure<mock>',
        recoverable=True
    )

    mock_raw_command = MagicMock(
        name='<Driver>._raw_command<mock>',
        return_value=Error(mock_failure)
    )

    monkeypatch.setattr(driver, raw_command_method_name, mock_raw_command)

    r = driver.release_pool_resources(logger, resource_ids)

    assert r.is_error
    assert r.unwrap_error() is mock_failure
