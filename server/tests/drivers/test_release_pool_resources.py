# import pytest


def test_nop(logger, pool_driver):
    r = pool_driver.release_pool_resources(logger, {})

    assert r.is_ok
    assert r.unwrap() is None
