import pytest

from tft.artemis.api.middleware import rewrite_request_path


@pytest.mark.parametrize('path', [
    '/_docs',
    '/metrics',
    '/guests/'
])
def test_rewrite_request_path_nop(path):
    assert rewrite_request_path(path) == path


@pytest.mark.parametrize('request_path, rewritten_path', [
    ('/guests/foo-bar-79', '/guests/GUESTNAME'),
    ('/guests/foo-bar-79/events', '/guests/GUESTNAME/events'),
    ('/guests/foo-bar-79/snapshots', '/guests/GUESTNAME/snapshots'),
    ('/guests/foo-bar-79/snapshots/baz-97', '/guests/GUESTNAME/snapshots/SNAPSHOTNAME'),
    ('/guests/foo-bar-79/snapshots/baz-97/restore', '/guests/GUESTNAME/snapshots/SNAPSHOTNAME/restore')
])
def test_rewrite_request_path(request_path, rewritten_path):
    assert rewrite_request_path(request_path) == rewritten_path
