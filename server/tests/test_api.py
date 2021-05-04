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
    ('/guests/foo-bar-79/snapshots/baz-97/restore', '/guests/GUESTNAME/snapshots/SNAPSHOTNAME/restore'),
    ('/current/guests/foo-bar-79', '/current/guests/GUESTNAME'),
    ('/current/guests/foo-bar-79/events', '/current/guests/GUESTNAME/events'),
    ('/current/guests/foo-bar-79/snapshots', '/current/guests/GUESTNAME/snapshots'),
    ('/current/guests/foo-bar-79/snapshots/baz-97', '/current/guests/GUESTNAME/snapshots/SNAPSHOTNAME'),
    ('/current/guests/foo-bar-79/snapshots/baz-97/restore', '/current/guests/GUESTNAME/snapshots/SNAPSHOTNAME/restore'),
    ('/v0.0.17/guests/foo-bar-79', '/v0.0.17/guests/GUESTNAME'),
    ('/v0.0.17/guests/foo-bar-79/events', '/v0.0.17/guests/GUESTNAME/events'),
    ('/v0.0.17/guests/foo-bar-79/snapshots', '/v0.0.17/guests/GUESTNAME/snapshots'),
    ('/v0.0.17/guests/foo-bar-79/snapshots/baz-97', '/v0.0.17/guests/GUESTNAME/snapshots/SNAPSHOTNAME'),
    ('/v0.0.17/guests/foo-bar-79/snapshots/baz-97/restore', '/v0.0.17/guests/GUESTNAME/snapshots/SNAPSHOTNAME/restore')
])
def test_rewrite_request_path(request_path, rewritten_path):
    assert rewrite_request_path(request_path) == rewritten_path
