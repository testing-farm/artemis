import molten.testing
import pytest

import tft.artemis.api
from tft.artemis import __VERSION__
from tft.artemis.api.middleware import rewrite_request_path


@pytest.fixture(name='api_server')
def fixture_api_server():
    return tft.artemis.api.run_app()


@pytest.fixture(name='api_client')
def fixture_api_client(api_server):
    return molten.testing.TestClient(api_server)


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


def test_api_bootstrap(api_server):
    # if we got here, API server must initialize properly, otherwise, the fixture would crash
    pass


def test_api_about(api_client: molten.testing.TestClient):
    response = api_client.request('GET', f'/v{__VERSION__}/about')

    assert response.status_code == 200
    assert response.json() == {
        'package_version': __VERSION__,
        'image_digest': None,
        'image_url': None,
        'artemis_deployment': None
    }


def test_api_redirects(api_client: molten.testing.TestClient):
    # current version should always return right away
    response = api_client.request('GET', f'/v{__VERSION__}/about')
    assert response.status_code == 200

    # other supported versions should do the same, no redirects
    response = api_client.request('GET', '/v0.0.18/about')
    assert response.status_code == 200

    response = api_client.request('GET', '/v0.0.17/about')
    assert response.status_code == 200

    # /current should be redirected to the current version
    response = api_client.request('GET', '/current/about')
    assert response.status_code == 308
    assert response.headers['location'] == f'/v{__VERSION__}/about'

    # same applies to legacy top-level endpoints, return redirects to the current version
    response = api_client.request('GET', '/about')
    assert response.status_code == 308
    assert response.headers['location'] == f'/v{__VERSION__}/about'
