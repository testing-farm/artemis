import re

import molten.testing
import pytest

import tft.artemis.api
from tft.artemis import __VERSION__
from tft.artemis.api import CURRENT_MILESTONE_VERSION
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
    response = api_client.request('GET', f'/{CURRENT_MILESTONE_VERSION}/about')

    assert response.status_code == 200
    assert response.json() == {
        'package_version': __VERSION__,
        'image_digest': None,
        'image_url': None,
        'artemis_deployment': None
    }


def test_api_redirects(api_client: molten.testing.TestClient):
    # supported versions should include no redirects
    response = api_client.request('GET', '/v0.0.18/about')
    assert response.status_code == 200

    response = api_client.request('GET', '/v0.0.17/about')
    assert response.status_code == 200

    # /current should be redirected to the current milestone version
    response = api_client.request('GET', '/current/about')
    assert response.status_code == 308
    assert response.headers['location'] == f'/{CURRENT_MILESTONE_VERSION}/about'

    # same applies to legacy top-level endpoints, return redirects to the current version
    response = api_client.request('GET', '/about')
    assert response.status_code == 308
    assert response.headers['location'] == f'/{CURRENT_MILESTONE_VERSION}/about'


@pytest.mark.usefixtures('_schema_actual')
def test_metrics(api_client: molten.testing.TestClient, db, logger, redis):
    response = api_client.request('GET', f'/v{__VERSION__}/metrics')

    assert response.status_code == 200

    print(response.data)

    expected_metrics = (
        # Artemis
        ('artemis_identity_info', 'gauge'),
        ('artemis_package_info', 'gauge'),
        # Messages and tasks
        ('overall_message_count', 'counter'),
        ('overall_errored_message_count', 'counter'),
        ('overall_retried_message_count', 'counter'),
        ('overall_rejected_message_count', 'counter'),
        ('current_message_count', 'gauge'),
        ('current_delayed_message_count', 'gauge'),
        ('message_duration_milliseconds', 'histogram'),
        # API server HTTP traffic
        ('http_requests_count', 'counter'),
        ('http_requests_inprogress_count', 'gauge'),
        # API server DB metrics
        ('db_pool_size', 'gauge'),
        ('db_pool_checked_in', 'gauge'),
        ('db_pool_checked_out', 'gauge'),
        ('db_pool_overflow', 'gauge'),
        # Routing metrics
        ('overall_policy_calls_count', 'counter'),
        ('overall_policy_cancellations_count', 'counter'),
        ('overall_policy_rulings_count', 'counter'),
        # Provisioning metrics
        ('current_guest_request_count', 'gauge'),
        ('current_guest_request_count_total', 'gauge'),
        ('overall_provisioning_count', 'counter'),
        ('overall_successfull_provisioning_count', 'counter'),
        ('overall_failover_count', 'counter'),
        ('overall_successfull_failover_count', 'counter'),
        ('guest_request_age', 'gauge'),
        ('provisioning_duration_seconds', 'histogram'),
        # Pool resource metrics
        ('pool_resources_instances', 'gauge'),
        ('pool_resources_cores', 'gauge'),
        ('pool_resources_memory_bytes', 'gauge'),
        ('pool_resources_diskspace_bytes', 'gauge'),
        ('pool_resources_snapshot', 'gauge'),
        ('pool_resources_updated_timestamp', 'gauge'),
        # Pool errors
        ('pool_errors', 'counter')
    )

    for metric_name, metric_type in expected_metrics:
        if metric_type == 'counter':
            assert re.search(f'^# TYPE {metric_name}_total {metric_type}$', response.data, re.M) is not None, \
                f'metric "{metric_name}_total" not found in the output'

        else:
            assert re.search(f'^# TYPE {metric_name} {metric_type}$', response.data, re.M) is not None, \
                f'metric "{metric_name}" not found in the output'
