import base64
import re
from typing import Any, Callable, List, Pattern, Tuple, cast

import _pytest.monkeypatch
import gluetool.log
import molten
import molten.testing
import pytest
import sqlalchemy
from mock import MagicMock

import tft.artemis.api
import tft.artemis.api.middleware
import tft.artemis.db
from tft.artemis import __VERSION__
from tft.artemis.api import CURRENT_MILESTONE_VERSION
from tft.artemis.api.middleware import AuthContext, rewrite_request_path


@pytest.fixture(name='api_server')
def fixture_api_server() -> molten.app.App:
    return tft.artemis.api.run_app()


@pytest.fixture(name='api_client')
def fixture_api_client(api_server: molten.app.App) -> molten.testing.TestClient:
    return molten.testing.TestClient(api_server)


@pytest.mark.parametrize('path', [
    '/_docs',
    '/metrics',
    '/guests/'
])
def test_rewrite_request_path_nop(path: str) -> None:
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
def test_rewrite_request_path(request_path: str, rewritten_path: str) -> None:
    assert rewrite_request_path(request_path) == rewritten_path


def test_api_bootstrap(api_server: molten.app.App) -> None:
    # if we got here, API server must initialize properly, otherwise, the fixture would crash
    pass


def test_api_about(api_client: molten.testing.TestClient) -> None:
    response = api_client.request('GET', f'/{CURRENT_MILESTONE_VERSION}/about')

    assert response.status_code == 200
    assert response.json() == {
        'package_version': __VERSION__,
        'image_digest': None,
        'image_url': None,
        'artemis_deployment': None
    }


def test_api_redirects(api_client: molten.testing.TestClient) -> None:
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
def test_metrics(
    api_client: molten.testing.TestClient,
    db: tft.artemis.db.DB,
    logger: gluetool.log.ContextAdapter,
    redis: None
) -> None:
    response = api_client.request('GET', f'/{CURRENT_MILESTONE_VERSION}/metrics')

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
        ('pool_errors', 'counter'),
        ('cli_calls', 'counter'),
        ('cli_call_duration_seconds', 'histogram')
    )

    for metric_name, metric_type in expected_metrics:
        if metric_type == 'counter':
            assert re.search(f'^# TYPE {metric_name}_total {metric_type}$', response.data, re.M) is not None, \
                f'metric "{metric_name}_total" not found in the output'

        else:
            assert re.search(f'^# TYPE {metric_name} {metric_type}$', response.data, re.M) is not None, \
                f'metric "{metric_name}" not found in the output'


@pytest.mark.parametrize(('path', 'patterns', 'expected'), [
    (
        '/_docs',
        tft.artemis.api.middleware.NO_AUTH,
        True
    ),
    (
        '/_docs',
        tft.artemis.api.middleware.PROVISIONING_AUTH,
        False
    ),
    (
        '/guests',
        tft.artemis.api.middleware.PROVISIONING_AUTH,
        True
    ),
    (
        '/guests/foo/snapshots',
        tft.artemis.api.middleware.PROVISIONING_AUTH,
        True
    ),
    (
        '/v0.0.24/guests/foo/snapshots',
        tft.artemis.api.middleware.PROVISIONING_AUTH,
        True
    )
])
def test_auth_matches_path(path: str, patterns: List[Pattern[str]], expected: bool) -> None:
    assert tft.artemis.api.middleware.matches_path(
        MagicMock(path=path),
        patterns
    ) is expected


@pytest.fixture(name='mock_request')
def fixture_mock_request() -> molten.Request:
    return molten.Request()


@pytest.fixture(name='auth_context')
def fixture_auth_context(mock_request: molten.Request) -> AuthContext:
    return AuthContext(
        mock_request,
        is_authentication_enabled=True,
        is_authorization_enabled=True
    )


def _compare_contexts(first: AuthContext, second: AuthContext) -> None:
    for field in AuthContext._serialized_fields:
        assert getattr(first, field) == getattr(second, field)

    assert first.request is second.request


def test_auth_context_serialization(auth_context: AuthContext) -> None:
    serialized = auth_context.serialize()

    second = AuthContext.unserialize(serialized, auth_context.request)

    _compare_contexts(auth_context, second)


def test_auth_context_inject(auth_context: AuthContext) -> None:
    from tft.artemis.api.middleware import AUTH_CTX_HEADER

    auth_context.request.headers.add(AUTH_CTX_HEADER, 'original header value')

    auth_context.inject()

    assert auth_context.request.headers.get(AUTH_CTX_HEADER) == auth_context.serialize()

    r_extracted = AuthContext.extract(auth_context.request)

    assert r_extracted.is_ok

    extracted = r_extracted.unwrap()

    _compare_contexts(auth_context, extracted)


def test_auth_context_extract_credentials_basic_none(auth_context: AuthContext) -> None:
    auth_context._extract_credentials_basic()

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None


@pytest.mark.parametrize('payload', [
    'wrong-type-missing-credentials',
    'wrong-type dummy credentials',
    'Basic',
    f'Basic {base64.b64encode(b"username-and-nothing-more").decode()}',
    f'Basic {base64.b64encode(b"username-only:").decode()}',
    f'Basic {base64.b64encode(b":password-only").decode()}',
    f'Basic {base64.b64encode(b"some-url-decoding%20").decode()}',
    f'Basic foobar{base64.b64encode(b"broken base64").decode()}',
])
def test_auth_context_extract_credentials_basic_bad_payload(auth_context: AuthContext, payload: str) -> None:
    auth_context.request.headers.add('Authorization', payload)

    auth_context._extract_credentials_basic()

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is True
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None


def test_auth_context_extract_credentials_basic(auth_context: AuthContext) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-user:dummy-password").decode()}'
    )

    auth_context._extract_credentials_basic()

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-user'
    assert auth_context.token == 'dummy-password'


@pytest.fixture
def _schema_test_db_Users(db: tft.artemis.db.DB, session: sqlalchemy.orm.session.Session) -> None:
    from tft.artemis.db import User

    User.__table__.create(db.engine)

    session.commit()  # type: ignore  # TODO: untyped commit()??


@pytest.fixture
def _schema_test_db_Users_user(session: sqlalchemy.orm.session.Session, _schema_test_db_Users: None) -> None:
    from tft.artemis.db import User, UserRoles

    session.add(User(
        username='dummy-user',
        role=UserRoles.USER.value,
        provisioning_token=User.hash_token('dummy-user-provisioning-token'),
        admin_token=User.hash_token('dummy-user-admin-token')
    ))

    session.commit()  # type: ignore  # TODO: untyped commit()??


@pytest.fixture
def _schema_test_db_Users_admin(session: sqlalchemy.orm.session.Session, _schema_test_db_Users: None) -> None:
    from tft.artemis.db import User, UserRoles

    session.add(User(
        username='dummy-admin',
        role=UserRoles.ADMIN.value,
        provisioning_token=User.hash_token('dummy-admin-provisioning-token'),
        admin_token=User.hash_token('dummy-admin-admin-token')
    ))

    session.commit()  # type: ignore  # TODO: untyped commit()??


def test_auth_context_verify_auth_basic_empty(
    auth_context:
    AuthContext, session: sqlalchemy.orm.session.Session
) -> None:
    auth_context.is_empty = True

    auth_context.verify_auth_basic(session, 'whatever')

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None


def test_auth_context_verify_auth_basic_invalid(
    auth_context: AuthContext,
    session: sqlalchemy.orm.session.Session
) -> None:
    auth_context.is_empty = True
    auth_context.is_invalid_request = True

    auth_context.verify_auth_basic(session, 'whatever')

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is True
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None


@pytest.mark.usefixtures('_schema_test_db_Users')
def test_auth_context_verify_auth_basic_no_such_user(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"wrong-username:dummy-password").decode()}'
    )

    auth_context.verify_auth_basic(session, 'whatever')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'wrong-username'
    assert auth_context.token == 'dummy-password'


@pytest.mark.usefixtures('_schema_test_db_Users_user')
def test_auth_context_verify_auth_basic_provisioning_valid(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-user:dummy-user-provisioning-token").decode()}'
    )

    auth_context.verify_auth_basic(session, 'provisioning')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is True
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-user'
    assert auth_context.token == 'dummy-user-provisioning-token'


@pytest.mark.usefixtures('_schema_test_db_Users_user')
def test_auth_context_verify_auth_basic_provisioning_invalid_type(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-user:dummy-user-provisioning-token").decode()}'
    )

    auth_context.verify_auth_basic(session, 'admin')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-user'
    assert auth_context.token == 'dummy-user-provisioning-token'


@pytest.mark.usefixtures('_schema_test_db_Users_user')
def test_auth_context_verify_auth_basic_provisioning_invalid_token(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-user:wrong-password").decode()}'
    )

    auth_context.verify_auth_basic(session, 'admin')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-user'
    assert auth_context.token == 'wrong-password'


@pytest.mark.usefixtures('_schema_test_db_Users_admin')
def test_auth_context_verify_auth_basic_admin_valid(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-admin:dummy-admin-admin-token").decode()}'
    )

    auth_context.verify_auth_basic(session, 'admin')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is True
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-admin'
    assert auth_context.token == 'dummy-admin-admin-token'


@pytest.mark.usefixtures('_schema_test_db_Users_user')
def test_auth_context_verify_auth_basic_admin_invalid_type(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-admin:dummy-admin-admin-token").decode()}'
    )

    auth_context.verify_auth_basic(session, 'provisioning')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-admin'
    assert auth_context.token == 'dummy-admin-admin-token'


@pytest.mark.usefixtures('_schema_test_db_Users_admin')
def test_auth_context_verify_auth_basic_admin_invalid_token(
    session: sqlalchemy.orm.session.Session,
    auth_context: AuthContext
) -> None:
    auth_context.request.headers.add(
        'Authorization',
        f'Basic {base64.b64encode(b"dummy-admin:wrong-password").decode()}'
    )

    auth_context.verify_auth_basic(session, 'admin')

    assert auth_context.is_empty is False
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username == 'dummy-admin'
    assert auth_context.token == 'wrong-password'


def test_auth_context_verify_auth_no_auth(db: tft.artemis.db.DB, auth_context: AuthContext) -> None:
    auth_context.request.path = '/_docs'

    auth_context.verify_auth(db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is True
    assert auth_context.username is None
    assert auth_context.token is None


def test_auth_context_verify_auth_provisioning(
    db: tft.artemis.db.DB,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    auth_context: AuthContext
) -> None:
    auth_context.request.path = '/guests/foo'

    mock_user = MagicMock(name='user<mock>')

    def mock_verify_auth_basic(session: sqlalchemy.orm.session.Session, token_type: str) -> None:
        assert token_type == 'provisioning'

        auth_context.user = mock_user
        auth_context.is_authenticated = True

    monkeypatch.setattr(auth_context, 'verify_auth_basic', mock_verify_auth_basic)

    auth_context.verify_auth(db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is True
    assert auth_context.is_authorized is True
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is mock_user


def test_auth_context_verify_auth_admin(
    db: tft.artemis.db.DB,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    auth_context: AuthContext
) -> None:
    auth_context.request.path = '/users/foo'

    mock_user = MagicMock(
        name='user<mock>',
        role=tft.artemis.db.UserRoles.ADMIN
    )

    def mock_verify_auth_basic(session: sqlalchemy.orm.session.Session, token_type: str) -> None:
        assert token_type == 'admin'

        auth_context.user = mock_user
        auth_context.is_authenticated = True

    monkeypatch.setattr(auth_context, 'verify_auth_basic', mock_verify_auth_basic)

    auth_context.verify_auth(db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is True
    assert auth_context.is_authorized is True
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is mock_user


def test_auth_context_verify_auth_admin_with_user_role(
    db: tft.artemis.db.DB,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    auth_context: AuthContext
) -> None:
    auth_context.request.path = '/users/foo'

    mock_user = MagicMock(
        name='user<mock>',
        role=tft.artemis.db.UserRoles.USER
    )

    def mock_verify_auth_basic(session: sqlalchemy.orm.session.Session, token_type: str) -> None:
        assert token_type == 'admin'

        auth_context.user = mock_user
        auth_context.is_authenticated = True

    monkeypatch.setattr(auth_context, 'verify_auth_basic', mock_verify_auth_basic)

    auth_context.verify_auth(db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is True
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is mock_user


@pytest.fixture(name='mock_middleware')
def fixture_mock_middleware(
    db: tft.artemis.db.DB,
    monkeypatch: _pytest.monkeypatch.MonkeyPatch,
    auth_context: AuthContext
) -> Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]:
    mock_context_creator = MagicMock(
        name='AuthContext<mock>',
        return_value=auth_context
    )

    mock_handler = MagicMock(
        name='handler<mock>',
        return_value=MagicMock(name='handler.return_value<mock>')
    )

    monkeypatch.setattr(tft.artemis.api.middleware, 'AuthContext', mock_context_creator)

    monkeypatch.setattr(auth_context, 'inject', MagicMock(name='auth_context.inject<mock>'))
    monkeypatch.setattr(auth_context, 'verify_auth', MagicMock(name='auth_context.verify_auth<mock>'))
    auth_context.request.path = '/guests'

    wrapped = tft.artemis.api.middleware.authorization_middleware(mock_handler)

    return mock_handler, wrapped


def test_auth_middleware_disabled_authentication(
    db: tft.artemis.db.DB,
    auth_context: AuthContext,
    mock_middleware: Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]
) -> None:
    mock_handler, wrapped = mock_middleware

    auth_context.is_authentication_enabled = False

    ret = wrapped(auth_context.request, db)

    assert ret is mock_handler.return_value

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is None

    auth_context.inject.assert_called_once_with()  # type: ignore  # callable is a MagicMock instance
    auth_context.verify_auth.assert_not_called()  # type: ignore  # callable is a MagicMock instance


def test_auth_middleware_disabled_authorization(
    db: tft.artemis.db.DB,
    auth_context: AuthContext,
    mock_middleware: Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]
) -> None:
    mock_handler, wrapped = mock_middleware

    auth_context.is_authorization_enabled = False

    ret = wrapped(auth_context.request, db)

    assert ret is mock_handler.return_value

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is None

    assert len(cast(MagicMock, auth_context.inject).mock_calls) == 2


def test_auth_middleware_invalid_request(
    db: tft.artemis.db.DB,
    auth_context: AuthContext,
    mock_middleware: Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]
) -> None:
    mock_handler, wrapped = mock_middleware

    auth_context.is_invalid_request = True

    with pytest.raises(tft.artemis.api.errors.BadRequestError):
        wrapped(auth_context.request, db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is True
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is None

    assert len(cast(MagicMock, auth_context.inject).mock_calls) == 2


@pytest.mark.skip('Enable when authentication becomes mandatory')
def test_auth_middleware_require_authentication(
    db: tft.artemis.db.DB,
    auth_context: AuthContext,
    mock_middleware: Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]
) -> None:
    mock_handler, wrapped = mock_middleware

    auth_context.is_invalid_request = True

    with pytest.raises(tft.artemis.api.errors.UnauthorizedError):
        wrapped(auth_context.request, db)

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is True
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is False
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is None

    assert len(cast(MagicMock, auth_context.inject).mock_calls) == 2


def test_auth_middleware_full(
    db: tft.artemis.db.DB,
    auth_context: AuthContext,
    mock_middleware: Tuple[MagicMock, Callable[[molten.Request, tft.artemis.db.DB], Any]]
) -> None:
    mock_handler, wrapped = mock_middleware

    auth_context.is_authorized = True

    ret = wrapped(auth_context.request, db)

    assert ret is mock_handler.return_value

    assert auth_context.is_empty is True
    assert auth_context.is_invalid_request is False
    assert auth_context.is_authenticated is False
    assert auth_context.is_authorized is True
    assert auth_context.username is None
    assert auth_context.token is None
    assert auth_context.user is None

    assert len(cast(MagicMock, auth_context.inject).mock_calls) == 2
