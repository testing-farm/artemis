from typing import Any, Dict, List, Optional

import requests

from . import Configuration, fetch_remote


def fetch_artemis(
    cfg: Configuration,
    endpoint: str,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:
    assert cfg.artemis_api_url is not None

    logger = cfg.logger

    def _error_callback(res: requests.Response, request_kwargs: Dict[str, Any]) -> None:
        assert logger is not None

        logger.error(
            'Failed to communicate with Artemis API Server, responded with code {}: {}'
            '\nRequest:\n{}\n{}'.format(res.status_code, res.reason, res.request.url, request_kwargs)
        )

    if cfg.authentication_method == 'basic':
        from requests.auth import HTTPBasicAuth

        assert cfg.basic_auth is not None

        if request_kwargs is None:
            request_kwargs = {}

        request_kwargs['auth'] = HTTPBasicAuth(
            cfg.basic_auth.username,
            # TODO: pick proper token based on URL
            cfg.basic_auth.provisioning_token
        )

    return fetch_remote(
        cfg,
        '{}/{}'.format(cfg.artemis_api_url, endpoint),
        logger,
        method=method,
        request_kwargs=request_kwargs,
        on_error=_error_callback,
        allow_statuses=allow_statuses
    )


def api_inspect(
    cfg: Configuration,
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:
    request_kwargs: Dict[str, Any] = {}

    if data is not None:
        request_kwargs['json'] = data

    if params is not None:
        request_kwargs['params'] = params

    return fetch_artemis(
        cfg,
        endpoint,
        request_kwargs=request_kwargs,
        allow_statuses=allow_statuses
    )


def api_inspect_guest(
    cfg: Configuration,
    guestname: Optional[str] = None
) -> requests.Response:
    if guestname is None:
        return api_inspect(cfg, '/guests/')

    return api_inspect(cfg, f'/guests/{guestname}')


def api_inspect_snapshot(
    cfg: Configuration,
    guestname: str,
    snapshotname: str
) -> requests.Response:
    return api_inspect(cfg, f'/guests/{guestname}/snapshots/{snapshotname}')


def api_inspect_events(
    cfg: Configuration,
    guestname: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None
) -> requests.Response:
    if guestname is None:
        return api_inspect(cfg, '/events', params=params)

    return api_inspect(cfg, f'/guests/{guestname}/events', params=params)


def api_inspect_knob(
    cfg: Configuration,
    knobname: Optional[str] = None
) -> requests.Response:
    if knobname is None:
        return api_inspect(cfg, '/knobs/')

    return api_inspect(cfg, f'/knobs/{knobname}')


def api_inspect_user(
    cfg: Configuration,
    username: Optional[str] = None
) -> requests.Response:
    if username is None:
        return api_inspect(cfg, '/users/')

    return api_inspect(cfg, f'/users/{username}')


def api_create(
    cfg: Configuration,
    endpoint: str,
    data: Optional[Dict[str, Any]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:
    request_kwargs: Dict[str, Any] = {}

    if data is not None:
        request_kwargs['json'] = data

    return fetch_artemis(
        cfg,
        endpoint,
        method='post',
        request_kwargs=request_kwargs,
        allow_statuses=allow_statuses
    )


def api_create_guest(
    cfg: Configuration,
    data: Dict[str, Any]
) -> requests.Response:
    return api_create(cfg, '/guests/', data=data)


def api_create_snapshot(
    cfg: Configuration,
    guestname: str,
    data: Dict[str, Any]
) -> requests.Response:
    return api_create(cfg, f'/guests/{guestname}/snapshots/', data=data)


def api_restore_snapshot(
    cfg: Configuration,
    guestname: str,
    snapshotname: str
) -> requests.Response:
    return api_create(cfg, f'/guests/{guestname}/snapshots/{snapshotname}')


def api_create_user(
    cfg: Configuration,
    username: str,
    data: Dict[str, Any]
) -> requests.Response:
    return api_create(cfg, f'/users/{username}', data=data)


def api_create_user_token(
    cfg: Configuration,
    username: str,
    tokentype: str
) -> requests.Response:
    return api_create(cfg, f'/users/{username}/tokens/{tokentype}/reset')


def api_update(
    cfg: Configuration,
    endpoint: str,
    data: Dict[str, Any]
) -> requests.Response:
    request_kwargs: Dict[str, Any] = {}

    if data is not None:
        request_kwargs['json'] = data

    return fetch_artemis(
        cfg,
        endpoint,
        method='put',
        request_kwargs=request_kwargs
    )


def api_update_knob(
    cfg: Configuration,
    knobname: str,
    data: Dict[str, Any]
) -> requests.Response:
    return api_update(cfg, f'/knobs/{knobname}', data)


def api_delete(
    cfg: Configuration,
    endpoint: str
) -> requests.Response:
    return fetch_artemis(
        cfg,
        endpoint,
        method='delete',
        allow_statuses=[200, 201, 204, 404, 409]
    )


def api_delete_guest(cfg: Configuration, guestname: str) -> requests.Response:
    return api_delete(cfg, f'/guests/{guestname}')


def api_delete_snapshot(cfg: Configuration, guestname: str, snapshotname: str) -> requests.Response:
    return api_delete(cfg, f'/guests/{guestname}/{snapshotname}')


def api_delete_knob(cfg: Configuration, knobname: str) -> requests.Response:
    return api_delete(cfg, f'/knobs/{knobname}')


def api_delete_user(cfg: Configuration, username: str) -> requests.Response:
    return api_delete(cfg, f'/users/{username}')


def api_inspect_console_log(
    cfg: Configuration,
    guestname: str
) -> requests.Response:
    return api_inspect(cfg, f'/guests/{guestname}/console/url')


def api_create_guest_log(cfg: Configuration, guestname: str, logname: str, contenttype: str) -> requests.Response:
    return api_create(
        cfg,
        f'/guests/{guestname}/logs/{logname}/{contenttype}',
        allow_statuses=[202]
    )


def api_inspect_guest_log(cfg: Configuration, guestname: str, logname: str, contenttype: str) -> requests.Response:
    return api_inspect(
        cfg,
        f'/guests/{guestname}/logs/{logname}/{contenttype}',
        allow_statuses=[200, 404, 409]
    )
