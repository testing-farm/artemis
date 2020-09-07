import requests
import tft.praxis

from tft.praxis import Logger, fetch_remote

from typing import Any, Dict, Optional


class Configuration(tft.praxis.Configuration):
    pass


def fetch_artemis(
    cfg: Configuration,
    endpoint: str,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    logger: Optional[Logger] = None
) -> requests.Response:
    assert cfg.artemis_api_url is not None

    if not logger:
        logger = Logger()

    def _error_callback(res: requests.Response, request_kwargs) -> None:
        assert logger is not None

        logger.error(f"""
Failed to communicate with Artemis API Server, responded with code {res.status_code}: {res.reson}

Request:
  {res.request.url}

  {request_kwargs}
""")

    return fetch_remote(
        f'{cfg.artemis_api_url}/{endpoint}',
        logger=logger,
        method=method,
        request_kwargs=request_kwargs,
        on_error=_error_callback
    )


def artemis_inspect(cfg, resource, rid, params=None, data=None, logger=None):
    return fetch_artemis(
        cfg,
        f'/{resource}/{rid}',
        request_kwargs={
            'json': data,
            'params': params
        }
    )


def artemis_create(cfg, resource, data, logger=None):
    return fetch_artemis(
        cfg,
        f'/{resource}',
        method='post',
        request_kwargs={
            'json': data
        }
    )


def artemis_delete(
    cfg,
    resource,
    rid,
    logger=None
):
    return fetch_artemis(cfg, f'{resource}/{rid}', method='delete', logger=None)
