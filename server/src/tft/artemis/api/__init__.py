# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
import os
import platform
import shutil
import sys
from typing import Any, List, NoReturn, Optional, Sequence, cast

import fastapi
import gluetool.log
import gluetool.utils
import uvicorn.config
import uvicorn.workers
from fastapi import FastAPI
from gluetool.result import Ok
from starlette.middleware import Middleware
from starlette.responses import RedirectResponse

from .. import get_logger, metrics
from ..knobs import KNOB_LOGGING_JSON, KNOB_WORKER_PROCESS_METRICS_ENABLED, KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK, \
    Knob
from ..script import hook_engine
from . import environment
from .middleware import AuthorizationMiddleware, ErrorHandlerMiddleware, PrometheusMiddleware, RSSWatcherMiddleware
from .routers import define_openapi_schema

KNOB_API_PROCESSES: Knob[int] = Knob(
    'api.processes',
    'Number of processes to spawn for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_PROCESSES',
    cast_from_str=int,
    default=1
)

KNOB_API_THREADS: Knob[int] = Knob(
    'api.threads',
    'Number of threads to spawn in each process for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_THREADS',
    cast_from_str=int,
    default=1
)

KNOB_API_ENABLE_PROFILING: Knob[bool] = Knob(
    'api.profiling.enabled',
    'If enabled, API server will profile handling of each request, emitting a summary into log.',
    has_db=False,
    envvar='ARTEMIS_API_ENABLE_PROFILING',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_PROFILE_LIMIT: Knob[int] = Knob(
    'api.profiling.limit',
    'How many functions should be included in the summary.',
    has_db=False,
    envvar='ARTEMIS_API_PROFILING_LIMIT',
    cast_from_str=int,
    default=20
)

KNOB_API_ENGINE_RELOAD_ON_CHANGE: Knob[bool] = Knob(
    'api.engine.reload-on-change',
    'Reload API server when its code changes.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_ON_CHANGE',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_ENGINE_DEBUG: Knob[bool] = Knob(
    'api.engine.debug',
    'Run engine with a debugging enabled.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_DEBUG',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS: Knob[int] = Knob(
    'api.engine.reload.request-limit',
    'Reload a worker process after serving this number of requests.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT',
    cast_from_str=int,
    default=0
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD: Knob[int] = Knob(
    'api.engine.reload.request-limit.spread',
    'A range by which is number of requests randomized.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT_SPREAD',
    cast_from_str=int,
    default=0
)


def generate_redirects(app: fastapi.FastAPI, api_version: str, routes: List[fastapi.routing.APIRoute],
                       redirects: List[str]) -> None:
    async def _redirect_endpoint_current(request: fastapi.Request) -> RedirectResponse:
        to_url = request.url.path.replace('current', api_version, 1)
        return RedirectResponse(to_url, status_code=308)

    async def _redirect_endpoint_toplevel(request: fastapi.Request) -> RedirectResponse:
        to_url = f'/{api_version}{request.url.path}'
        return RedirectResponse(to_url, status_code=308)

    api_version_prefix = f'/{api_version}'

    for redirect in redirects:
        for route in routes:
            url_rest = route.path.lstrip(api_version_prefix).rstrip('/')

            if redirect == 'toplevel':
                app.add_api_route(f'/{url_rest}', endpoint=_redirect_endpoint_toplevel, methods=list(route.methods))
            elif redirect == 'current':
                app.add_api_route(f'/{redirect}/{url_rest}', endpoint=_redirect_endpoint_current,
                                  methods=list(route.methods))


def _create_app(
    middlewares: Optional[Sequence[Middleware]] = None, dependencies: Optional[Sequence[Any]] = None
) -> fastapi.FastAPI:
    app = FastAPI(
        middleware=middlewares or [],
        dependencies=dependencies or [],
    )

    # TBD All api versions that are compatible should be taken from environment.API_MILESTONES
    for api_version, _ in environment.API_MILESTONES:
        # Each api version will be a separate application that will be mounted. This way we'll get separate docs for
        # each version
        subapi = FastAPI(docs_url='/_docs', openapi_url='/_schema')
        api_module_name = api_version.replace('.', '_')
        api_module = importlib.import_module(f'.routers.{api_module_name}', __name__)
        api_module.register_routes(subapi)
        app.mount(f'/{api_version}', subapi)

        # add possible redirects are added here
        generate_redirects(app, api_version, cast(List[fastapi.routing.APIRoute], subapi.routes),
                           environment.get_redirects(api_version))

    # This should be called after all possible redirects have been generated
    define_openapi_schema(app)
    return app


def run_app() -> fastapi.FastAPI:
    # Load routing hook to populate our list of knobs with those created dynamicaly for custom policies - the hook
    # is loaded by workers, but those are completely different processes, therefore they would remain invisible
    # to us.
    logger = get_logger()

    if os.getenv('ARTEMIS_HOOK_ROUTE'):
        r_routing_hook = hook_engine('ROUTE')

        if r_routing_hook.is_error:
            r_routing_hook.unwrap_error().handle(logger)

            sys.exit(1)

    if KNOB_WORKER_PROCESS_METRICS_ENABLED.value is True:
        metrics.WorkerMetrics.spawn_metrics_refresher(  # noqa: F841
            logger,
            f'api-{platform.node()}-{os.getpid()}',
            KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK.value,
            # TODO: try to find out the actual values
            lambda _unused: Ok((1, KNOB_API_THREADS.value))
        )

    mw: List[Middleware] = [
        Middleware(AuthorizationMiddleware),
        Middleware(ErrorHandlerMiddleware),
        Middleware(PrometheusMiddleware),
        Middleware(RSSWatcherMiddleware)
    ]

    return _create_app(middlewares=mw)


class UvicornWorker(uvicorn.workers.UvicornWorker):
    CONFIG_KWARGS = uvicorn.workers.UvicornWorker.CONFIG_KWARGS
    CONFIG_KWARGS['log_config'] = uvicorn.config.LOGGING_CONFIG
    CONFIG_KWARGS['log_config']['formatters']['access']['fmt'] = \
        '[%(asctime)s] [+] [%(process)s] [%(client_addr)s] [%(request_line)s] %(status_code)s'
    CONFIG_KWARGS['log_config']['formatters']['access']['datefmt'] = \
        '%H:%M:%S'


def main() -> NoReturn:
    gunicorn_path = shutil.which('gunicorn')

    if not gunicorn_path:
        raise Exception('No "gunicorn" executable found')

    sys.stdout.flush()
    sys.stderr.flush()

    gunicorn_options: List[str] = []

    if KNOB_API_ENABLE_PROFILING.value is True:
        gunicorn_options += [
            '-c', 'src/tft/artemis/api/wsgi_profiler.py'
        ]

    gunicorn_options += [
        '-k', 'tft.artemis.api.UvicornWorker',
        '--bind', '0.0.0.0:8001',
        '--workers', str(KNOB_API_PROCESSES.value),
        '--threads', str(KNOB_API_THREADS.value),
        '--access-logfile', '-',
        '--error-logfile', '-'
    ]

    if KNOB_API_ENGINE_DEBUG.value is True:
        gunicorn_options += [
            '--log-level', 'debug'
        ]

    if KNOB_API_ENGINE_RELOAD_ON_CHANGE.value is True:
        gunicorn_options += [
            '--reload'
        ]

    # TODO: this does not apply anymore! Since the work is offloaded to Uvicorn worker,
    # we need to modify its logging configuration.
    #
    # See https://docs.gunicorn.org/en/stable/settings.html#access-log-format
    if KNOB_LOGGING_JSON.value is True:
        gunicorn_options += [
            '--access-logformat',
            json.dumps({
                'client': '%(h)s',
                'request_method': '%(m)s',
                'request_path': '%(U)s',
                'request_query_string': '%(q)s',
                'request_status_line': '%(r)s',
                'request_user_agent': '%(a)s',
                'response_code': '%(s)s',
                'response_length': '%(B)s',
                'duration': '%(D)s'
            })
        ]

    if KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value != 0:
        gunicorn_options += [
            '--max-requests', str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value),
            '--max-requests-jitter', str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD.value)
        ]

    os.execve(
        gunicorn_path,
        [
            'gunicorn'
        ] + gunicorn_options + [
            'tft.artemis.api:run_app()'
        ],
        os.environ
    )


if __name__ == '__main__':
    main()
