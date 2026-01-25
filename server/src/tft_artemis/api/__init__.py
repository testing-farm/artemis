# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import importlib
import json
import os
import platform
import re
import shutil
import sys
from collections.abc import Sequence
from typing import Any, NoReturn, Optional, cast

import fastapi
import gluetool.log
import gluetool.utils
import uvicorn.config
import uvicorn.workers
from fastapi import FastAPI
from gluetool.result import Ok
from starlette.middleware import Middleware
from starlette.responses import RedirectResponse

from .. import Failure, get_logger, metrics
from ..knobs import (
    KNOB_LOGGING_JSON,
    KNOB_TRACING_ENABLED,
    KNOB_WORKER_PROCESS_METRICS_ENABLED,
    KNOB_WORKER_PROCESS_METRICS_UPDATE_TICK,
    Knob,
)
from ..script import hook_engine
from . import environment
from .middleware import MIDDLEWARE, ErrorHandlerMiddleware, ProfileMiddleware, TracingMiddleware
from .routers import define_openapi_schema

KNOB_API_ENGINE: Knob[str] = Knob(
    'api.engine',
    'Which engine to user for API server, gunicorn or uvicorn.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE',
    cast_from_str=str,
    default='gunicorn',
)

KNOB_API_PROCESSES: Knob[int] = Knob(
    'api.processes',
    'Number of processes to spawn for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_PROCESSES',
    cast_from_str=int,
    default=1,
)

KNOB_API_THREADS: Knob[int] = Knob(
    'api.threads',
    'Number of threads to spawn in each process for servicing API requests.',
    has_db=False,
    envvar='ARTEMIS_API_THREADS',
    cast_from_str=int,
    default=1,
)

KNOB_API_MIDDLEWARE: Knob[str] = Knob(
    'api.middleware',
    'Comma-separated list of API middleware, in order in which they should be enabled.',
    has_db=False,
    envvar='ARTEMIS_API_MIDDLEWARE',
    cast_from_str=str,
    default='request-cancelled,authorization,prometheus,rss-watcher',
)

KNOB_API_ENABLE_PROFILING: Knob[bool] = Knob(
    'api.profiling.enabled',
    'If enabled, API server will profile handling of each request, emitting a summary into log.',
    has_db=False,
    envvar='ARTEMIS_API_ENABLE_PROFILING',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False,
)

KNOB_API_VERBOSE_PROFILING: Knob[bool] = Knob(
    'api.profiling.verbose',
    'If enabled, API profiling will emit more information about more stack frames.',
    has_db=False,
    envvar='ARTEMIS_API_VERBOSE_PROFILING',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False,
)

KNOB_API_PROFILING_PATH_PATTERN: Knob[str] = Knob(
    'api.profiling.path-pattern',
    'Only requests for paths matching this pattern will be profiled.',
    has_db=False,
    envvar='ARTEMIS_API_PROFILING_PATH_PATTERN',
    cast_from_str=str,
    default=r'.*',
)

KNOB_API_PROFILING_LIMIT: Knob[int] = Knob(
    'api.profiling.limit',
    'How many functions should be included in the summary.',
    has_db=False,
    envvar='ARTEMIS_API_PROFILING_LIMIT',
    cast_from_str=int,
    default=20,
)

KNOB_API_ENGINE_RELOAD_ON_CHANGE: Knob[bool] = Knob(
    'api.engine.reload-on-change',
    'Reload API server when its code changes.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_ON_CHANGE',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False,
)

KNOB_API_ENGINE_DEBUG: Knob[bool] = Knob(
    'api.engine.debug',
    'Run engine with a debugging enabled.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_DEBUG',
    cast_from_str=gluetool.utils.normalize_bool_option,
    default=False,
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS: Knob[int] = Knob(
    'api.engine.reload.request-limit',
    'Reload a worker process after serving this number of requests.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT',
    cast_from_str=int,
    default=0,
)

KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD: Knob[int] = Knob(
    'api.engine.reload.request-limit.spread',
    'A range by which is number of requests randomized.',
    has_db=False,
    envvar='ARTEMIS_API_ENGINE_RELOAD_REQUESTS_LIMIT_SPREAD',
    cast_from_str=int,
    default=0,
)


# Precompile the profiling path pattern
try:
    API_PROFILE_PATH_PATTERN = re.compile(KNOB_API_PROFILING_PATH_PATTERN.value)

except Exception as exc:
    Failure.from_exc(
        'failed to compile ARTEMIS_API_PROFILING_PATH_PATTERN pattern',
        exc,
        pattern=KNOB_API_PROFILING_PATH_PATTERN.value,
    ).handle(get_logger())

    sys.exit(1)


def generate_redirects(
    app: fastapi.FastAPI, api_version: str, routes: list[fastapi.routing.APIRoute], redirects: list[str]
) -> None:
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
                app.add_api_route(
                    f'/{redirect}/{url_rest}', endpoint=_redirect_endpoint_current, methods=list(route.methods)
                )


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
        generate_redirects(
            app,
            api_version,
            cast(list[fastapi.routing.APIRoute], subapi.routes),
            environment.get_redirects(api_version),
        )

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
            lambda _unused: Ok((1, KNOB_API_THREADS.value)),
        )

    mw: list[Middleware] = []

    if KNOB_API_ENABLE_PROFILING.value is True:
        mw += [Middleware(ProfileMiddleware)]

    if KNOB_TRACING_ENABLED.value is True:
        mw += [Middleware(TracingMiddleware)]

    for middleware_name in KNOB_API_MIDDLEWARE.value.split(','):
        middleware_name = middleware_name.strip().lower()

        if not middleware_name:
            continue

        middleware_class = MIDDLEWARE.get(middleware_name)

        if middleware_class is None:
            Failure('unknown API middleware', middleware=middleware_name).handle(logger)

            sys.exit(1)

        mw.append(Middleware(middleware_class))

    mw += [Middleware(ErrorHandlerMiddleware)]

    return _create_app(middlewares=mw)


class UvicornWorker(uvicorn.workers.UvicornWorker):
    CONFIG_KWARGS = uvicorn.workers.UvicornWorker.CONFIG_KWARGS
    CONFIG_KWARGS['log_config'] = uvicorn.config.LOGGING_CONFIG
    CONFIG_KWARGS['log_config']['formatters']['access']['fmt'] = (
        '[%(asctime)s] [+] [%(process)s] [%(client_addr)s] [%(request_line)s] %(status_code)s'
    )
    CONFIG_KWARGS['log_config']['formatters']['access']['datefmt'] = '%H:%M:%S'


def _main_uvicorn() -> NoReturn:
    uvicorn_path = shutil.which('uvicorn')

    if not uvicorn_path:
        raise Exception('No "uvicorn" executable found')

    sys.stdout.flush()
    sys.stderr.flush()

    uvicorn_options: list[str] = []

    uvicorn_options += [
        'tft_artemis.api:run_app',
        '--factory',
        '--host',
        '0.0.0.0',
        '--port',
        '8001',
        '--workers',
        str(KNOB_API_PROCESSES.value),
        '--access-log',
    ]

    if KNOB_API_ENGINE_DEBUG.value is True:
        uvicorn_options += ['--log-level', 'debug']

    if KNOB_API_ENGINE_RELOAD_ON_CHANGE.value is True:
        uvicorn_options += ['--reload']

    if KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value != 0:
        uvicorn_options += [
            '--limit-max-requests',
            str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value),
        ]

    os.execve(uvicorn_path, ['uvicorn', *uvicorn_options], os.environ)


def _main_gunicorn() -> NoReturn:
    gunicorn_path = shutil.which('gunicorn')

    if not gunicorn_path:
        raise Exception('No "gunicorn" executable found')

    gunicorn_options: list[str] = []

    gunicorn_options += [
        '-k',
        'tft_artemis.api.UvicornWorker',
        '--bind',
        '0.0.0.0:8001',
        '--workers',
        str(KNOB_API_PROCESSES.value),
        '--threads',
        str(KNOB_API_THREADS.value),
        '--access-logfile',
        '-',
        '--error-logfile',
        '-',
    ]

    if KNOB_API_ENGINE_DEBUG.value is True:
        gunicorn_options += ['--log-level', 'debug']

    if KNOB_API_ENGINE_RELOAD_ON_CHANGE.value is True:
        gunicorn_options += ['--reload']

    # TODO: this does not apply anymore! Since the work is offloaded to Uvicorn worker,
    # we need to modify its logging configuration.
    #
    # See https://docs.gunicorn.org/en/stable/settings.html#access-log-format
    if KNOB_LOGGING_JSON.value is True:
        gunicorn_options += [
            '--access-logformat',
            json.dumps(
                {
                    'client': '%(h)s',
                    'request_method': '%(m)s',
                    'request_path': '%(U)s',
                    'request_query_string': '%(q)s',
                    'request_status_line': '%(r)s',
                    'request_user_agent': '%(a)s',
                    'response_code': '%(s)s',
                    'response_length': '%(B)s',
                    'duration': '%(D)s',
                }
            ),
        ]

    if KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value != 0:
        gunicorn_options += [
            '--max-requests',
            str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS.value),
            '--max-requests-jitter',
            str(KNOB_API_ENGINE_WORKER_RESTART_REQUESTS_SPREAD.value),
        ]

    os.execve(gunicorn_path, ['gunicorn', *gunicorn_options, 'tft_artemis.api:run_app()'], os.environ)


def main() -> NoReturn:
    sys.stdout.flush()
    sys.stderr.flush()

    if KNOB_API_ENGINE.value == 'gunicorn':
        _main_gunicorn()

    if KNOB_API_ENGINE.value == 'uvicorn':
        _main_uvicorn()

    raise Exception(f'Unknown API engine "{KNOB_API_ENGINE.value}"')


if __name__ == '__main__':
    main()
