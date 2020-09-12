import json
import re

from molten import Headers, Request, Response
# To make mypy happy when others try `from api.middleware import REQUEST_COUNT`, explicit re-export is needed.
# See https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-no-implicit-reexport
from molten.contrib.prometheus import REQUEST_COUNT as REQUEST_COUNT, REQUESTS_INPROGRESS as REQUESTS_INPROGRESS

from . import errors

from typing import Any, Callable, Optional

NO_AUTH = ["/_docs", "/_schema"]


def authorization_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def middleware(request: Request, authorization: Optional[Headers]) -> Any:
        if request.path not in NO_AUTH:
            if authorization is None or "Basic" not in authorization:
                raise errors.NotAuthorizedError()

            # TODO: check if forbidden
        return handler()
    return middleware


def error_handler_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    def middleware() -> Any:
        try:
            return handler()
        except errors.ArtemisHTTPError as error:
            return Response(
                status=error.status,
                content=json.dumps(error.response),
                headers=error.headers)
    return middleware


def prometheus_middleware(handler: Callable[..., Any]) -> Callable[..., Any]:
    guest_route_pattern = re.compile(r'(/guests/)[a-z0-9-]*(/events)?')

    def middleware(request: Request) -> Any:
        status = "500 Internal Server Error"
        # this is needed so that metrics for each guestname route won't clog up metrics page
        # let's treat all /guest/<guestname> routes as the single one
        path = guest_route_pattern.sub(r'\1GUEST\2', request.path)
        requests_inprogress = REQUESTS_INPROGRESS.labels(request.method, path)
        requests_inprogress.inc()

        try:
            response = handler()
            status = response.status
            return response
        finally:
            requests_inprogress.dec()
            REQUEST_COUNT.labels(request.method, path, status).inc()
    return middleware
