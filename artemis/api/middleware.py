import json

from molten import Headers, Request, Response
from artemis.api import errors
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
