from typing import Any, Dict, Optional
from molten import HTTP_409, HTTP_404, HTTP_401, HTTP_403, HTTP_400, HTTP_500, Request
from molten.errors import HTTPError

from artemis import gluetool_sentry


def get_tags_from_request(request: Optional[Request] = None) -> Dict[str, Any]:

    if not request:
        return {}

    return {
        'request_method': request.method,
        'request_path': request.path,
        'request_params': request.params,
        'request_host': request.host
    }


class ArtemisHTTPError(HTTPError):
    def __init__(
        self,
        status: str,
        response: Any = None,
        headers: Any = None,
        request: Optional[Request] = None
    ) -> None:
        self.request = request
        gluetool_sentry.submit_message(
            '{}: {}'.format(
                status if status else 'No HTTP status',
                response.get('message', '<no response message>') if response else '<no response>',
            ),
            tags=get_tags_from_request(request)
        )
        super().__init__(status=status, response=response, headers=headers)


class GenericError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(
            status=HTTP_500,
            response={
                'message': 'Unknown error'
            },
            headers=headers,
            request=request
        )


class BadRequestError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(
            status=HTTP_400,
            response={
                'message': 'Bad Request'
            },
            headers=headers,
            request=request
        )


class NoSuchEntityError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(
            status=HTTP_404,
            response={
                'message': 'No such entity'
            },
            headers=headers,
            request=request
        )


class NonUniqueValidationError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_409,
                         response={"message": "Object already exists"},
                         headers=headers,
                         request=request)


class ForeignKeyValidationError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Foreign key constraint failed"},
                         headers=headers,
                         request=request)


class RequiredValidationError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Required fields can't be null"},
                         headers=headers,
                         request=request)


class SchemaValidationError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Request doesn't match the API schema"},
                         headers=headers,
                         request=request)


class NotAuthorizedError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_401,
                         response={"message": "Not authorized to perform this action"},
                         headers=headers,
                         request=request)


class ForbiddenError(ArtemisHTTPError):
    def __init__(self, headers: Any = None, request: Optional[Request] = None) -> None:
        super().__init__(status=HTTP_403,
                         response={"message": "Not authorized to perform this action"},
                         headers=headers,
                         request=request)
