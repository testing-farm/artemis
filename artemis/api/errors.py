from typing import Any
from molten import HTTP_409, HTTP_404, HTTP_401, HTTP_403, HTTP_400, HTTP_500
from molten.errors import HTTPError


class GenericError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(
            status=HTTP_500,
            response={
                'message': 'Unknown error'
            },
            headers=headers
        )


class NoSuchEntityError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(
            status=HTTP_404,
            response={
                'message': 'No such entity'
            },
            headers=headers
        )


class NonUniqueValidationError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_409,
                         response={"message": "Object already exists"},
                         headers=headers)


class ForeignKeyValidationError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Foreign key constraint failed"},
                         headers=headers)


class RequiredValidationError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Required fields can't be null"},
                         headers=headers)


class SchemaValidationError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_400,
                         response={"message": "Request doesn't match the API schema"},
                         headers=headers)


class NotAuthorizedError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_401,
                         response={"message": "Not authorized to perform this action"},
                         headers=headers)


class ForbiddenError(HTTPError):
    def __init__(self, headers: Any = None) -> None:
        super().__init__(status=HTTP_403,
                         response={"message": "Not authorized to perform this action"},
                         headers=headers)
