from typing import Any, Dict, Optional, Union

import gluetool.log
import molten.http.query_params
from molten import HTTP_400, HTTP_401, HTTP_403, HTTP_404, HTTP_409, HTTP_500, Request
from molten.errors import HTTPError

from .. import Failure, FailureDetailsType, get_logger


def get_failure_details_from_request(request: Optional[Request]) -> Dict[str, Any]:
    """
    Extract interesting bits from the given request. We plan to use them as :py:class:`Failure` details when
    reporting HTTP error as a failure.
    """

    if not request:
        return {}

    # Request params are dict-like, but not a dict alone which makes it harder for our YAML-ish logging
    # to represent them as strings. To overcome this difficulty, help our logging until it gets smarter.
    if request.params is None:
        serialized_params: Optional[Union[str, Dict[str, str]]] = None

    elif isinstance(request.params, (dict, molten.http.query_params.QueryParams)):
        serialized_params = dict(request.params)

    else:
        serialized_params = str(request.params)

    return {
        'api_request_method': request.method,
        'api_request_path': request.path,
        'api_request_params': serialized_params,
        'api_request_host': request.host
    }


# There will be a lot of copy paste when it comes to parameters of `__init__` methods. I'd love to replace
# all the parameters with `*kwargs`, but at that moment mypy would lost track of types. It would be possible
# to `raise BadRequestError(caused_by='this should have been a failure instance')`, and mypy wouldn't spot
# the error. As soon as mypy gives me tools smart enough to protect me from the errors like this, I'll be
# happy to use them.
class ArtemisHTTPError(HTTPError):
    def __init__(
        self,
        *,
        status: str,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        report_as_failure: bool = True,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        """
        Base class for our custom HTTP errors. Provides one interface to reporting issues via HTTP responses
        and takes care of proper reporting if needed.

        :param status: HTTP status code as provided by :py:mod:`molten`.
        :param message: a message to include in the response body. It is ignored if ``response`` is specified.
        :param response: a JSON representing the body of the response. If not specified, an empty mapping is used.
        :param headers: mapping with additional or custom HTTP headers to include in the response.
        :param request: request whose handling lead to the error.
        :param report_as_failure: if set, an ad-hoc :py:class:`Failure` and logged.
        :param logger: logger to use for logging.
        :param caused_by: a :py:class:`Failure` instance representing the cause of the error.
        :param failure_details: additional details for the ad-hoc :py:class:`Failure` created when
            ``report_as_failure`` was set.
        """

        if response is not None:
            pass

        elif message is not None:
            response = {
                'message': message
            }

        else:
            response = {}

        super().__init__(status=status, response=response, headers=headers)

        if report_as_failure:
            details = {}

            if failure_details:
                details.update(failure_details)

            details.update(get_failure_details_from_request(request))

            Failure(
                'API error',
                caused_by=caused_by,
                api_response_status=status,
                api_response_payload=response,
                **details
            ).handle(logger or get_logger())


class InternalServerError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'Unknown error'

        super().__init__(
            status=HTTP_500,
            message=message,
            response=response,
            headers=headers,
            request=request,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )


class BadRequestError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'Bad request'

        super().__init__(
            status=HTTP_400,
            message=message,
            response=response,
            headers=headers,
            request=request,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )


class NoSuchEntityError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'No such entity'

        super().__init__(
            status=HTTP_404,
            message=message,
            response=response,
            headers=headers,
            request=request,
            report_as_failure=False,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )


class UnauthorizedError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'Not authorized to perform this action'

        super().__init__(
            status=HTTP_401,
            message=message,
            response=response,
            headers=headers,
            request=request,
            report_as_failure=False,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )


class ForbiddenError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'Not authorized to perform this action'

        super().__init__(
            status=HTTP_403,
            message=message,
            response=response,
            headers=headers,
            request=request,
            report_as_failure=False,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )


class ConflictError(ArtemisHTTPError):
    def __init__(
        self,
        *,
        message: Optional[str] = None,
        response: Optional[Any] = None,
        headers: Optional[Any] = None,
        request: Optional[Request] = None,
        logger: Optional[gluetool.log.ContextAdapter] = None,
        caused_by: Optional[Failure] = None,
        failure_details: Optional[FailureDetailsType] = None
    ) -> None:
        if not message and not response:
            message = 'Request conflicts with the current state of the resource'

        super().__init__(
            status=HTTP_409,
            message=message,
            response=response,
            headers=headers,
            request=request,
            report_as_failure=False,
            logger=logger,
            caused_by=caused_by,
            failure_details=failure_details
        )
