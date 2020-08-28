import json

from molten import HTTP_200, Response
from molten.app import BaseApp
from molten.openapi.handlers import OpenAPIHandler as handler


# This custom handler was implemented to replace molten.openapi.handlers.OpenAPIHandler, which returns dict instead of
# molten.Response. Ideally, we need every route to return molten.Response (or api.APIResponse) so that we can
# use middleware, that is designed to work with molten.Response, and just stay consistent in general.
class OpenAPIHandler(handler):
    """Dynamically generates and serves OpenAPI v3 documents based on
    the current application object.  Once generated, the document is
    subsequently served from cache.
    """

    def __call__(self, app: BaseApp) -> Response:
        """Generates an OpenAPI v3 document."""
        self.document = handler(
            self.metadata,
            self.security_schemes,
            self.default_security_scheme
        )(app)

        return Response(
            status=HTTP_200,
            content=json.dumps(self.document),
            headers={'Content-Type': 'application/json'}
        )
