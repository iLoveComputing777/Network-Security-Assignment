from ..common import RequestHandlerABC, RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo
from .. import log
import base64



LOG = log.getLogger("middlewares.digest_auth")


class DigestAuthMiddleware(RequestHandlerABC):
  
    def __init__(self, next: RequestHandler, credentials: dict[str, str]):
        self.next = next
        self.__cred = credentials
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
       

    def __verify_authorization(self, header_value: str):
       

        # Split header scheme and payload (e.g. "Basic dXNlcjpwYXNz")
        auth_type, _, data = header_value.partition(" ")

        # Enforce that authentication scheme must explicitly be "Basic"
        if not data or auth_type != "Digest":
            return False

        # Base64 decode payload string and split username:password credential pair
        # Format after decoding: "username:password"
        username, _, password = (
            base64.b64decode(data).decode("utf-8", "replace").partition(":")
        )

        # Check credential match against configured user directory
        if username in self.__cred and self.__cred[username] == password:
            LOG.debug(f"Digest authentication correct credentials.")
            return True

        LOG.warning(f"Digest authentication incorrect credentials.")
        return False

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        
        handler = DigestAuthMiddleware()
        response = handler(conn_info, request)

        
        
        if "Authorization" in request.headers and self.__verify_authorization(
            request.headers["Authorization"]
        ):
            return self.next(conn_info, request)

        return self.http.status(
            401,
            HeaderContainer({"WWW-Authenticate": 'Digest realm="auth", charset="UTF-8"'}),
        )

