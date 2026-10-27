""" Secure Digest Authentication Middleware """
import os
import hashlib
import hmac
from py_http_server.http.response import HTTPResponse
from py_http_server.http.response_body import ResponseBody

class DigestAuthMiddleware:
    def __init__(self, next, pwdfile="passwords.txt"):
        """Initialize the middleware and load the user database."""
        self.next = next
        self.pwdfile = pwdfile
        self.passwords = self._load_passwords()
        self.active_nonces = set()

    def _load_passwords(self):
        """Parse passwords.txt into a dictionary of {username: sha256_hash}."""
        creds = {}
        try:
            with open(self.pwdfile, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        user, pwd_hash = line.split(':', 1)
                        creds[user] = pwd_hash
        except FileNotFoundError:
            pass
        return creds

    def __call__(self, conn_info, request):
        """Intercept the request and validate the Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header.startswith("Digest "):
            return self._require_auth()

        auth_str = auth_header[7:]
        auth_dict = {
            k.strip(): v.strip(' "') 
            for item in auth_str.split(",") 
            if "=" in item for k, v in [item.split("=", 1)]
        }

        username = auth_dict.get("username")
        nonce = auth_dict.get("nonce")
        client_response = auth_dict.get("response")

        if not all([username, nonce, client_response]):
            return self._require_auth()

        if username not in self.passwords or nonce not in self.active_nonces:
            return self._require_auth()

        stored_hash = self.passwords[username]
        payload = (username + nonce + stored_hash).encode()
        expected_response = hashlib.sha256(payload).hexdigest()

        if hmac.compare_digest(expected_response, client_response):
            self.active_nonces.remove(nonce)
            # Pass both arguments to the next handler
            return self.next(conn_info, request)
        else:
            return self._require_auth()

    def _require_auth(self):
        """Generate a 401 response with a new server nonce."""
        new_nonce = os.urandom(16).hex()
        self.active_nonces.add(new_nonce)
        headers = {
            "WWW-Authenticate": f'Digest realm="Restricted Area", nonce="{new_nonce}"'
        }
        
        # Use the static method to generate the body object from bytes
        body = ResponseBody.from_bytes(b"401 Unauthorized")
        return HTTPResponse(401, headers, body)