""" Secure Digest Authentication Client """
import urllib.request
import urllib.error
import hashlib
import re

def request_protected_resource(url):
    """Attempt to access a resource, handling the Digest Auth challenge."""
    try:
        # Initial unauthenticated request
        urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        # Server responds with 401; intercept the WWW-Authenticate header
        if e.code == 401:
            auth_header = e.headers.get("WWW-Authenticate")
            match = re.search(r'nonce="([^"]+)"', auth_header)
            
            if match:
                nonce = match.group(1)
                
                # Request credentials from the user
                username = input("Username: ")
                password = input("Password: ")

                # Compute the required Digest response
                pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                payload = (username + nonce + pwd_hash).encode()
                response_hash = hashlib.sha256(payload).hexdigest()

                # Build the authenticated request
                req = urllib.request.Request(url)
                digest_val = f'Digest username="{username}", nonce="{nonce}", response="{response_hash}"'
                req.add_header("Authorization", digest_val)

                try:
                    # Attempt retrieval of the page content
                    resp = urllib.request.urlopen(req)
                    print(f"Status Code: {resp.getcode()}") # R5: Show status code
                    print(resp.read().decode())             # R5: Show page content
                except urllib.error.HTTPError as err:
                    print(f"Authentication Failed. Status Code: {err.code}")
        else:
            print(f"Unexpected HTTP Error: {e.code}")
    except Exception as ex:
        print(f"Connection Error: {ex}")

if __name__ == "__main__":
    target_url = input("Enter server URL (e.g., http://127.0.0.1:8080/): ")
    request_protected_resource(target_url)