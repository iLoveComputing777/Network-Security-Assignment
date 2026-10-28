"""
Secure Digest Authentication Client (Looping with Lockout Retry)
Satisfies Requirement R5.
"""
import urllib.request
import urllib.error
import hashlib
import re

def request_protected_resource(url):
    """Attempt to access a resource, looping upon Digest Auth challenges."""
    # Start with an unauthenticated request to trigger the first 401
    req = urllib.request.Request(url)
    
    while True:
        try:
            # Attempt retrieval of the page content
            resp = urllib.request.urlopen(req)
            print(f"\nStatus Code: {resp.getcode()} OK") 
            print(resp.read().decode())             
            break # Success! Exit the loop.
            
        except urllib.error.HTTPError as e:
            # R5: Server responds with 401; intercept the WWW-Authenticate header
            if e.code == 401:
                auth_header = e.headers.get("WWW-Authenticate", "")
                match = re.search(r'nonce="([^"]+)"', auth_header)
                
                if match:
                    nonce = match.group(1)
                    print("\n[!] Authentication required.")
                    
                    # R5: Request credentials from the user
                    username = input("Username: ")
                    password = input("Password: ")

                    # Compute the required Digest response
                    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                    payload = (username + nonce + pwd_hash).encode()
                    response_hash = hashlib.sha256(payload).hexdigest()

                    # Build the authenticated request for the next iteration of the loop
                    req = urllib.request.Request(url)
                    digest_val = f'Digest username="{username}", nonce="{nonce}", response="{response_hash}"'
                    req.add_header("Authorization", digest_val)
                else:
                    print("\nError: No nonce found in 401 response.")
                    break
                    
            elif e.code == 429:
                # Catch the lockout, print the error, but DO NOT break the loop
                retry_after = e.headers.get("Retry-After", "30")
                print(f"\n[!] Error: Password entered incorrectly too many times, {retry_after} sec lockout.")
                
                # Reset to an unauthenticated request. The next loop will hit a 401 and prompt the user again.
                req = urllib.request.Request(url)
                
            else:
                print(f"\nUnexpected HTTP Error: {e.code}")
                break
        except Exception as ex:
            print(f"\nConnection Error: {ex}")
            break

if __name__ == "__main__":
    target_url = input("Enter server URL (e.g., http://127.0.0.1:8080/): ")
    request_protected_resource(target_url)