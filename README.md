# Network-Security-Assignment

# It seems like a lot but just focus on the following files

# Main folder
# Basic_client.py
# Basic_server.py
# Start_server_digest.py
# Start_server_subverted.py
# Client.py
# Client_subverted.py

# Go inside py_http_server folder and into the middlewares folder
# digest_auth.py
# digest_auth_subverted.py

# You may want to look at basic_auth.py for reference but we gotta figure out how to do digest authentication (lab 2/3)


# R1: The authentication must work with the password file format described in the previous section.
# So just make it work the same way as passwords.txt

# R2: The authentication must produce an HTTP 200 OK response with the page content whenever an 'Authorization' header is provided with a correct username and password pair. 
# Look in basic_auth.py and try to implement it as digest authentication

# In addition, your secure authentication must satisfy the following requirement:
# R3: The authentication must produce an HTTP 401 UNAUTHORIZED response if the 'Authorization' header is missing or provided with an invalid username and password pair,
# Look in basic_auth.py and try to implement it as digest authentication

# and your subverted authentication must satisfy the following requirement:
# R4: The authentication must produce an HTTP 200 OK response with the page content whenever the backdoor is used allowing to authenticate as any user.
# This is the "flaw" that we need to add, it must allow us into the website if we do the vulnerability

# Finally, your secure and subverted clients must satisfy the following requirement:
# R5: The client must request credentials (username and password) from the user, attempt to retrieve the page content, and show the response status code.