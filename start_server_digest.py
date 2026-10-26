import socket

from py_http_server.middlewares import CompressMiddleware, DigestAuthMiddleware, DefaultMiddleware
from py_http_server.routers import FileRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

import base64
import sys

app_main(
    handler_chain=DefaultMiddleware(
        DigestAuthMiddleware(
            next=FileRouter("."),
            pwdfile="passwords.txt"
        )
    ),
    http_listeners=[
        TCPAddress("127.0.0.1", 8080),
        TCPAddress("::1", 8080),
    ]
)

def get_basic_auth_header(username: str, password: str) -> str:
    """
    Generates the Basic Authentication header value.
    """
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    return f"Authorization: Basic {encoded_credentials}"


if __name__ == "__main__":

    try:

        # Get user inputs
        host = input("Enter host (e.g., example.com): ").strip()
        path = input("Enter path (e.g., /index.html): ").strip()
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        


        import socket
        # create the socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # connect to the server 65432
            client_socket.connect(('127.0.0.1', 8080)) # <- IP and Port#

            request_lines = [
            
                f"GET {path} HTTP/1.1",
            
                f"Host: {host}",
                "User-Agent: PythonSocketClient/1.0",
                "Accept: */*",
            
                get_basic_auth_header(username, password),
                    "Connection: close",
            
                "",  # Empty line to indicate end of headers
                ""            
            ]    
            request_data = "\r\n".join(request_lines)

            # send data (converted to bytes)
            message = "Hello, Server!"
            client_socket.sendall(message.encode('utf-8'))
            # receive data / response
            data = client_socket.recv(1024)
            print(f"Received from server: {data.decode('utf-8')}")

            # Send request
            client_socket.sendall(request_data.encode())

            # Receive response
            response_chunks = []
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response_chunks.append(chunk)
            response = b"".join(response_chunks).decode(errors="replace")
            print("=== HTTP Response ===")
            print(response)

        finally:
            # close socket to free OS resources
            client_socket.close()

        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
                


    


