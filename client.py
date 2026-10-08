# You must also provide a simple client that can retrieve the files and resources protected by the
# authentication, requesting the username and password to the user. This should be implemented as
# 'client.py' and 'client_subverted.py'. You can use modules and classes from the server to
# help with HTTP parsing, but you cannot modify them (the server files)."


import socket

HOST = '127.0.0.1'
PORT = 65432

def start_client():
    # AF_INET = IPv4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # connect to IP and port
        client_socket.connect((HOST, PORT))
        
        # send a simple hello message (that the server will return back to us)
        message = "Hello, World!"
        print(f"Sending: {message}")
        client_socket.sendall(message.encode('utf-8'))
        
        # wait to receive the response
        data = client_socket.recv(1024)
        print(f"Received back: {data.decode('utf-8')}")

if __name__ == '__main__':
    start_client()