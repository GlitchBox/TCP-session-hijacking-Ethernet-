#!/usr/bin/env python3

import socket
import sys

HOST = sys.argv[1]  # The server's hostname or IP address
PORT = int(sys.argv[2])        # The port used by the server

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s=socket.bind("")
s.connect((HOST, PORT))
s.sendall(b'hello server')
while True:
    # data = input()
    # bdata = bytes(data,"utf-8")
    # s.sendall(bdata)
    data = s.recv(1024)
    print('Received: ', repr(data))
    s.sendall(b'hello server')
