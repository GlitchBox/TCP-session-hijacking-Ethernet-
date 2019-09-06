#!/usr/bin/env python3

import socket
import sys

HOST = sys.argv[1]  # Standard loopback interface address (localhost)
PORT = int(sys.argv[2])        # Port to listen on (non-privileged ports are > 1023)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()
print('Connected by', addr)
while True:
    data = conn.recv(1024)
    print(repr(data))
    dataToSend = input()
    conn.sendall(data)
