#!/usr/bin/env python3
"""
Simple solution for Collider challenge
Using known MD5 collision pair to get the flag
"""

import socket
import json

# Known MD5 collision pair (both have hash: 79054025255fb1a26e4bc422aef54eb4)
doc1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
doc2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"

# Connect to server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("socket.cryptohack.org", 13389))

# Receive initial message
print(sock.recv(4096).decode())

# Send first document
sock.send(json.dumps({"document": doc1}).encode() + b'\n')
print(sock.recv(4096).decode())

# Send second document (different but same hash)
sock.send(json.dumps({"document": doc2}).encode() + b'\n')
response = sock.recv(4096).decode()
print(response)

sock.close()
