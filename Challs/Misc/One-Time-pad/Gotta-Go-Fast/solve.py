#!/usr/bin/env python3

# TL;DR:
# The server "OTP" key is just SHA256(current Unix time in seconds).
# That means the key is totally predictable if we know roughly when
# the flag was encrypted. So we grab the encrypted flag, brute-force
# timestamps around the current time, regenerate the key for each one,
# XOR it with the ciphertext, and look for something that starts with
# "crypto{". When we see it, we win.

import socket
import json
import time
import hashlib
from Crypto.Util.number import long_to_bytes

HOST = "socket.cryptohack.org"
PORT = 13372

# Helper function to send JSON and receive response
def send_json(sock, data):
    sock.send((json.dumps(data) + "\n").encode())
    return json.loads(sock.recv(4096).decode())

# Connect to remote challenge
sock = socket.socket()
sock.connect((HOST, PORT))

# Receive banner
print(sock.recv(1024).decode())

# Step 1: Request encrypted flag
response = send_json(sock, {"option": "get_flag"})
encrypted_flag_hex = response["encrypted_flag"]
ciphertext = bytes.fromhex(encrypted_flag_hex)

print(f"[+] Encrypted flag: {encrypted_flag_hex}")

# Step 2: Brute force timestamps near current time
current_time = int(time.time())

print("[*] Brute forcing timestamps...")

for t in range(current_time - 10, current_time + 10):
    # Recreate key = SHA256(timestamp)
    key = hashlib.sha256(long_to_bytes(t)).digest()

    # Decrypt via XOR
    plaintext = bytes([ciphertext[i] ^ key[i] for i in range(len(ciphertext))])

    # Check if it looks like a flag
    if b"crypto{" in plaintext:
        print(f"[+] Found correct timestamp: {t}")
        print(f"[+] Flag: {plaintext.decode()}")
        break

sock.close()
