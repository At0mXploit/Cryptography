#!/usr/bin/env python3

# TL;DR:
# The OTP is random BUT it never contains 0x00.
# That means ciphertext[i] can never equal FLAG[i].
#
# So for each byte position:
# ciphertext values will eventually take every possible value
# EXCEPT the real flag byte.
#
# We just collect ciphertexts repeatedly.
# For each position, once we've seen 255 different values,
# the only missing value in 0..255 must be the flag byte.
#
# We speed things up by only tracking the unknown part of:
# crypto{????????????}
# Since we already know the prefix and suffix.

import socket
import json
import base64

HOST = "socket.cryptohack.org"
PORT = 13370

def send_json(sock, data):
    sock.send((json.dumps(data) + "\n").encode())
    return json.loads(sock.recv(4096).decode())

sock = socket.socket()
sock.connect((HOST, PORT))

print(sock.recv(1024).decode())

flag_length = 20

# Known parts of the flag
known_prefix = b"crypto{"
known_suffix = b"}"

# Unknown positions are 7 through 18
unknown_indices = list(range(7, 19))

# Track seen ciphertext byte values only for unknown positions
seen = {i: set() for i in unknown_indices}

print("[*] Collecting ciphertexts (tracking only unknown bytes)...")

count = 0

while True:
    count += 1

    response = send_json(sock, {"msg": "request"})
    if "ciphertext" not in response:
        continue

    ct = base64.b64decode(response["ciphertext"])

    for i in unknown_indices:
        seen[i].add(ct[i])

    # Print progress occasionally
    if count % 500 == 0:
        print(f"[+] {count} requests sent...")

    # Stop once every unknown position has seen 255 values
    if all(len(seen[i]) == 255 for i in unknown_indices):
        break

print(f"[+] Done after {count} requests")
print("[+] Recovering flag...")

flag_bytes = bytearray(flag_length)

# Fill known parts
flag_bytes[:7] = known_prefix
flag_bytes[-1:] = known_suffix

# Recover unknown bytes
for i in unknown_indices:
    all_bytes = set(range(256))
    missing = list(all_bytes - seen[i])
    flag_bytes[i] = missing[0]

print("[+] Flag:", flag_bytes.decode())

sock.close()
