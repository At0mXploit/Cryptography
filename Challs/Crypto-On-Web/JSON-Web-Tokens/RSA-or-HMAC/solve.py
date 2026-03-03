#!/usr/bin/env python3

"""
RSA or HMAC – Algorithm Confusion Attack
Manual implementation (no PyJWT patch required)

Server verifies with:

    jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])

If we send:
    alg = HS256

Server will use PUBLIC_KEY as HMAC secret.

Since the public key is public, we can sign our own admin token.
"""

import base64
import json
import hmac
import hashlib
import requests

BASE_URL = "https://web.cryptohack.org/rsa-or-hmac"

def b64url_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')

# -------------------------------------------------
# Step 1: Get public key
# -------------------------------------------------
pubkey_resp = requests.get(f"{BASE_URL}/get_pubkey/")
PUBLIC_KEY = pubkey_resp.json()["pubkey"].encode()

print("[+] Retrieved Public Key")

# -------------------------------------------------
# Step 2: Create malicious header & payload
# -------------------------------------------------
header = {
    "typ": "JWT",
    "alg": "HS256"
}

payload = {
    "admin": True
}

header_b64 = b64url_encode(json.dumps(header).encode())
payload_b64 = b64url_encode(json.dumps(payload).encode())

message = header_b64 + b"." + payload_b64

# -------------------------------------------------
# Step 3: Sign with HMAC-SHA256 using PUBLIC_KEY
# -------------------------------------------------
signature = hmac.new(
    PUBLIC_KEY,
    message,
    hashlib.sha256
).digest()

signature_b64 = b64url_encode(signature)

forged_token = message + b"." + signature_b64

print("[+] Forged Token:\n")
print(forged_token.decode())
print()

# -------------------------------------------------
# Step 4: Send forged token
# -------------------------------------------------
auth_resp = requests.get(
    f"{BASE_URL}/authorise/{forged_token.decode()}/"
)

print("[+] Server Response:\n")
print(auth_resp.json())
