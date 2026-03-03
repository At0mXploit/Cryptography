#!/usr/bin/env python3

"""
JWT Secrets Challenge Exploit

------------------------------------------------------------
Notes:

The most common signing algorithms used in JWTs are HS256 and RS256.

- HS256:
    Symmetric signing scheme using HMAC-SHA256.
    The same secret key is used for BOTH signing and verifying.

- RS256:
    Asymmetric signing scheme using RSA.
    Private key signs, public key verifies.

Security Discussion:

HS256 requires the secret key to be present on every server
that verifies tokens. If this secret key is leaked or guessed,
an attacker can forge arbitrary tokens and escalate privileges.

RS256 is safer in distributed systems because:
- The private signing key can remain protected.
- The public verification key can be freely distributed.

In this challenge, the source code contains:

    SECRET_KEY = ? # TODO: PyJWT readme key, change later

The PyJWT README example uses:

    key = "secret"

This strongly suggests the developer forgot to change
the default example key.

Exploit Strategy:

1. Assume SECRET_KEY = "secret"
2. Forge a new token with:
       {"admin": True}
3. Sign it using HS256 and the known key.
4. Send it to the /authorise endpoint.
5. Retrieve the flag.
------------------------------------------------------------
"""

import jwt
import requests

BASE_URL = "https://web.cryptohack.org/jwt-secrets"

# -------------------------------------------------
# Step 1: Guess the secret key from PyJWT README
# -------------------------------------------------
SECRET_KEY = "secret"

# -------------------------------------------------
# Step 2: Create malicious payload with admin=True
# -------------------------------------------------
payload = {
    "admin": True
}

# -------------------------------------------------
# Step 3: Sign token using HS256 and known secret
# -------------------------------------------------
forged_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

print("[+] Forged Admin Token:")
print(forged_token)
print()

# -------------------------------------------------
# Step 4: Send token to authorise endpoint
# -------------------------------------------------
url = f"{BASE_URL}/authorise/{forged_token}/"

response = requests.get(url)

print("[+] Server Response:")
print(response.json())
