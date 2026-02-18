#!/usr/bin/env python3

from datetime import datetime, timedelta
import requests

BASE_URL = "https://aes.cryptohack.org/flipping_cookie/"


def request_cookie():
    """Get encrypted cookie (IV + ciphertext in hex)."""
    r = requests.get(BASE_URL + "get_cookie/")
    return r.json()["cookie"]


def request_check_admin(cookie_hex, iv_hex):
    """Send modified values to check_admin endpoint."""
    r = requests.get(BASE_URL + f"check_admin/{cookie_hex}/{iv_hex}/")
    return r.json()


def flip_cookie(original_cookie_hex, known_plaintext):
    """
    Perform CBC bit‑flipping attack to change:
        admin=False  →  admin=True
    """
    cookie_bytes = bytes.fromhex(original_cookie_hex)

    # Prepare fake IV and modified ciphertext buffer
    fake_iv = bytearray(16)
    modified_cipher = bytearray(cookie_bytes)

    # Target string we want after decryption
    target = b";admin=True;"

    # Locate "admin=False" in known plaintext
    start = known_plaintext.find(b"admin=False")

    # Flip bits in IV and ciphertext so decrypted text becomes target
    for i in range(len(target)):
        modified_cipher[16 + i] = (
            known_plaintext[16 + i] ^ cookie_bytes[16 + i] ^ target[i]
        )
        fake_iv[start + i] = (
            known_plaintext[start + i] ^ cookie_bytes[start + i] ^ target[i]
        )

    return modified_cipher.hex(), bytes(fake_iv).hex()


def main():
    # Recreate plaintext format used by server
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    known_plaintext = f"admin=False;expiry={expires_at}".encode()

    # Step 1: get cookie
    cookie_hex = request_cookie()

    # Step 2: flip bits to forge admin=True
    forged_cookie, forged_iv = flip_cookie(cookie_hex, known_plaintext)

    # Step 3: send forged values to retrieve flag
    result = request_check_admin(forged_cookie, forged_iv)
    print(result)


if __name__ == "__main__":
    main()

