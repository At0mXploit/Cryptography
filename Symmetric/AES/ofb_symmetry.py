#!/usr/bin/env python3
import requests

BASE = "https://aes.cryptohack.org/symmetry/"

def encrypt(plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt arbitrary plaintext with chosen IV using server OFB oracle."""
    r = requests.get(BASE + f"encrypt/{plaintext.hex()}/{iv.hex()}/")
    return bytes.fromhex(r.json()["ciphertext"])

def encrypt_flag():
    """Get encrypted flag + IV from server."""
    r = requests.get(BASE + "encrypt_flag/")
    data = r.json()["ciphertext"]
    iv = bytes.fromhex(data[:32])
    ciphertext = bytes.fromhex(data[32:])
    return iv, ciphertext

def main():
    # Step 1: get encrypted flag
    iv, c_flag = encrypt_flag()

    # Step 2: send a known plaintext with same IV
    known_plain = b"A" * len(c_flag)
    c_known = encrypt(known_plain, iv)

    # Step 3: recover keystream
    keystream = bytes(a ^ b for a, b in zip(c_known, known_plain))

    # Step 4: recover flag
    flag = bytes(a ^ b for a, b in zip(c_flag, keystream))
    print("Recovered flag:", flag.decode())

if __name__ == "__main__":
    main()

