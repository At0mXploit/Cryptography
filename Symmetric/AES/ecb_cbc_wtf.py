#!/usr/bin/env python3
import requests

URL = "https://aes.cryptohack.org/"

def strxor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def get_flag_enc() -> tuple[bytes, bytes]:
    """Fetch the CBC-encrypted flag from the server."""
    r = requests.get(URL + "ecbcbcwtf/encrypt_flag/")
    data = r.json()["ciphertext"]
    ciphertext = bytes.fromhex(data)
    iv = ciphertext[:16]
    cipher = ciphertext[16:]
    return iv, cipher

def get_plaintext_ecb(ciphertext: bytes) -> tuple[bytes, bytes]:
    """Decrypt a ciphertext in ECB mode (oracle) and return two blocks."""
    r = requests.get(URL + f"ecbcbcwtf/decrypt/{ciphertext.hex()}/")
    pt = bytes.fromhex(r.json()["plaintext"])
    return pt[:16], pt[16:32]

def main():
    iv, cipher = get_flag_enc()
    c0 = cipher[:16]
    c1 = cipher[16:32]

    # Use ECB oracle to decrypt blocks
    p0, p1 = get_plaintext_ecb(cipher)

    # Recover plaintext using CBC formula: P_i = D(C_i) ^ C_{i-1}
    block0 = strxor(iv, p0)
    block1 = strxor(c0, p1)

    flag = block0 + block1
    print("Recovered flag:", flag.decode())

if __name__ == "__main__":
    main()

