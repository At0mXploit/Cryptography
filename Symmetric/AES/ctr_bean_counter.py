#!/usr/bin/env python3
import requests

BASE_URL = "https://aes.cryptohack.org/bean_counter/encrypt/"

# Standard 16‑byte PNG header
PNG_HEADER = bytes([
    0x89, 0x50, 0x4E, 0x47,
    0x0D, 0x0A, 0x1A, 0x0A,
    0x00, 0x00, 0x00, 0x0D,
    0x49, 0x48, 0x44, 0x52
])


def get_ciphertext() -> bytes:
    """Fetch encrypted PNG from server."""
    r = requests.get(BASE_URL)
    return bytes.fromhex(r.json()["encrypted"])


def recover_keystream(ciphertext: bytes) -> bytes:
    """Recover repeating keystream using known PNG header."""
    return bytes(c ^ p for c, p in zip(ciphertext[:16], PNG_HEADER))


def decrypt_image(ciphertext: bytes, keystream: bytes) -> bytes:
    """Decrypt full image using repeating keystream."""
    return bytes(
        c ^ keystream[i % len(keystream)]
        for i, c in enumerate(ciphertext)
    )


def main():
    ciphertext = get_ciphertext()

    keystream = recover_keystream(ciphertext)
    print("Recovered keystream:", keystream.hex())

    plaintext = decrypt_image(ciphertext, keystream)

    with open("bean_counter.png", "wb") as f:
        f.write(plaintext)

    print("Decrypted image saved as bean_counter.png")


if __name__ == "__main__":
    main()

