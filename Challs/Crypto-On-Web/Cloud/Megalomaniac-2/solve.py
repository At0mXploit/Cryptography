#!/usr/bin/env python3
import json
import socket
import secrets
from math import gcd
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import PolynomialRing, Zmod

HOST = "socket.cryptohack.org"
PORT = 13409


def recv_registration(f):
    for _ in range(4):
        f.readline()
    return json.loads(f.readline())


def request(f, obj):
    f.write((json.dumps(obj) + "\n").encode())
    line = f.readline()
    if line.startswith(b"Login attempt from Alice:"):
        line = f.readline()
    return json.loads(line)


def recover_factor_from_truncated_fault(n, m, s_hi):
    A = (s_hi << 128) - m
    R = PolynomialRing(Zmod(n), "x")
    x = R.gen()
    f = x + (A % n)
    roots = f.small_roots(X=2**128, beta=0.49)
    for r in roots:
        g = gcd(A + int(r), n)
        if 1 < g < n:
            return g
    return None


def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb", buffering=0)

    reg = recv_registration(f)
    n, e = reg["share_key_pub"]
    master_key_enc = bytes.fromhex(reg["master_key_enc"])
    share_key_enc = bytes.fromhex(reg["share_key_enc"])

    flag_ct = bytes.fromhex(request(f, {"action": "get_encrypted_flag"})["encrypted_flag"])

    m = secrets.randbelow(n - 1) + 1
    c = pow(m, e, n)

    blocks = [bytearray(share_key_enc[i:i+16]) for i in range(0, len(share_key_enc), 16)]
    # Corrupt a late block located in u, keeping p/q/d intact.
    blocks[39][0] ^= 1
    share_fault = b"".join(bytes(b) for b in blocks)

    request(f, {"action": "wait_login"})
    out = request(
        f,
        {
            "action": "send_challenge",
            "SID_enc": long_to_bytes(c).hex(),
            "share_key_enc": share_fault.hex(),
            "master_key_enc": master_key_enc.hex(),
        },
    )

    if "SID" not in out:
        raise RuntimeError(out)

    s_hi = bytes_to_long(bytes.fromhex(out["SID"]))
    p = recover_factor_from_truncated_fault(n, m, s_hi)
    if p is None:
        raise RuntimeError("No factor recovered; rerun for fresh instance.")

    q = n // p
    for a, b in [(p, q), (q, p)]:
        key = SHA256.new(long_to_bytes(a) + long_to_bytes(b)).digest()
        pt = AES.new(key, AES.MODE_ECB).decrypt(flag_ct)
        try:
            pt = unpad(pt, 16)
        except ValueError:
            continue
        if pt.startswith(b"crypto{"):
            print(pt.decode())
            return

    raise RuntimeError("Recovered factors but flag decrypt failed")


if __name__ == "__main__":
    main()
