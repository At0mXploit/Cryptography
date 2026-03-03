#!/usr/bin/env python3
import json
import secrets
import socket
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from Crypto.Util.Padding import unpad, pad

HOST = "socket.cryptohack.org"
PORT = 13410


def recv_until_json_lines(f, needed):
    out = []
    while len(out) < needed:
        line = f.readline()
        if not line:
            raise RuntimeError("connection closed")
        s = line.decode().strip()
        if s.startswith("{") and s.endswith("}"):
            out.append(json.loads(s))
    return out


def request(f, obj):
    f.write((json.dumps(obj) + "\n").encode())
    line = f.readline()
    if line.startswith(b"Login attempt from Alice:"):
        line = f.readline()
    return json.loads(line)


def fmt_num(x):
    b = long_to_bytes(x)
    return len(b).to_bytes(2, "big") + b


def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb", buffering=0)

    reg, upload, leaked = recv_until_json_lines(f, 3)

    master_key_enc = bytes.fromhex(reg["master_key_enc"])
    share_key_enc = bytes.fromhex(reg["share_key_enc"])
    n, e = reg["share_key_pub"]

    node_key_enc = bytes.fromhex(upload["node_key_enc"])
    file_enc = bytes.fromhex(upload["file_enc"])

    # Given leak: (n, e, p)
    _, _, p = leaked["share_key"]
    q = n // p
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    u = inverse(p, q)

    # Rebuild exact serialized private key plaintext.
    p_b = long_to_bytes(p)
    q_b = long_to_bytes(q)
    d_b = long_to_bytes(d)
    u_b = long_to_bytes(u)

    plain = pad(fmt_num(p) + fmt_num(q) + fmt_num(d) + fmt_num(u), 16)
    if len(plain) != len(share_key_enc):
        raise RuntimeError("Unexpected share key length mismatch")

    # Locate a full ciphertext block that lies inside u bytes (not touching len(u) field).
    u_field_start = len(fmt_num(p)) + len(fmt_num(q)) + len(fmt_num(d))
    u_data_start = u_field_start + 2
    u_data_end = u_data_start + len(u_b)

    chosen_block = None
    for bi in range(len(plain) // 16):
        bs, be = 16 * bi, 16 * (bi + 1)
        if bs >= u_data_start and be <= u_data_end:
            chosen_block = bi
            break
    if chosen_block is None:
        raise RuntimeError("Could not find in-u full block")

    # Compute offset of unknown 16-byte chunk within u byte string.
    chunk_abs = chosen_block * 16
    off = chunk_abs - u_data_start

    # Build forged share_key_enc by swapping one u-block with node_key_enc block.
    blocks = [share_key_enc[i:i + 16] for i in range(0, len(share_key_enc), 16)]
    blocks[chosen_block] = node_key_enc
    forged_share = b"".join(blocks)

    # One oracle query.
    m = secrets.randbelow(n - 1) + 1
    c = pow(m, e, n)

    dp = d % (p - 1)
    dq = d % (q - 1)
    mp = pow(c, dp, p)
    mq = pow(c, dq, q)
    t = (mq - mp) % q
    if t == 0:
        raise RuntimeError("Unlucky t=0; rerun")

    request(f, {"action": "wait_login"})
    out = request(
        f,
        {
            "action": "send_challenge",
            "SID_enc": long_to_bytes(c).hex(),
            "share_key_enc": forged_share.hex(),
            "master_key_enc": master_key_enc.hex(),
        },
    )
    if "SID" not in out:
        raise RuntimeError(out)

    s_hi = bytes_to_long(bytes.fromhex(out["SID"]))

    # Recover exact s' low 128 bits using known p congruence.
    x = (mp - (s_hi << 128)) % p
    if x >= (1 << 128):
        raise RuntimeError("Low-bits reconstruction failed; rerun")

    s_prime = (s_hi << 128) + x
    if (s_prime - mp) % p != 0:
        raise RuntimeError("Consistency failure")

    r = (s_prime - mp) // p

    # r = (t * u') mod q, where u' is parsed forged-u integer (mod q).
    u_prime_mod_q = (r * inverse(t, q)) % q

    # u' bytes are u bytes with one 16-byte unknown chunk (= node_key) replaced.
    L = len(u_b)
    if off < 0 or off + 16 > L:
        raise RuntimeError("Invalid u-chunk offset")

    ub_zero = bytearray(u_b)
    ub_zero[off:off + 16] = b"\x00" * 16
    A = bytes_to_long(bytes(ub_zero))
    coeff = 1 << (8 * (L - (off + 16)))

    X = ((u_prime_mod_q - A) * inverse(coeff, q)) % q
    if X >= (1 << 128):
        raise RuntimeError("Recovered chunk outside 16-byte range; rerun")

    node_key = long_to_bytes(X, 16)
    pt = unpad(AES.new(node_key, AES.MODE_ECB).decrypt(file_enc), 16)
    print(pt.decode())


if __name__ == "__main__":
    main()
