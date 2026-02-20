#!/usr/bin/env python3

from pwn import *
import json
import hashlib
from Crypto.Util.number import bytes_to_long, inverse
from ecdsa.ecdsa import generator_192, Public_key, Private_key, Signature

HOST = "socket.cryptohack.org"
PORT = 13381

# ECDSA params
g = generator_192
order = g.order()

def sha1_int(m):
    return bytes_to_long(hashlib.sha1(m.encode()).digest())

def recv_json(io):
    return json.loads(io.recvline().decode())

def send_json(io, data):
    io.sendline(json.dumps(data).encode())

def main():
    io = remote(HOST, PORT)

    print(io.recvline().decode())  # Welcome message

    # Request signature
    send_json(io, {"option": "sign_time"})
    data = recv_json(io)

    msg = data["msg"]
    r = int(data["r"], 16)
    s = int(data["s"], 16)

    print("[+] Got signature")
    print("msg:", msg)
    print("r:", r)
    print("s:", s)

    h = sha1_int(msg)

    # Recover private key
    print("[*] Brute forcing nonce...")

    for k in range(1, 60):  # seconds max = 59
        try:
            d = ((s * k - h) * inverse(r, order)) % order
            pub_candidate = g * d

            # Recompute r to check k correctness
            r_check = (g * k).x() % order

            if r_check == r:
                print("[+] Found nonce k =", k)
                print("[+] Recovered private key d =", d)
                break
        except Exception:
            continue
    else:
        print("[-] Failed to recover key")
        return

    # Forge signature for "unlock"
    h_unlock = sha1_int("unlock")

    # Use any valid k
    k_forge = 7
    R = g * k_forge
    r_forge = R.x() % order
    s_forge = (inverse(k_forge, order) * (h_unlock + r_forge * d)) % order

    print("[+] Forged signature:")
    print("r =", r_forge)
    print("s =", s_forge)

    # Send forged signature
    send_json(io, {
        "option": "verify",
        "msg": "unlock",
        "r": hex(r_forge),
        "s": hex(s_forge)
    })

    result = recv_json(io)
    print("[+] Server response:", result)

    io.close()

if __name__ == "__main__":
    main()
