import socket
import json
from fastecdsa.point import Point
from fastecdsa.curve import P256

# Bing's public key (our target)
BING_X = 0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531
BING_Y = 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A
BING_Q = Point(BING_X, BING_Y, curve=P256)

# Choose fake private key, must not be +1 or -1
d_fake = 2

# Compute forged generator
# We need: 2 * G' = BING_Q
# So:      G' = inv(2) * BING_Q
n       = P256.q
inv_d   = pow(d_fake, -1, n)
G_prime = inv_d * BING_Q

# Verify math
assert d_fake * G_prime == BING_Q, "Math check failed!"
print(f"[+] 2 * G' = Bing pubkey confirmed")
print(f"[*] G'.x = {hex(G_prime.x)}")
print(f"[*] G'.y = {hex(G_prime.y)}")

# Build and send payload
payload = json.dumps({
    "private_key": d_fake,
    "host": "www.bing.com",
    "curve": "secp256r1",
    "generator": [G_prime.x, G_prime.y]
}) + "\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13382))
print(s.recv(1024).decode().strip())
s.sendall(payload.encode())
print(s.recv(1024).decode().strip())
s.close()
