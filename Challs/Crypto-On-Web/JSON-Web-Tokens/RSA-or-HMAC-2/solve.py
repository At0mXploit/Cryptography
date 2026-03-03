import urllib.request
import json
import hmac
import hashlib
import base64
import gmpy2
import time
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# helper to GET a JSON endpoint and parse the response
def fetch(url):
    return json.loads(urllib.request.urlopen(url).read())

# base64url decode with padding fix (JWT drops the = padding)
def b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

# base64url encode and strip = padding to match JWT spec
def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

# PKCS#1 v1.5 pad a message for RSA signature verification
# RSA signatures are: sig^e mod n = 0x0001ff...ff00 || DigestInfo || sha256(msg)
# we reproduce this expected value so we can subtract it from sig^e later
def pkcs1_pad(msg):
    # ASN.1 DigestInfo prefix for SHA-256
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest = hashlib.sha256(msg).digest()
    t = prefix + digest
    # total block is 256 bytes (2048-bit key), format: 00 01 ff...ff 00 || t
    padded = b'\x00\x01' + b'\xff' * (256 - len(t) - 3) + b'\x00' + t
    return gmpy2.mpz(int.from_bytes(padded, "big"))

# step 1 - get two legitimately signed RS256 tokens from the server
# each token is signed with the same private key, giving us two sig/msg pairs
print("[1] Fetching tokens...")
t1 = fetch("https://web.cryptohack.org/rsa-or-hmac-2/create_session/alice/")["session"]
t2 = fetch("https://web.cryptohack.org/rsa-or-hmac-2/create_session/bob/")["session"]

# split a JWT into its integer signature and the raw signing input bytes
# signing input is header.payload as bytes, signature is big-endian integer
def parse(token):
    header, payload, signature = token.split(".")
    sig = gmpy2.mpz(int.from_bytes(b64url_decode(signature), "big"))
    msg = (header + "." + payload).encode()
    return sig, msg

s1, m1 = parse(t1)
s2, m2 = parse(t2)

# step 2 - compute sig^e - pkcs1_pad(msg) for each token
# by RSA: sig^e ≡ pkcs1_pad(msg) (mod n)
# so sig^e - pkcs1_pad(msg) ≡ 0 (mod n)
# meaning n divides both of these values
print("[2] Computing exponentiations...")
start = time.time()
val1 = gmpy2.mpz(s1) ** 65537 - pkcs1_pad(m1)
val2 = gmpy2.mpz(s2) ** 65537 - pkcs1_pad(m2)
print(f"   Done in {round(time.time() - start, 2)} seconds")

# step 3 - recover n by taking gcd of the two values
# gcd(val1, val2) = n because n is the only large common factor
# small spurious factors are possible but unlikely to affect the 2048-bit n
print("[3] Recovering modulus with gcd...")
n = int(gmpy2.gcd(val1, val2))
print(f"   Bit length: {n.bit_length()}")

# rebuild the RSA public key object from (e=65537, n) and export as PEM
# we need PEM format because the server loads its key that way
# and we will use these exact bytes as the HMAC secret in the attack
pem = RSAPublicNumbers(65537, n).public_key(default_backend()).public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.PKCS1
)

# step 4 - algorithm confusion attack (RS256 -> HS256)
# the server calls jwt.decode(token, PUBLIC_KEY, algorithms=['HS256', 'RS256'])
# if the token header says alg=HS256, PyJWT verifies it as HMAC-SHA256
# using PUBLIC_KEY as the HMAC secret
# since we recovered the public key, we can forge a valid HS256 token ourselves
print("[4] Forging admin token...")

# build header and payload manually as base64url-encoded JSON
# we cannot use jwt.encode() here because PyJWT rejects PEM bytes as HMAC keys
header  = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
payload = b64url_encode(b'{"username":"admin","admin":true}')

# signing input is always header.payload
signing_input = f"{header}.{payload}".encode()

# sign with HMAC-SHA256 using the raw PEM bytes as the secret
# this is exactly what the server will compute when it verifies with HS256
sig = hmac.new(pem, signing_input, hashlib.sha256).digest()

# assemble the final JWT: header.payload.signature
admin_token = f"{header}.{payload}.{b64url_encode(sig)}"

# step 5 - send the forged token and get the flag
print("[5] Submitting forged token...")
result = fetch(f"https://web.cryptohack.org/rsa-or-hmac-2/authorise/{admin_token}/")
print(result)
