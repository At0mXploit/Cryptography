from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sympy.ntheory import discrete_log
import hashlib
import json

def decrypt_flag(shared_secret, iv_hex, ciphertext_hex):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        return unpad(plaintext, 16).decode('ascii')
    except:
        return plaintext.decode('ascii')

conn = remote('socket.cryptohack.org', 13379)

# Alice sends supported list
alice_raw = conn.recvline().decode().strip()
print(f"Alice: {alice_raw}")

# Downgrade to DH64
conn.recvuntil(b"Send to Bob: ")
conn.sendline(json.dumps({"supported": ["DH64"]}).encode())
print("Sent to Bob: DH64 only")

# Bob picks DH64
bob_raw = conn.recvline().decode().strip()
print(f"Bob: {bob_raw}")
bob_msg = json.loads(bob_raw.split("Intercepted from Bob: ")[1])

# Forward to Alice
conn.recvuntil(b"Send to Alice: ")
conn.sendline(json.dumps(bob_msg).encode())

# Alice sends p, g, A
alice2_raw = conn.recvline().decode().strip()
print(f"Alice params: {alice2_raw}")
alice2_msg = json.loads(alice2_raw.split("Intercepted from Alice: ")[1])
p = int(alice2_msg['p'], 16)
g = int(alice2_msg['g'], 16)
A = int(alice2_msg['A'], 16)

# Bob sends B
bob2_raw = conn.recvline().decode().strip()
print(f"Bob public value: {bob2_raw}")
bob2_msg = json.loads(bob2_raw.split("Intercepted from Bob: ")[1])
B = int(bob2_msg['B'], 16)

# Solve discrete log: find a such that g^a = A mod p
print(f"\np = {p} ({p.bit_length()} bits)")
print("Solving discrete log...")
a = discrete_log(p, A, g)
print(f"Found a = {a}")

shared_secret = pow(B, a, p)
print(f"Shared secret = {shared_secret}")

# Receive encrypted flag
enc_raw = conn.recvline().decode().strip()
print(f"Encrypted: {enc_raw}")
enc_msg = json.loads(enc_raw.split("Intercepted from Alice: ")[1] if "Intercepted" in enc_raw else enc_raw)

flag = decrypt_flag(shared_secret, enc_msg['iv'], enc_msg['encrypted_flag'])
print(f"\nFlag: {flag}")

conn.close()
