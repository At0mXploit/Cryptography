from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import json

# Connect to the server
conn = remote('socket.cryptohack.org', 13371)

# Receive Alice's message and parse it
alice_raw = conn.recvline().decode().strip()
print(f"Alice: {alice_raw}")

alice_msg = json.loads(alice_raw.split("Intercepted from Alice: ")[1])
p = int(alice_msg['p'], 16)
g = int(alice_msg['g'], 16)

# Inject A = p so Bob computes p^b mod p = 0
inject = {"p": hex(p), "g": hex(g), "A": hex(p)}
conn.recvuntil(b"Send to Bob: ")
conn.sendline(json.dumps(inject).encode())
print(f"Sent to Bob: {json.dumps(inject)}")

# Receive Bob's response (ignored, shared secret is already known to be 0)
bob_raw = conn.recvline().decode().strip()
print(f"Bob: {bob_raw}")

# Inject B = p so Alice computes p^a mod p = 0
bob_msg = json.loads(bob_raw.split("Intercepted from Bob: ")[1])
inject_b = {"B": hex(p)}
conn.recvuntil(b"Send to Alice: ")
conn.sendline(json.dumps(inject_b).encode())
print(f"Sent to Alice: {json.dumps(inject_b)}")

# Receive the encrypted flag
enc_raw = conn.recvline().decode().strip()
print(f"Encrypted flag: {enc_raw}")
enc_msg = json.loads(enc_raw.split("Intercepted from Alice: ")[1] if "Intercepted" in enc_raw else enc_raw)

# Shared secret is 0 because p^anything mod p = 0
shared_secret = 0

# Derive AES key from shared secret using SHA1
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]

# Decrypt the flag using AES-CBC
iv         = bytes.fromhex(enc_msg['iv'])
ciphertext = bytes.fromhex(enc_msg['encrypted_flag'])
cipher     = AES.new(key, AES.MODE_CBC, iv)
plaintext  = cipher.decrypt(ciphertext)

try:
    flag = unpad(plaintext, 16).decode('ascii')
except:
    flag = plaintext.decode('ascii')

print(f"\nFlag: {flag}")
conn.close()
