from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

# Shared secret from ECC
shared_secret = 171172176587165701252669133307091694084

# Derive AES key (first 16 bytes of SHA-1 of shared_secret)
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]
print("Derived AES key (hex):", key.hex())

# Ciphertext and IV from output.txt
iv_hex = "07e2628b590095a5e332d397b8a59aa7"
ct_hex = "8220b7c47b36777a737f5ef9caa2814cf20c1c1ef496ec21a9b4833da24a008d0870d3ac3a6ad80065c138a2ed6136af"

iv = bytes.fromhex(iv_hex)
ciphertext = bytes.fromhex(ct_hex)

# Decrypt AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_padded = cipher.decrypt(ciphertext)
flag = unpad(plaintext_padded, 16).decode('ascii')

print("Decrypted flag:", flag)
