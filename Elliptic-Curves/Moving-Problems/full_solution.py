from sage.all import * 
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

def gen_shared_secret(P, n):
    S = n*P
    return S.xy()[0]

def decrypt_flag(iv_hex: str, ciphertext_hex: str, shared_secret: int) -> bytes:
    """
    Decrypt AES-CBC flag from IV and ciphertext (hex) using shared_secret (int).
    Returns plaintext (FLAG) as bytes.
    """
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a, b])
G = E(479691812266187139164535778017, 568535594075310466177352868412) 

# Find embedding degree k
Gn = G.order()
k = 1
while p^k % Gn != 1:
    k += 1
print("Found k:", k)

# Public key Q
Q = E(1110072782478160369250829345256, 800079550745409318906383650948)

# Lift curve to GF(p^k)
Ek = EllipticCurve(GF(p ^ k), [a, b])
Gk = Ek(G)
Qk = Ek(Q)
Rk = Ek.random_point()

# Find T of order dividing G's order
m = Rk.order()
d = gcd(m, Gn)
Tk = (m // d) * Rk
assert Tk.order() == d
assert (Gn*Tk).is_zero() # point at infinity

# Compute pairings
g = Gk.weil_pairing(Tk, Gn)
q = Qk.weil_pairing(Tk, Gn)

print("Calculating private key...")
found_key = q.log(g)
print(found_key)

# Decrypt flag
Qa = E(1110072782478160369250829345256 , 800079550745409318906383650948 )
Qb = E(1290982289093010194550717223760 , 762857612860564354370535420319 )
iv = 'eac58c26203c04f68d63dc2c58d79aca'
encrypted_flag = 'bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d'

shared = gen_shared_secret(Qb, found_key) 
print(decrypt_flag(iv, encrypted_flag, shared))
