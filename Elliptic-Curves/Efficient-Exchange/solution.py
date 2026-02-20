from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Elliptic curve parameters
p = 9739
a = 497
b = 1768

# Bob's secret
nB = 6534

# Alice's x-coordinate
xA = 4726

# Provided IV and ciphertext
iv = 'cd9da9f1c60925922377ea952afc212c'
ciphertext = 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'

# Helper functions
def mod_sqrt(y2, p):
    """Compute modular sqrt when p % 4 == 3"""
    return pow(y2, (p + 1) // 4, p)

def point_add(P, Q):
    """Add two points on the curve"""
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1) = P
    (x2, y2) = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # Point at infinity
    if P != Q:
        m = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
    else:
        m = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    """Multiply point P by scalar k"""
    R = None
    addend = P
    while k > 0:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

# Step 1: compute possible y values for Alice's point 
y2 = (xA**3 + a*xA + b) % p
yA1 = mod_sqrt(y2, p)
yA2 = (-yA1) % p

# Either y works; let's pick yA1
QA = (xA, yA1)

# Step 2: compute shared secret 
S = scalar_mult(nB, QA)
shared_secret = S[0]  # x-coordinate

# Step 3: decrypt the flag 
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    ciphertext_bytes = bytes.fromhex(ciphertext)
    iv_bytes = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
    plaintext = cipher.decrypt(ciphertext_bytes)
    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

flag = decrypt_flag(shared_secret, iv, ciphertext)
print("Flag:", flag)
