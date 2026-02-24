#!/usr/bin/env python3

from Crypto.Util.number import inverse, long_to_bytes

# Given RSA values
n = 984994081290620368062168960884976209711107645166770780785733
e = 65537
ct = 948553474947320504624302879933619818331484350431616834086273

# ---------- FACTORS FROM FACTORDb ----------
# We factored n using FactorDB:
# n = p * q
p = 848445505077945374527983649411
q = 1160939713152385063689030212503

# Step 1: Compute phi(n)
phi = (p - 1) * (q - 1)

# Step 2: Compute private exponent d
d = inverse(e, phi)

# Step 3: Decrypt ciphertext
pt = pow(ct, d, n)

# Step 4: Convert decrypted number to bytes
flag = long_to_bytes(pt)

print("FLAG:", flag.decode())
