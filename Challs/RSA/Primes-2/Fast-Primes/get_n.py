from Crypto.PublicKey import RSA

# Open the public key file
with open('key.pem', 'r') as f:
    key = RSA.import_key(f.read())

# Print the modulus n and exponent e
print("n =", key.n)
print("e =", key.e)
