from Crypto.PublicKey import RSA

with open("transparency_afff0345c6f99bf80eab5895458d8eab.pem", "rb") as f:
    key = RSA.import_key(f.read())

print(key.n)
