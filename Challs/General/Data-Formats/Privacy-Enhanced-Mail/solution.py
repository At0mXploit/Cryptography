from Crypto.PublicKey import RSA

with open("privacy_enhanced_mail.pem", "rb") as f:
    key = RSA.import_key(f.read())

print(key.d)
