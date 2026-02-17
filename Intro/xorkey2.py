data = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

# "crypto{" in bytes
prefix = b"crypto{"

# XOR the first 7 bytes of data with "crypto{" to find the key
key_bytes = bytes(d ^ p for d, p in zip(data, prefix))
print("Key bytes:", key_bytes)
print("Key hex:", key_bytes.hex())
