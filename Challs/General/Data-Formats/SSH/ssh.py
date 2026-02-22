import base64
import struct

with open("bruce_rsa_6e7ecd53b443a97013397b1a1ea30e14.pub") as f:
    keydata = f.read().split()[1]

data = base64.b64decode(keydata)

def read_string(data):
    length = struct.unpack(">I", data[:4])[0]
    return data[4:4+length], data[4+length:]

# Read "ssh-rsa"
keytype, rest = read_string(data)

# Read exponent (e)
e_bytes, rest = read_string(rest)

# Read modulus (n)
n_bytes, rest = read_string(rest)

n = int.from_bytes(n_bytes, byteorder="big")

print(n)
