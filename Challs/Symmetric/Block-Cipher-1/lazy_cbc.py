import requests

URL = "https://aes.cryptohack.org/lazy_cbc"

def encrypt(pt_hex):
    r = requests.get(f"{URL}/encrypt/{pt_hex}/")
    return r.json()["ciphertext"]

def receive(ct_hex):
    r = requests.get(f"{URL}/receive/{ct_hex}/")
    return r.json()

def get_flag(key_hex):
    r = requests.get(f"{URL}/get_flag/{key_hex}/")
    return r.json()

# Step 1: Encrypt two blocks of zeros
plaintext = "00" * 32
ciphertext = encrypt(plaintext)

# Split into blocks
C1 = ciphertext[:32]
C2 = ciphertext[32:64]

# Step 2: Craft malicious ciphertext
malicious = C1 + ("00" * 16) + C1

response = receive(malicious)

# Extract leaked plaintext
leaked = response["error"].split(": ")[1]

P1 = leaked[:32]
P2 = leaked[32:64]
P3 = leaked[64:96]

# Recover key: KEY = P1 XOR P3
key = bytes(a ^ b for a, b in zip(bytes.fromhex(P1), bytes.fromhex(P3)))
key_hex = key.hex()

print("Recovered KEY:", key_hex)

# Step 3: Get flag
flag_response = get_flag(key_hex)
print("FLAG:", bytes.fromhex(flag_response["plaintext"]).decode())
