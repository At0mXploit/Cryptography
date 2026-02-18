import subprocess
import sys
import os
import hashlib
import requests
from Crypto.Cipher import AES

def ensure(pkg):
    try:
        __import__(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure("requests")
ensure("Crypto")

wordlist = "words.txt"
url = "https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words"

if not os.path.exists(wordlist):
    r = requests.get(url, timeout=20)
    with open(wordlist, "wb") as f:
        f.write(r.content)

base = "https://aes.cryptohack.org/passwords_as_keys"
cipher_hex = requests.get(f"{base}/encrypt_flag/", timeout=20).json()["ciphertext"]
ciphertext = bytes.fromhex(cipher_hex)

with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
    words = [w.strip() for w in f]

for w in words:
    key = hashlib.md5(w.encode()).digest()
    pt = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    if b"crypto{" in pt:
        print(pt.decode())
        break

