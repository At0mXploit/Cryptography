from pwn import *
import json
import base64
import codecs
from Crypto.Util.number import long_to_bytes

r = remote('socket.cryptohack.org', 13377)

def json_recv():
    return json.loads(r.recvline().decode())

def json_send(hsh):
    r.sendline(json.dumps(hsh).encode())

for _ in range(101):  # 100 levels + flag
    received = json_recv()
    
    if "flag" in received:
        print(received["flag"])
        break
    
    encoding_type = received["type"]
    encoded = received["encoded"]
    
    if encoding_type == "base64":
        decoded = base64.b64decode(encoded).decode()
        
    elif encoding_type == "hex":
        decoded = bytes.fromhex(encoded).decode()
        
    elif encoding_type == "rot13":
        decoded = codecs.decode(encoded, "rot_13")
        
    elif encoding_type == "bigint":
        decoded = long_to_bytes(int(encoded, 16)).decode()
        
    elif encoding_type == "utf-8":
        decoded = "".join(chr(b) for b in encoded)
        
    json_send({"decoded": decoded})
