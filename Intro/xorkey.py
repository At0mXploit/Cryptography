data = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")

for key in range(256):
    decoded = bytes(b ^ key for b in data)
    try:
        text = decoded.decode()
        if text.startswith("crypto{"):
            print(f"Key: {hex(key)}, Flag: {text}")
            break
    except:
        continue

