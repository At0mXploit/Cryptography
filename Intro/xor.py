s = "label"
print("crypto{" + "".join(chr(ord(c) ^ 13) for c in s) + "}")

