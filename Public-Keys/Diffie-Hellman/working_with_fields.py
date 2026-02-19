p, g = 991, 209
d = pow(g, -1, p)
print(f"d = {d}")
print(f"Verify: {g} * {d} mod {p} = {(g * d) % p}")
