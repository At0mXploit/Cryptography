from sympy import factorint

def is_primitive(g, p):
    """
    g is primitive if g^((p-1)/q) != 1 mod p
    for every prime factor q of (p-1).
    """
    order = p - 1
    for q in factorint(order):               # get prime factors of p-1
        if pow(g, order // q, p) == 1:
            return False
    return True

p = 28151

for g in range(2, p):
    if is_primitive(g, p):
        print(f"Smallest primitive element: g = {g}")
        break
