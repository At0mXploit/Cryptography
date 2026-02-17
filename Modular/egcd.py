# a.u + b.v = gcd(a,b)

def egcd(a, b):
    if b == 0:
        return a, 1, 0

    gcd, x, y = egcd(b, a % b)

    u = y
    v = x - (a // b) * y

    return gcd, u, v


p = 26513
q = 32321

gcd, u, v = egcd(p, q)

print(min(u, v))

