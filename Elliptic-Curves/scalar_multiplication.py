p = 9739
a = 497
b = 1768

def mod_inv(x, p):
    return pow(x, -1, p)

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # Point at infinity

    if P == Q:
        lam = ((3*x1**2 + a) * mod_inv(2*y1, p)) % p
    else:
        lam = ((y2 - y1) * mod_inv(x2 - x1, p)) % p

    x3 = (lam**2 - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(P, n):
    R = None  # identity
    Q = P
    while n > 0:
        if n % 2 == 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        n = n // 2
    return R

P = (2339, 2213)
n = 7863
Q = scalar_mult(P, n)
print("Q =", Q)

# Verify
x, y = Q
assert (y**2 - (x**3 + a*x + b)) % p == 0
print("Q is on the curve")
