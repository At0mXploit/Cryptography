p = 9739
a = 497
b = 1768

def mod_inv(x, p):
    return pow(x, -1, p)

def point_add(P, Q):
    if P is None:  # identity
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:  # P = -Q
        return None

    if P == Q:  # doubling
        lam = ((3 * x1**2 + a) * mod_inv(2 * y1, p)) % p
    else:
        lam = ((y2 - y1) * mod_inv(x2 - x1, p)) % p

    x3 = (lam**2 - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

# Points
P = (493, 5564)
Q = (1539, 4742)
R = (4403, 5202)

# Compute S
T = point_add(P, P)  # P + P
U = point_add(T, Q)  # T + Q
S = point_add(U, R)  # U + R

print("S =", S)

# Verify that S is on the curve
x, y = S
assert (y**2 - (x**3 + a*x + b)) % p == 0
print("S is on the curve")
