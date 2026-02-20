p = 2**255 - 19
A = 486662
B = 1

def modinv(a):
    return pow(a, p - 2, p)

def point_double(P):
    if P is None:
        return None
    x1, y1 = P
    if y1 == 0:
        return None
    alpha = ((3 * x1**2 + 2 * A * x1 + 1) * modinv(2 * B * y1)) % p
    x3 = (B * alpha**2 - A - 2 * x1) % p
    y3 = (alpha * (x1 - x3) - y1) % p
    return (x3, y3)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        return point_double(P) if y1 == y2 else None
    alpha = ((y2 - y1) * modinv(x2 - x1)) % p
    x3 = (B * alpha**2 - A - x1 - x2) % p
    y3 = (alpha * (x1 - x3) - y1) % p
    return (x3, y3)

def montgomery_ladder(k, P):
    bits = k.bit_length()
    R0 = P
    R1 = point_double(P)
    for i in range(bits - 2, -1, -1):
        ki = (k >> i) & 1
        if ki == 0:
            R1 = point_add(R0, R1)
            R0 = point_double(R0)
        else:
            R0 = point_add(R0, R1)
            R1 = point_double(R1)
    return R0

def find_y(x):
    rhs = (x**3 + A * x**2 + x) % p
    # p ≡ 5 (mod 8), special sqrt
    y = pow(rhs, (p + 3) // 8, p)
    if pow(y, 2, p) == rhs:
        return y
    y = (y * pow(2, (p - 1) // 4, p)) % p
    if pow(y, 2, p) == rhs:
        return y
    raise ValueError("No square root")

G = (9, find_y(9))
k = 0x1337c0decafe

Q = montgomery_ladder(k, G)
print(Q[0])
