# Curve parameters
p = 1331169830894825846283645180581
a = -35
b = 98
E = EllipticCurve(GF(p), [a, b])

# Points
G = E(479691812266187139164535778017,
      568535594075310466177352868412)
Q = E(1110072782478160369250829345256,
      800079550745409318906383650948)  # Alice public key

# Find embedding degree k
Gn = G.order()
k = 1
while p^k % Gn != 1:
    k += 1
print("Found embedding degree k:", k)

# Lift curve to extension field GF(p^k)
Ek = EllipticCurve(GF(p^k), [a, b])
Gk = Ek(G)
Qk = Ek(Q)

# Find a point T of order dividing G's order
Rk = Ek.random_point()
m = Rk.order()
d = gcd(m, Gn)
Tk = (m // d) * Rk
assert Tk.order() == d
assert (Gn * Tk).is_zero()  # Point at infinity

# Compute Weil pairings
g = Gk.weil_pairing(Tk, Gn)
q = Qk.weil_pairing(Tk, Gn)

# Compute private key
found_key = q.log(g)
print("Recovered private key:", found_key)

# Compute shared secret
shared_secret = int((n_a * P2).xy()[0])
print("Shared secret:", shared_secret)
