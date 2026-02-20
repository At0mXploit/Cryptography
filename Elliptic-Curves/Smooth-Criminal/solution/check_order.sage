# Check if order is smooth or not, if smooth = Pohling-Hellman Attack
# Ran in sagecell

p = 310717010502520989590157367261876774703
a = 2
b = 3

E = EllipticCurve(GF(p), [a, b])
order = E.order()
factors = factor(order)

print("Curve order:", order)
print("Prime factorization:", factors)

# Check if all prime factors are below threshold B
B = 2*10^11  # set threshold high enough to include largest factor
is_smooth = all(prime <= B for prime, exp in factors)
print(f"Is the order {B}-smooth?", is_smooth)
