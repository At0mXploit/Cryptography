# We want d such that 3 * d ≡ 1 (mod 13)
p = 13
g = 3

# Using Fermat's little theorem
d = pow(g, p-2, p)
print(d)

