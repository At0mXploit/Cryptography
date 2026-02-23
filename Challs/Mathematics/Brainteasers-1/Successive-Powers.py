from math import gcd
from sympy import mod_inverse, isprime

nums = [588,665,216,113,642,4,836,114,851,492,819,237]

# Step 1: compute p using first three values
a, b, c = nums[0], nums[1], nums[2]

value = b*b - a*c   # p must divide this
print("Candidate multiple of p:", value)

# Factor to find 3-digit prime
candidates = []
for i in range(100, 1000):
    if value % i == 0 and isprime(i):
        candidates.append(i)

print("Possible primes:", candidates)

p = candidates[0]
print("p =", p)

# Step 2: compute x
x = (b * mod_inverse(a, p)) % p
print("x =", x)

# Optional: verify sequence
print("Verification:")
current = a
for _ in range(len(nums)):
    print(current, end=" ")
    current = (current * x) % p
