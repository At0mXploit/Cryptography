# Given primes and public exponent
p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537

# Compute Euler's totient
phi_N = (p - 1) * (q - 1)

# Compute modular inverse to get private key
d = pow(e, -1, phi_N)

print(d)

