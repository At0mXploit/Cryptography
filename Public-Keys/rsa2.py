# RSA parameters
p = 17
q = 23
e = 65537
m = 12  # message

# Compute modulus
N = p * q

# Encrypt the message
ciphertext = pow(m, e, N)

print(ciphertext)

