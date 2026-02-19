from sympy import factorint

# The 150-bit number
n = 510143758735509025530880200653196460532653147

# Factor it
factors = factorint(n)  # Returns a dictionary {prime: exponent}

# Get the list of prime factors and sort them
primes = sorted(factors.keys())

# Print the smaller prime
print(primes[0])

