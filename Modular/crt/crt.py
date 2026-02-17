from sympy.ntheory.modular import crt

remainders = [2, 3, 5]
moduli = [5, 11, 17]

# crt returns (solution, N) where N = product of moduli
solution, N = crt(moduli, remainders)
print(solution)
