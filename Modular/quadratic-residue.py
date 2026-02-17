p = 29

ints = [14, 6, 11]

for x in ints:
    found = False  

    # Check all possible values a from 1 to p-1
    for a in range(1, p):
        # If a^2 ≡ x (mod p), then x is a quadratic residue
        if (a * a) % p == x:
            found = True  

            # Two roots exist: a and -a mod p
            root1 = a
            root2 = p - a

            smaller_root = min(root1, root2)

            print(f"{x} is a quadratic residue. Square roots: {root1}, {root2}. Smaller root: {smaller_root}")

            break  

    # If no square root was found, x is a quadratic non-residue
    if not found:
        print(f"{x} is a quadratic non-residue.")

