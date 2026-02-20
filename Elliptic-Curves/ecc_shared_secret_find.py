from tinyec.ec import SubGroup, Curve, Point
import hashlib

# Define the finite field and curve
p = 9739
a = 497
b = 1768

# Subgroup / curve
field = SubGroup(p=p, g=(1804, 5368), n=p, h=1)
curve = Curve(a=a, b=b, field=field, name='StarterCurve')

# Alice's public key
Q_A = Point(curve, 815, 3190)  # Create point with x=815, y=3190

# Your secret integer
n_B = 1829

# Compute shared secret S = n_B * Q_A
S = n_B * Q_A

print("Shared secret S:", S)

# Use x-coordinate to generate SHA1 hash
x_coord = S.x
key = hashlib.sha1(str(x_coord).encode()).hexdigest()

print("Flag: crypto{" + key + "}")
