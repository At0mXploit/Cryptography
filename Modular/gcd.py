def gcd(a,b):
    while b:
        a,b = b, a % b
    return a 
print(gcd(66528, 52920))
