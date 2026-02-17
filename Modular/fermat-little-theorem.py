p = 17
print(3**17 % p)
print(5**17 % p)  
print(7**17 % p)  

p = 65537
a = 273246787654
print(a**65536 % p)  # a^(p-1) mod p
