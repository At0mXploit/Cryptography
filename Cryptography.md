# Symmetric Cryptography

Symmetric cryptography uses a single secret key for both encrypting and decrypting data, ensuring that only parties with the key can access the original information.
## XOR

Strangely enough, we'll start our crypto journey with the humble [Exclusive Or](https://en.wikipedia.org/wiki/Exclusive_or) (XOR) operator. An XOR is one of the most common [bitwise operators](https://en.wikipedia.org/wiki/Logical_connective) that you will encounter in your security journey, _especially_ in cryptography. A couple of terms to unpack here...

**Bitwise.** Remember from [Dealing with Data](https://pwn.college/fundamentals/data-dealings/) that computers think in binary! That is, they conceptualize numbers in [base 2](https://www.google.com/search?q=learn+number+bases), so something like `9` is expressed as `1001`. An XOR operates on one pair of bits at a time, resulting in `1` if the bits are different (one is `1` and the other is `0`) or `0` if they are the same (both `1` or both `0`). It is then applied to every bit pair independently, and the results are concatenated. For example, decimal `9` (`1001`) XORed with decimal `5` (`0101`) results in `1100` (decimal 12).

**Cryptography.** Why is XOR so common in crypto? In cryptography, it is common because it is [_self-inverse_](https://en.wikipedia.org/wiki/Exclusive_or#Properties)! That is (using `^` for XOR here, which is consistent with many programming languages), `5 ^ 9 == 12`, and `12 ^ 9 == 5`. If the number `9` is a key only known to you and me, I can send you messages by XORing them with `9`, and you can recover the message with XORing them with `9` as well! Obviously, we can achieve this property with me adding 9 and you subtracting 9, without using XOR, but this requires more complex circuitry and extra bits (e.g., to handle "carrying the 1" in `1111 + 0001 == 10000`), whereas XOR does not have this problem (`1111 ^ 0001 == 1110`).

In this level, you will learn to XOR! We'll give you a shared _key_, `XOR` a secret number with it, and expect you to recover the number.
### Solution

```bash
hacker@cryptography~xor:~$ /challenge/run
The key: 208
Encrypted secret: 63
Decrypted secret? 
```

```bash
>>> 208 ^ 63
239
```
## XORing Hex

Of course, as you also learned in [Dealing with Data](https://pwn.college/fundamentals/data-dealings), we tend to represent values in computer memory as _hexadecimal_. If you don't remember what that is, go back and review those levels. Otherwise, go forth and practice some hexadecimal XOR here!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import random
import sys

for n in range(10):
    print(f"Challenge number {n}...")

    key = random.randrange(1, 256)
    plain_secret = random.randrange(0, 256)
    cipher_secret = plain_secret ^ key

    print(f"The key: {key:#04x}")
    print(f"Encrypted secret: {cipher_secret:#04x}")
    answer = int(input("Decrypted secret? "), 16)
    print(f"You entered: {answer:#04x}, decimal {answer}.")
    if answer != plain_secret:
        print("INCORRECT!")
        sys.exit(1)

    print("Correct! Moving on.")

print("CORRECT! Your flag:")
print(open("/flag").read())
```

```python
#!/usr/bin/env python3
from pwn import *

p = process('/challenge/run')

while True:
    try:
        # Get key
        p.recvuntil(b'The key: ')
        key = int(p.recvline(), 16)
        
        # Get cipher
        p.recvuntil(b'Encrypted secret: ')
        cipher = int(p.recvline(), 16)
        
        # Send answer
        answer = key ^ cipher
        p.sendline(hex(answer))
    except:
        break

# Get flag
print(p.recvall().decode())
p.close()
```
## XORing ASCII

The cool thing is that, since ASCII puts byte values to characters, we can do operations like XOR! This has obvious implications for cryptography.

In this level, we'll explore these implications byte by byte. The challenge will give you one letter a time, along with a key to "decrypt" (XOR) the letter with. You give us the result of the XOR. For example:

```console
hacker@dojo:~$ /challenge/run
Challenge number 0...
- Encrypted Character: A
- XOR Key: 0x01
- Decrypted Character?
```

How would you approach this? You can `man ascii` and find the entry for A:

```none
Oct   Dec   Hex   Char
──────────────────────
101   65    41    A
```

So A is `0x41` in hex. You would XOR that with `0x01` The result here would be: `0x41 ^ 0x01 == 0x40`, and, according to `man ascii`:

```none
Oct   Dec   Hex   Char
──────────────────────
100   64    40    @
```

It's the @ character!

```console
hacker@dojo:~$ /challenge/run
Challenge number 0...
- Encrypted Character: A
- XOR Key: 0x01
- Decrypted Character? @
Correct! Moving on.
```

Now it's your turn! Can you XOR things up and get the flag?
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import random
import string
import sys

if not sys.stdin.isatty():
    print("You must interact with me directly. No scripting this!")
    sys.exit(1)

for n in range(1, 10):
    print(f"Challenge number {n}...")
    pt_chr, ct_chr = random.sample(
        string.digits + string.ascii_letters + string.punctuation,
        2
    )
    key = ord(pt_chr) ^ ord(ct_chr)

    print(f"- Encrypted Character: {ct_chr}")
    print(f"- XOR Key: {key:#04x}")
    answer = input("- Decrypted Character? ").strip()
    if answer != pt_chr:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

```python
#!/usr/bin/env python3
from pwn import *

# Use PTY constant from pwntools
p = process('/challenge/run', stdin=PTY, stdout=PTY)

try:
    while True:
        p.recvuntil(b'- Encrypted Character: ')
        c = p.recvline().strip().decode()

        p.recvuntil(b'- XOR Key: ')
        k = int(p.recvline().strip(), 16)

        answer = chr(ord(c) ^ k)
        p.sendline(answer)

except:
    pass

print(p.recvall().decode())
p.close()
```
## XORing ASCII Strings

Okay, now you know how to XOR ASCII characters. This is a critical step as we build up to our first cryptosystem, but now, we need to XOR entire ASCII strings! Let's try this.

Like Python provides the `^` operator to XOR integers, a Python library called PyCryptoDome provides a function called `strxor` to XOR two strings of characters together. You can import it in Python using `from Crypto.Util.strxor import strxor`.

XORing two strings is done byte by byte, just like XORing two bytes is done bit by bit. So, to draw on an earlier example:

```console
hacker@dojo:~$ python
>>> from Crypto.Util.strxor import strxor
>>> strxor(b"AAA", b"16/")
b'pwn'
```

You can verify this yourself with the ASCII table: A ^ 1 is p, A ^ 6 is w, and A ^ / is n. We just decrypted the _ciphertext_ `AAA` with the _key_ `16/` to retrieve the _plaintext_ `pwn`.

In this challenge, you'll do this several times in a row: like the previous challenge, but with strings! Good luck!

**CAVEAT:** What are these `b`s prepended to the quotes? Python's default string representation (e.g., `"AAA"`) is [_Unicode_](https://en.wikipedia.org/wiki/Unicode), and unlike, say, the Latin alphabet, Unicode encompasses all characters known to humanity (including the Latin alphabet)! This means a single character can have thousands of different values (when this text was written, Unicode encompassed 154,998 characters!), from "A" to "💩".

Unfortunately, a single byte of 8 bits can only hold `2**8 == 256` different values, which is enough for ASCII (not that many letters/numbers/etc in the Latin alphabet), but not enough for Unicode. Unicode is _encoded_ using different encodings, such as the [UTF-8](https://en.wikipedia.org/wiki/UTF-8) we mentioned earlier. UTF-8 is designed to be backwards-compatible with ASCII "A" is just 0x41, something like "💩" is _four_ bytes: `f0 9f 92 a9`!

Basically, `ASCII` is to `The Latin Alphabet` as `UTF-8` is to `Unicode`, and in the same way that the Latin alphabet is a subset of Unicode, ASCII is a subset of UTF-8. Wild.

Anyways, Python's normal strings (and, typically, `input()` you get from the terminal) are Unicode, but some functions, such as `strxor`, consume and produce _bytes_. You can specify them directly, as I did above, by prepending your quotes with `b` (for **b**ytes) and using ASCII or hex encoding (e.g., `b"AAA"` and `b"A\x41\x41"` are equivalent), or you can _encode_ a Unicode string into bytes using UTF-8, as such: `"AAA".encode() == b"AAA"` or `"💩".encode() == b"\xf0\x9f\x92\xa9"`. You can also _decode_ the resulting bytes back into Unicode strings: `b"AAA".decode() == "AAA"` or `b"\xf0\x9f\x92\xa9".decode() == "💩"`.

This is _further_ complicated by the fact that UTF-8 can't turn any arbitrary bytes into Unicode. For example, `b'\xb0'.decode()` raises an exception. You can fix this by abandoning the default UTF-8 and using a pre-Unicode non-encoding encoding like "[latin](https://en.wikipedia.org/wiki/ISO/IEC_8859-1)"/ISO-8859-1, from the ancient days of computing, as so: `b'\xb0'.decode('latin')`. While ISO-8859-1 originally predated Unicode, its Python implementation converts to Unicode strings. However, keep in mind that this encoding is _different_ from UTF-8: `b"\xb0".encode('latin").decode() == b'\xc2\xb0'`. You must, instead, be consistent and decode and encode with the same encoding: `b"\xb0".encode('latin").decode(latin1) == b"\xb0"`.

Anyways, all this sounds terrifying, but it's mostly a warning for the future. For _this_ level, we VERY carefully chose the characters so that you don't run into these issues.

**CAUTION:** Python's strings-vs-bytes situation is terrible and _will_ byte (haha!) you eventually. There's no way to avoid pitfalls --- they still get us after years and years of using Python, so you will just have to learn to pick yourself up, brush yourself off, fix your code, and carry on. With enough experience under your belt, you will improve from losing _entire freaking days_ to bugs caused by string/bytes mixups to merely _entire freaking hours_.
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import random
import string
import sys

from Crypto.Util.strxor import strxor

valid_keys = "!#$%&()"
valid_chars = ''.join(
    c for c in string.ascii_letters
    if all(chr(ord(k)^ord(c)) in string.ascii_letters for k in valid_keys)
)

print(valid_keys, valid_chars)

for n in range(1, 10):
    print(f"Challenge number {n}...")

    key_str = ''.join(random.sample(valid_keys*10, 10))
    pt_str = ''.join(random.sample(valid_chars*10, 10))
    ct_str = strxor(pt_str.encode(), key_str.encode()).decode()

    print(f"- Encrypted String: {ct_str}")
    print(f"- XOR Key String: {key_str}")
    answer = input("- Decrypted String? ").strip()
    if answer != pt_str:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

```python
#!/usr/bin/env python3
from pwn import *
from Crypto.Util.strxor import strxor

p = process('/challenge/run', stdin=PTY, stdout=PTY)

try:
    while True:
        p.recvuntil(b'- Encrypted String: ')
        ct = p.recvline().strip().decode()
        
        p.recvuntil(b'- XOR Key String: ')
        key = p.recvline().strip().decode()
        
        # strxor(ct, key) gives us plaintext
        answer = strxor(ct.encode(), key.encode()).decode()
        p.sendline(answer)
        
except:
    pass

print(p.recvall().decode())
p.close()
```
## One-time Pad

In this challenge you will decrypt a secret encrypted with a [one-time pad](https://en.wikipedia.org/wiki/One-time_pad). Although simple, this is the most secure encryption mechanism, if a) you can securely transfer the key and b) you only ever use the pad _once_. It's also the most simple encryption mechanism: you simply _XOR_ the bits of the plaintext with the bits of the key one by one!

This challenge encrypts the flag with a one-time pad and then gives you the key. Luckily, a one-time pad is a _symmetric_ cryptosystem: that is, you use the same key to encrypt and to decrypt, so you have everything you need to decrypt the flag!

**Fun fact:** the One-time Pad is the _only_ cryptosystem that humanity has been able to _prove_ is perfectly secure. If you securely transfer the key, and you only use it for one message, it cannot be cracked even by attackers with infinite computational power! We have not been able to make this proof for any other cryptosystem.

**One-Time Pad (OTP)** is a theoretically unbreakable encryption method where:

1. **Key = random bits**, same length as the plaintext
2. **Encryption**: `ciphertext = plaintext ⊕ key` (XOR operation)
3. **Decryption**: `plaintext = ciphertext ⊕ key` (same XOR operation)
4. **Key is used only once** (hence "one-time
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

flag = open("/flag", "rb").read()

key = get_random_bytes(len(flag))
ciphertext = strxor(flag, key)

print(f"One-Time Pad Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```bash
hacker@cryptography~one-time-pad:~$ /challenge/run
One-Time Pad Key (hex): b55ce9277f8dde70048809ed1116b7ec5a0c1fc018548c11069197d869f76150838cd6afdcc58e086a7a40dddd412f836dfe5e1e906ec88e2c12e5d0
Flag Ciphertext (hex): c52b87091ce2b21c61ef6c967670dca80c4128b85d16bb5f36f7f99b0da2343cc9fcbfe08d82a3263b2270bea70c55f42eb02679fa20f8cb564598da
```

```python
#!/usr/bin/env python3
from Crypto.Util.strxor import strxor

# Hex strings from challenge
key_hex = "b55ce9277f8dde70048809ed1116b7ec5a0c1fc018548c11069197d869f76150838cd6afdcc58e086a7a40dddd412f836dfe5e1e906ec88e2c12e5d0"
ciphertext_hex = "c52b87091ce2b21c61ef6c967670dca80c4128b85d16bb5f36f7f99b0da2343cc9fcbfe08d82a3263b2270bea70c55f42eb02679fa20f8cb564598da"

# Convert hex to bytes
key = bytes.fromhex(key_hex)
ciphertext = bytes.fromhex(ciphertext_hex)

# Decrypt using strxor: flag = ciphertext XOR key
flag_bytes = strxor(ciphertext, key)

# Convert to string
flag = flag_bytes.decode()
print(flag)
```
## One-time Pad Tampering

So, the One Time Pad is proven to be secure... but only in the _Confidential_ sense! It actually does not guarantee anything about Integrity. This challenge asks you: what if you could _tamper_ with the message in transit? Think about how XOR works, and see if you can get the flag!
### Solution

```bash
hacker@cryptography~one-time-pad-tampering:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Util.strxor import strxor

key = open("/challenge/.key", "rb").read()
ciphertext = strxor(b"sleep", key[:5])

print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~one-time-pad-tampering:~$ cat /challenge/worker
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Util.strxor import strxor

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    cipher_len = min(len(data), len(key))
    plaintext = strxor(data[:cipher_len], key[:cipher_len])

    print(f"Hex of plaintext: {plaintext.hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == b"sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == b"flag!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

The dispatcher creates a ciphertext of `"sleep"` XORed with the first 5 bytes of the key. The worker decrypts commands and executes them. We need to send a modified ciphertext that decrypts to `"flag!"` instead of `"sleep"`.

```bash
hacker@cryptography~one-time-pad-tampering:~$ /challenge/dispatcher 
TASK: 0e39c5c9a2
```

Now this cipher `0e39c5c9a2` will decrypt to sleep but we want to modify it such that it decrypts to `flag!` instead. Since XOR is reversible:  if `A XOR B = C`, then `A XOR C = B`

Original: `ciphertext = "sleep" XOR key`

Therefore: `key = ciphertext XOR "sleep"`

We want: `new_ciphertext XOR key = "flag!"`

Substitute `key`: `new_ciphertext XOR (ciphertext XOR "sleep") = "flag!"`

Simplify: `new_ciphertext = ciphertext XOR "sleep" XOR "flag!"`

```python
#!/usr/bin/env python3
from Crypto.Util.strxor import strxor

# Get the ciphertext from dispatcher
ciphertext_hex = "0e39c5c9a2"
ciphertext = bytes.fromhex(ciphertext_hex)

# Messages
sleep = b"sleep"
flag = b"flag!"

# Calculate: new = ciphertext XOR (sleep XOR flag!)
# Using strxor from Crypto library
sleep_xor_flag = strxor(sleep, flag)  # sleep XOR flag!
new_ciphertext = strxor(ciphertext, sleep_xor_flag)  # ciphertext 

print(f"TASK: {new_ciphertext.hex()}")
```

```bash
hacker@cryptography~one-time-pad-tampering:~$ python3 main.py
TASK: 1b39c1cbf3
hacker@cryptography~one-time-pad-tampering:~$ /challenge/worker 
TASK: 1b39c1cbf3
Hex of plaintext: 666c616721
Received command: b'flag!'
Victory! Your flag:
pwn.college{g29OM_moeAmWxM3G-RzqxscHvDI.01M3kjNxwCNxgjN0EzW}
```
# Many-time Pad

The previous challenge gave you the one time pad to decrypt the ciphertext. If you did not know the one time pad, and it was only ever used for one message, the previous challenge would be unsolvable! In this level, we'll explore what happens if the latter condition is violated. You don't get the key this time, but we'll let you encrypt as many messages as you want. Can you decrypt the flag?

**Hint:** think deeply about how XOR works, and consider that it is a distributative, commutative, and associative operation...

**Hint:** we recommend writing your solution in Python and using the `strxor` function that we use in the challenge! It makes life much simpler.
### Solution

```python
hacker@cryptography~many-time-pad:~$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

flag = open("/flag", "rb").read()

key = get_random_bytes(256)
ciphertext = strxor(flag, key[:len(flag)])

print(f"Flag Ciphertext (hex): {ciphertext.hex()}")

while True:
    plaintext = bytes.fromhex(input("Plaintext (hex): "))
    ciphertext = strxor(plaintext, key[:len(plaintext)])
    print(f"Ciphertext (hex): {ciphertext.hex()}")
```

The flag is encrypted with: 

```python
ciphertext_flag = flag XOR key
```

If we sent the same `ciphertext_flag` as plaintext:

```python
plaintext = ciphertext_flag
```

```python
ciphertext = plaintext XOR key
```

So in this case:

```python
ciphertext_returned = (flag XOR key) XOR key
```

Using associative property:

```python
(flag XOR key) XOR key
= flag XOR (key XOR key)
```

```python
key XOR key = 00 00 00 00 ...
```

So key gets cancelled and we get `flag XOR 0` which will be `flag`

```bash
hacker@cryptography~many-time-pad:~$ /challenge/run
Flag Ciphertext (hex): b4ac31d3af6a1c1f19a1ffcb99985904ffeb865855bfc67fd098ebd9820bf0389189b845e3ae07a2360485968bc6bae92c61216a0b48b0b858a43ae1
Plaintext (hex): b4ac31d3af6a1c1f19a1ffcb99985904ffeb865855bfc67fd098ebd9820bf0389189b845e3ae07a2360485968bc6bae92c61216a0b48b0b858a43ae1
Ciphertext (hex): 70776e2e636f6c6c6567657b345a65576b415f454c595838646e4d31566a5a2d614f35343945392e515831637a4d7a77434e78676a4e30457a577d0a
```

```bash
>>> bytes.fromhex("70776e2e636f6c6c6567657b345a65576b415f454c595838646e\
4d31566a5a2d614f35343945392e515831637a4d7a77434e78676a4e30457a577d0a")
b'pwn.college{4ZeWkA_ELYX8dnM1VjZ-aO549E9.QX1czMzwCNxgjN0EzW}\n
```
## AES

So, One Time Pads fail when you reuse them. This is suboptimal: given how careful one has to be when transferring keys, it would be better if the key could be used for more than just a single message!

Enter: the [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), AES. AES is relatively new: coming on the scene in 2001. Like a One-time Pad, AES is _also_ symmetric: the same key is used to encrypt and decrypt. Unlike a One-time Pad, AES maintains security for multiple messages encrypted with the same key.

In this challenge you will decrypt a secret encrypted with Advanced Encryption Standard (AES).  
AES is what is called a "block cipher", encrypting one plaintext "block" of 16 bytes (128 bits) at a time. So `AAAABBBBCCCCDDDD` would be a single block of plaintext that would be encrypted into a single block of ciphertext.

AES _must_ operate on complete blocks. If the plaintext is _shorter_ than a block (e.g., `AAAABBBB`), it will be _padded_ to the block size, and the padded plaintext will be encrypted.

Different AES "modes" define what to do when the plaintext is longer than one block. In this challenge, we are using the simplest mode: "[Electronic Codebook (ECB)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_\(ECB\))". In ECB, each block is encrypted separately with the same key and simply concatenated together. So if you are encrypting something like `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH`, it will be split into two plaintext blocks (`AAAABBBBCCCCDDDD` and `EEEEFFFFGGGGHHHH`), encrypted separately (resulting, let's imagine, in `UVSDFGIWEHFBFFCA` and `LKXBFVYASLJDEWEU`), then concatenated (resulting the ciphertext `UVSDFGIWEHFBFFCALKXBFVYASLJDEWEU`).

This challenge will give you the AES-encrypted flag and the key used to encrypt it. We won't learn about the internals of AES, in terms of how it actually encrypts the raw bytes. Instead, we'll learn about different _applications_ of AES, and how they break down in practice. If you're interested in learning about AES internals, we can highly recommend [CryptoHack](https://cryptohack.org/courses/), an amazing learning resource that focuses on the nitty gritty details of crypto!

Now, go decrypt the flag and score!

**HINT:** We use the [PyCryptoDome](https://www.pycryptodome.org/) library to implement the encryption in this level. You'll want to read its documentation to figure out how to implement your decryption!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(flag, cipher.block_size))

print(f"AES Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```bash
hacker@cryptography~aes:~$ /challenge/run
AES Key (hex): f739514940660e7da8ce35b9cebae3ae
Flag Ciphertext (hex): 365efdedf9648cc1a1cd350c8aefda7d2c87f170a17f47fccec293a660e7b8e01bc9f05e918b52a3ebe5d63dfea42b6915f9c9a50b6c587638ccd877b9a895f4
```

AES is reversible:

```
ciphertext = encrypt(flag, key)
```

If we have key we can decrypt it:

```
flag = decrypt(ciphertext, key)
```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key_hex = "f739514940660e7da8ce35b9cebae3ae"
ciphertext_hex = "365efdedf9648cc1a1cd350c8aefda7d2c87f170a17f47fccec293a660e7b8e01bc9f05e918b52a3ebe5d63dfea42b6915f9c9a50b6c587638ccd877b9a895f4"

# Convert hex to bytes
key = bytes.fromhex(key_hex)
ciphertext = bytes.fromhex(ciphertext_hex)

# Create AES ECB cipher
cipher = AES.new(key, AES.MODE_ECB)

# Decrypt
plaintext_padded = cipher.decrypt(ciphertext)

# Remove padding
plaintext = unpad(plaintext_padded, AES.block_size)

print(plaintext.decode())
```
## AES-ECB-CPA

Though the core of the AES crypto algorithm is thought to be secure (not _proven_ to be, though: no one has managed to do that! But no one has managed to significantly break the crypto in the 20+ years of its use, either), this core only encrypts 128-bit (16 byte) blocks at a time. To actually _use_ AES in practice, one must build a _cryptosystem_ on top of it.

In the previous level, we used the AES-[ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_\(ECB\)) cryptosystem: an Electronic Codebook Cipher where every block is independently encrypted by the same key. This system is quite simple but, as we will discover here, extremely susceptible to a certain class of attack.

Cryptosystems are held to very high standard of [ciphertext indistinguishability](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability). That is, an attacker that lacks the key to the cryptosystem should not be able to distinguish between pairs of ciphertext based on the plaintext that was encrypted. For example, if the attacker looks at ciphertexts `UVSDFGIWEHFBFFCA` and `LKXBFVYASLJDEWEU`, and is able to determine that the latter was produced from the plaintext `EEEEFFFFGGGGHHHH` (or, in fact, figure out _any_ information about the plaintext at all!), the cryptosystem is considered broken. This property must hold even if the attacker already knows part or all of the plaintext, a setting known as the [Known Plaintext Attack](https://en.wikipedia.org/wiki/Known-plaintext_attack), _or can even control part or all of the plaintext_, a setting known as the [Chosen Plaintext Attack](https://en.wikipedia.org/wiki/Chosen-plaintext_attack)!

ECB is susceptible to both known and chosen plaintext attack. Because every block is encrypted with the same key, with no other modifications, an attacker can observe identical ciphertext across different blocks that have identical plaintext. Moreover, if the attacker can choose or learn the plaintext associated with some of these blocks, they can carefully build a mapping from known-plaintext to known-ciphertext, and use that as a lookup table to decrypt other matching ciphertext!

In this level, you will do just this: you will build a codebook mapping from ciphertext to chosen plaintext, then use that to decrypt the flag. Good luck!

**HINT:** You might find it helpful to automate interactions with this challenge. You can do so using the `pwntools` Python package. Check out [this pwntools cheatsheet](https://gist.github.com/anvbis/64907e4f90974c4bdd930baeb705dedf) from a fellow pwn.college student!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

while True:
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Encrypt part of the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        index = int(input("Index? "))
        length = int(input("Length? "))
        pt = flag[index:index+length]
    else:
        break

    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Result: {ct.hex()}")
```

```bash
hacker@cryptography~aes-ecb-cpa:~$ /challenge/run
Choose an action?
1. Encrypt chosen plaintext.
2. Encrypt part of the flag.
Choice? 
```

```bash
hacker@cryptography~aes-ecb-cpa:~$ /challenge/run
Choose an action?
1. Encrypt chosen plaintext.
2. Encrypt part of the flag.
Choice? 2
Index? 0
Length? 1
Result: 47f894c00549813a46b1667f1ae0fdc0
Choose an action?
3. Encrypt chosen plaintext.
4. Encrypt part of the flag.
Choice? 1
Data? p
Result: 47f894c00549813a46b1667f1ae0fdc0
Choose an action?
5. Encrypt chosen plaintext.
```

Like this we can confirm flag starts with `p`. Now we can just repeat for every index.

```python
from pwn import *
import string

p = process("/challenge/run")

flag = ""
i = 0

while True:

    # --- get ciphertext of flag[i] ---
    p.recvuntil("Choice? ")
    p.sendline("2")
    p.recvuntil("Index? ")
    p.sendline(str(i))
    p.recvuntil("Length? ")
    p.sendline("1")
    p.recvuntil("Result: ")
    target = p.recvline().strip()

    found = False

    # --- try all printable chars ---
    for c in string.printable:
        p.recvuntil("Choice? ")
        p.sendline("1")
        p.recvuntil("Data? ")
        p.sendline(c)
        p.recvuntil("Result: ")
        test = p.recvline().strip()

        if test == target:
            flag += c
            print(flag)
            i += 1
            found = True
            break
```
## AES-ECB-CPA-HTTP

Okay, now we'll try that attack in a slightly more realistic scenario. Can you remember your SQL to carry out the attack and recover the flag? 

**HINT:** Remember that you can make select return chosen plaintext by doing `SELECT 'my_plaintext'`!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
import random
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE secrets AS SELECT ? AS flag""", [open("/flag").read()])

@app.route("/", methods=["GET"])                                                                                                             
def challenge_get():
    query = flask.request.args.get("query") or "'A'"

    try:
        sql = f'SELECT {query} FROM secrets'
        print(f"DEBUG: {sql=}")
        pt = db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")
    except TypeError:
        # no records found
        pt = "A"

    ct = cipher.encrypt(pad(pt.encode(), cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='{query}'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{sql}</pre><br>
        <b>Results:</b><pre>{ct.hex()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```bash
hacker@cryptography~aes-ecb-cpa-http:~$ curl "http://challenge.localhost/?query='p'"
DEBUG: sql="SELECT 'p' FROM secrets"
127.0.0.1 - - [08/Dec/2025 10:53:15] "GET /?query='p' HTTP/1.1" 200 -

        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value=''p''> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT 'p' FROM secrets</pre><br>
        <b>Results:</b><pre>679e20fa8a1e04bac4bd72e4907ad378</pre>
        </body></html>
    hacker@cryptography~aes-ecb-cpa-http:~$ curl 'http://challenge.localhost/?query=substr(flag,1,1)'
DEBUG: sql='SELECT substr(flag,1,1) FROM secrets'
127.0.0.1 - - [08/Dec/2025 10:53:19] "GET /?query=substr(flag,1,1) HTTP/1.1" 200 -

        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='substr(flag,1,1)'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT substr(flag,1,1) FROM secrets</pre><br>
        <b>Results:</b><pre>679e20fa8a1e04bac4bd72e4907ad378</pre>
        </body></html>
```

This is same as previous but we are using `query=p` to encrypt `p` and then using `query?substr(flag,1,1)` to get the first index of encrypted character.

```python
from pwn import *
import string
import urllib.parse

def enc(query):
    # send GET request: /?query=...
    url = "/?query=" + urllib.parse.quote(query)
    r = remote("challenge.localhost", 80)
    r.sendline(f"GET {url} HTTP/1.1")
    r.sendline("Host: challenge.localhost")
    r.sendline()
    data = r.recvall()
    r.close()
    # extract ciphertext hex
    start = data.rfind(b"<pre>") + 5
    end = data.find(b"</pre>", start)
    return data[start:end].strip()

flag = ""
i = 1  # SQLite is 1-indexed

charset = string.printable

while True:
    # ciphertext of real flag byte
    target = enc(f"substr(flag,{i},1)")

    found = False
    for c in charset:
        test = enc(f"'{c}'")
        if test == target:
            flag += c
            print(flag)
            i += 1
            found = True
            break

    if not found:
        print("\nFlag ended.")
        print(flag)
        break
```
## AES-ECB-CPA-HTTP (base64)

For historical reasons, different encodings tend to gain traction in different contexts. For example, on the web, the standard way to encode binary data is base64, an encoding that you learned in [Dealing with Data](https://pwn.college/fundamentals/data-dealings). Channel this skill now, adapting your previous solution for base64!

You'll (re-)note that base64 isn't as convenient to reason about as hex. Why do people use it? One reason: every byte requires _two_ hex letters to encode, whereas base64 encodes every 3 bytes with 4 letters. This means that, when sending each letter as a byte itself over the network, for example, base64 is marginally more efficient. On the other hand, it's a headache to work with, because of the unclean bit boundaries!

Throughout the rest of the modules, challenges might use hex or base64, as our heart desires. It's important to be able to handle either!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
import random
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE secrets AS SELECT ? AS flag""", [open("/flag").read()])

@app.route("/", methods=["GET"])                                                                                                             
def challenge_get():
    query = flask.request.args.get("query") or "'A'"

    try:
        sql = f'SELECT {query} FROM secrets'
        print(f"DEBUG: {sql=}")
        pt = db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")
    except TypeError:
        # no records found
        pt = "A"

    ct = cipher.encrypt(pad(pt.encode(), cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='{query}'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{sql}</pre><br>
        <b>Results:</b><pre>{b64encode(ct).decode()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```bash
hacker@cryptography~aes-ecb-cpa-http-base64:~$ curl "http://challenge.localhost/?query='p'"

        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value=''p''> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT 'p' FROM secrets</pre><br>
        <b>Results:</b><pre>CTKvDjqeQdb4Lll6At3Yog==</pre>
        </body></html>
hacker@cryptography~aes-ecb-cpa-http-base64:~$ curl "http://ch
allenge.localhost/?query=substr(flag,1,1)"

        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='substr(flag,1,1)'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT substr(flag,1,1) FROM secrets</pre><br>
        <b>Results:</b><pre>CTKvDjqeQdb4Lll6At3Yog==</pre>
        </body></html>
```

It is same as previous you just need to decode the base64. (Actually we don't even need to). Its exactly the same.

```python
from pwn import *
import string
import urllib.parse

def enc(query):
    url = "/?query=" + urllib.parse.quote(query)
    r = remote("challenge.localhost", 80)
    r.sendline(f"GET {url} HTTP/1.1")
    r.sendline("Host: challenge.localhost")
    r.sendline()
    data = r.recvall()
    r.close()

    # Extract Base64 inside <pre>...</pre>
    start = data.rfind(b"<pre>") + 5
    end   = data.find(b"</pre>", start)
    return data[start:end].strip()

flag = ""
i = 1
charset = string.printable

while True:
    target = enc(f"substr(flag,{i},1)")

    found = False
    for c in charset:
        test = enc(f"'{c}'")
        if test == target:
            flag += c
            print(flag)
            i += 1
            found = True
            break

    if not found:
        print("Flag ended.")
        print("Flag:", flag)
        break
```
## AES-ECB-CPA-Suffix

Okay, now let's complicate things slightly to increase the realism. It's rare that you can just craft queries for the plaintext that you want. However, it's less rare that you can isolate the _tail end_ of some data into its own block, and in ECB, this is bad news. We'll explore this concept in this challenge, replacing your ability to query substrings of the flag with just an ability to encrypt some bytes off the end.

Show us that you can still solve this!

**HINT:** Keep in mind that, once you recover some part of the end of the flag, you can build a new codebook with additional prefixes of the known parts, and repeat the attack on the previous byte!
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

while True:
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Encrypt the tail end of the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        length = int(input("Length? "))
        pt = flag[-length:]
    else:
        break

    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Result: {ct.hex()}")
```

```bash
hacker@cryptography~aes-ecb-cpa-suffix:~$ /challenge/run
Choose an action?
1. Encrypt chosen plaintext.
2. Encrypt the tail end of the flag.
Choice? 2
Length? 1
Result: 3e08143d0eea1cf67a26dd7ecd3557c5
Choose an action?
3. Encrypt chosen plaintext.
4. Encrypt the tail end of the flag.
Choice? 1
Data? }
Result: 3e08143d0eea1cf67a26dd7ecd3557c5
Choose an action?
5. Encrypt chosen plaintext.
6. Encrypt the tail end of the flag.
```

This is exactly same as first AES-CPA one except we dont have index this time:

```bash
You cannot ask for flag[i]
You can ONLY ask for the last N bytes
```

So the correct equivalent of:

```bash
Index? i
Length? 1
```

is:

```bash
Length? k
→ returns flag[-k:]
```

But here is the problem. Okay say somehow we got the flag till 15th position of end: (i.e `zN5wCNxgjN0EzW}`)

```bash
hacker@cryptography~aes-ecb-cpa-suffix:~$ /challenge/run
Choose an action?
1. Encrypt chosen plaintext.
2. Encrypt the tail end of the flag.
Choice? 2
Length? 2
Result: c4dfc23f96319d16098dc5a6f7da03e3
Choose an action?
3. Encrypt chosen plaintext.
4. Encrypt the tail end of the flag.
Choice? 1
Data? W}
Result: c4dfc23f96319d16098dc5a6f7da03e3
Choose an action?
5. Encrypt chosen plaintext.
6. Encrypt the tail end of the flag.
Choice? 1
Data? zW}
Result: 73948205c9a1dba64b750dd0c7dba180
Choose an action?
7. Encrypt chosen plaintext.
8. Encrypt the tail end of the flag.
Choice? 2
Length? 3
Result: 73948205c9a1dba64b750dd0c7dba180
Choose an action?
9. Encrypt chosen plaintext.
10. Encrypt the tail end of the flag.
Choice? 1              
Data? zN5wCNxgjN0EzW}
Result: e239c39754265ea5b9a5977755b24ebd
Choose an action?
11. Encrypt chosen plaintext.
12. Encrypt the tail end of the flag.
Choice? 2
Length? 15
Result: e239c39754265ea5b9a5977755b24ebd
Choose an action?
13. Encrypt chosen plaintext.
14. Encrypt the tail end of the flag.
Choice? 
```

But now if we try at 16th.

```bash
hacker@cryptography~aes-ecb-cpa-suffix:~$ /challenge/run
Choose an action?
1. Encrypt chosen plaintext.
2. Encrypt the tail end of the flag.
Choice? 1
Data? azN5wCNxgjN0EzW}
Result: 3238f71e7173cf51761976fbf572f858a28618933ccf8a74c91674607e926d6b
Choose an action?
3. Encrypt chosen plaintext.
4. Encrypt the tail end of the flag.
Choice? 2
Length? 16
Result: 5bb5ac2e993471593641ef628df2e932a28618933ccf8a74c91674607e926d6b
Choose an action?
5. Encrypt chosen plaintext.
6. Encrypt the tail end of the flag.
Choice? 1
Data? bzN5wCNxgjN0EzW}
Result: 4574cdd025ff1bf7aa0582b478e17b15a28618933ccf8a74c91674607e926d6b
Choose an action?
7. Encrypt chosen plaintext.
8. Encrypt the tail end of the flag.
```

Since AES ECB encrypts every 16 byte independently so last 16 bytes will always be same as you can see above. When we tried `azN5wCNxgjN0EzW}` and `bzN5wCNxgjN0EzW}` last 16 bytes were same because it were of `zN5wCNxgjN0EzW}`. So we can't ever try 16 bytes while guessing.

So correct way to get the 16 suffix would be:

```bash
candidate = c + zN5wCNxgjN0EzW}
```

Test it:

```bash
Choice? 1
Data? <candidate>
Result: <ciphertext>
```

So summary:

- **You MUST stop increasing `i` once it reaches 16.**  
    Because AES ECB blocks are 16 bytes, and `Length=16` becomes unmatchable.
- After `i == 16`, you simply **keep using Length = 15 forever**, while still growing `flag` backwards.

```python
from pwn import *
import string

p = process(b"/challenge/run")

# sync to the first menu (challenge prints blank lines first)
p.recvuntil(b"Choice? ")

flag = b""
BLOCK = 16
ALPH = string.printable.encode()

while True:
    k = len(flag) + 1

    # ask for last k bytes
    p.sendline(b"2")
    p.recvuntil(b"Length? ")
    p.sendline(str(k).encode())
    p.recvuntil(b"Result: ")
    target_hex = p.recvline().strip()
    target_ct = bytes.fromhex(target_hex.decode())
    target_block = target_ct[:BLOCK]

    found = False
    for c in ALPH:
        guess = bytes([c]) + flag

        p.recvuntil(b"Choice? ")
        p.sendline(b"1")
        p.recvuntil(b"Data? ")
        p.sendline(guess)
        p.recvuntil(b"Result: ")
        test_hex = p.recvline().strip()
        test_ct = bytes.fromhex(test_hex.decode())
        test_block = test_ct[:BLOCK]

        if test_block == target_block:
            flag = bytes([c]) + flag
            print(flag.decode(errors="ignore"))
            found = True
            break

    if not found:
        print(flag.decode(errors="ignore"))
        break
```
## AES-ECB-CPA-Prefix

Okay, now let's complicate things slightly. It's not so common that you can just chop off the end of interesting data and go wild. However, _much_ more common is the ability to _prepend_ chosen plaintext to a secret before it's encrypted. If you carefully craft the prepended data so that it _pushes_ the end of the secret into a new block, you've just successfully isolated it, accomplishing the same as if you were chopping it off!

Go ahead and do that in this challenge. The core attack is the same as before, it just involves more data massaging.

**HINT:** Keep in mind that a typical pwn.college flag is somewhere upwards of 50 bytes long. This is four blocks (three full and one partial), and the length can vary slightly. You will need to experiment with how many bytes you must prepend to push even one of the end characters to its own block.

**HINT:** Keep in mind that blocks are 16 bytes long! After you leak the last 16 bytes, you'll be looking at the second-to-last block, and so on.
### Solution

```python
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

for n in range(31337):
    print("")
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Prepend something to the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        pt = input("Data? ").strip().encode() + flag
    else:
        break

    padded_pt = pad(pt, cipher.block_size) if len(pt)%cipher.block_size else pt
    ct = cipher.encrypt(padded_pt)
    print(f"Result: {ct.hex()}")

    if n == 0:
        print("I'm here to help!")
        print("For the first 10, I will split them into blocks for you!")
        print("After this, you'll have to split them yourself.")
    if n < 10:
        print(f"# of blocks: {len(ct)//16}.")
        for n,i in enumerate(range(0, len(ct)-15, 16), start=1):
            print(f"Block {n}: {ct[i:i+16].hex()}")
```

```bash
hacker@cryptography~aes-ecb-cpa-prefix:~$ /challenge/run

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAAAAAAAAAA
Result: 052801d50915dbc1ad241057440a5ecf7b5ecc4887986b8ca343dcc2089670c6f1d7314fd0885f98e178339a57dab62b32e7512b4123725337eb07406bbadc2e5b207b097ba8408e0739f59e10b0a06a
I'm here to help!
For the first 10, I will split them into blocks for you!
After this, you'll have to split them yourself.
# of blocks: 5.
Block 1: 052801d50915dbc1ad241057440a5ecf
Block 2: 7b5ecc4887986b8ca343dcc2089670c6
Block 3: f1d7314fd0885f98e178339a57dab62b
Block 4: 32e7512b4123725337eb07406bbadc2e
Block 5: 5b207b097ba8408e0739f59e10b0a06a

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 1
Data? AAAAAAAAAAAAAAAp
Result: 052801d50915dbc1ad241057440a5ecf
# of blocks: 1.
Block 1: 052801d50915dbc1ad241057440a5ecf
```

The service takes **your input and prepends it to the secret flag**, forming `your_input + flag`, and then encrypts that whole string under ECB. By carefully choosing the length of your input, you can **shift the first unknown flag byte so that it lands at the very end of a 16-byte block**, allowing you to create a block that contains **15 bytes you fully control plus 1 unknown flag byte**.

We first prepend `15` bytes into the flag.

```bash
Choice? 2
Data? AAAAAAAAAAAAAAA      (15 bytes)
```

```bash
pt = "AAAAAAAAAAAAAAA" + flag
```

That becomes:

```bash
[ 15 A's ][ first byte of flag ][ rest of flag ... ]
```

AES-ECB splits this into 16-byte blocks:

```bash
BLOCK 1: AAAAAAAAAAAAAAA + flag[0]
BLOCK 2: flag[1..16]
BLOCK 3: flag[16..32]
BLOCK 4: flag[32..48]
BLOCK 5: flag[48..64-ish]
```

In the output, **Block 1** is:

```bash
052801d50915dbc1ad241057440a5ecf
```

This ciphertext is exactly the encryption of:

```bash
AAAAAAAAAAAAAAA?    ← ? = FIRST FLAG BYTE
```

Now we send this:

```bash
Choice? 1
Data? AAAAAAAAAAAAAAAp
Result: 052801d50915dbc1ad241057440a5ecf
```

Which forms _one full block_:

```bash
BLOCK 1: AAAAAAAAAAAAAAAp
```

And its ciphertext is:

```bash
052801d50915dbc1ad241057440a5ecf
```

This confirms that `p` is the first part of flag. Now to get the second letter we would prepend `14` bytes `AAAAAAAAAAAAAA` and check its first block ciphertext and send and encrypt `AAAAAAAAAAAAAA + p + guess` and if the cipher text of `AAAAAAAAAAAAAA + p + guess` matches with 1st block. That guess will be our second letter.

Okay let's say we find first 15th letter:

```bash
flag[0..14] = pwn.college{abc
```

But what to do find 16th letter. So to find the 16th letter we will:

```bash
Choice? 1
Data? flag[0..14] + guess
```

And in prepending, We will prepend nothing to get the real block 1.

```bash
Choice? 2
Data?
```

Which will give us the original flag ciphertext which we already have:

```bash
pt = "" + flag = flag
```

```bash
block1 = AES( flag[0..15] )
```

```bash
TARGET = AAAABBBBCCCCDDDDEEEEFFFF00001111
```

Say we guess `h`:

```bash
Choice? 1
Data? pwn.college{abch
```

```bash
Result: AAAABBBBCCCCDDDDEEEEFFFF00001111
```

This means our 16th letter is `h`. Again for 17 it will be different. Let's say `g` will be our 17th guess:

```bash
Choice? 2
Data? AAAAAAAAAAAAAAA      # 15 A's
```

```bash
Block 1: <hex>
Block 2: <THIS ONE IS IMPORTANT> ← contains the 17th letter
Block 3: ...
```

**We must copy Block 2**, because that is the ciphertext of:

```bash
flag[1..15] + flag[16]
```

Since we already know the first 16 bytes:

```bash
pwn.college{abch
```

`flag[1..15]` is:

```bash
wn.college{abch
```

Now we test a guess, for example `'g'`:

```bash
Choice? 1
Data? wn.college{abchg
Result: <some_hex>
```

This hex is **Block 1 ciphertext** of our chosen plaintext.

```python
#!/usr/bin/env python3
from pwn import *
import string

p = process(b"/challenge/run")

# Sync to first menu
p.recvuntil(b"Choice? ")

flag = b""
BLOCK = 16
ALPH = string.printable.encode()

# First, determine the flag length by checking how many blocks we get
p.sendline(b"2")
p.recvuntil(b"Data? ")
p.sendline(b"")  # Empty prefix to see original flag
p.recvuntil(b"Result: ")
original_ct = bytes.fromhex(p.recvline().strip().decode())
num_blocks = len(original_ct) // BLOCK

print(f"[*] Total blocks: {num_blocks}")
print(f"[*] Approximate flag length: {len(original_ct)} bytes")

# Extract each block one by one
for block_idx in range(num_blocks):
    print(f"\n[*] Working on block {block_idx + 1}/{num_blocks}")
    
    # For each byte in this block
    for byte_pos in range(BLOCK):
        # Calculate how many padding bytes we need
        # We want to align so that the unknown byte is at the end of a block
        total_known = len(flag)
        padding_needed = (BLOCK - 1 - (total_known % BLOCK)) % BLOCK
        
        # Get target ciphertext with padding
        p.recvuntil(b"Choice? ")
        p.sendline(b"2")
        p.recvuntil(b"Data? ")
        p.sendline(b"A" * padding_needed)
        p.recvuntil(b"Result: ")
        target_ct = bytes.fromhex(p.recvline().strip().decode())
        
        # The block we care about is at position:
        # (padding_needed + total_known) // BLOCK
        target_block_idx = (padding_needed + total_known) // BLOCK
        target_block = target_ct[target_block_idx * BLOCK:(target_block_idx + 1) * BLOCK]
        
        # Now brute force the byte
        found = False
        for c in ALPH:
            # Build our test block
            # We need exactly 16 bytes: padding + known_flag + guess
            test_data = b"A" * padding_needed + flag + bytes([c])
            
            # Only take the last 16 bytes to form one complete block
            test_block_data = test_data[-(BLOCK):]
            
            p.recvuntil(b"Choice? ")
            p.sendline(b"1")
            p.recvuntil(b"Data? ")
            p.sendline(test_block_data)
            p.recvuntil(b"Result: ")
            test_ct = bytes.fromhex(p.recvline().strip().decode())
            test_block = test_ct[:BLOCK]  # First block of our encryption
            
            if test_block == target_block:
                flag += bytes([c])
                print(f"[+] Found: {flag.decode(errors='ignore')}")
                found = True
                break
        
        if not found:
            print(f"[!] Could not find byte at position {len(flag)}")
            print(f"[*] Final flag: {flag.decode(errors='ignore')}")
            p.close()
            exit()
        
        # Check if we've hit the flag end (likely with '}')
        if flag.endswith(b"}"):
            print(f"\n[*] Complete flag: {flag.decode()}")
            p.close()
            exit()

print(f"\n[*] Final flag: {flag.decode(errors='ignore')}")
p.close()
```
## AES-ECB-CPA-Prefix-2

The previous challenge ignored something very important: [_padding_](https://en.wikipedia.org/wiki/Padding_\(cryptography\)#Byte_padding). AES has a 128-bit (16 byte) block size. This means that input to the algorithm _must_ be 16 bytes long, and any input shorter than that must be _padded_ to 16 bytes by having data added to the plaintext before encryption. When the ciphertext is decrypted, the result must be _unpadded_ (e.g., the added padding bytes must be removed) to recover the original plaintext.

_How_ to pad is an interesting question. For example, you could pad with null bytes (`0x00`). But what if your data has null bytes at the end? They might be erroneously removed during unpadding, leaving you with a plaintext different than your original! This would not be good.

One padding standard (and likely the most popular) is PKCS7, which simply pads the input with bytes all containing a value equal to the number of bytes padded. If one byte is added to a 15-byte input, it contains the value `0x01`, two bytes added to a 14-byte input would be `0x02 0x02`, and the 15 bytes added to a 1-byte input would all have a value `0x0f`. During unpadding, PKCS7 looks at the value of the last byte of the block and removes that many bytes. Simple!

But wait... What if exactly 16 bytes of plaintext are encrypted (e.g., no padding needed), but the plaintext byte has a value of `0x01`? Left to its own devices, PKCS7 would chop off that byte during unpadding, leaving us with a corrupted plaintext. The solution to this is slightly silly: if the last block of the plaintext is exactly 16 bytes, we add a block of _all_ padding (e.g., 16 padding bytes, each with a value of `0x10`). PKCS7 removes the whole block during unpadding, and the sanctity of the plaintext is preserved at the expense of a bit more data.

**Input:** `"Hello1234567890!"` (16 bytes ASCII)

```bash
Hex: 48 65 6C 6C 6F 31 32 33 34 35 36 37 38 39 30 21
```

**PKCS7 adds a FULL EXTRA BLOCK:**

```bash
Original:   48 65 6C 6C 6F 31 32 33 34 35 36 37 38 39 30 21
Padding:    10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
            ↑ 16 bytes of 0x10 (16 decimal)
```

**Total to encrypt:** 32 bytes (2 blocks)

Anyways, the previous challenge explicitly disabled this last case, which would have the result of popping in a "decoy" ciphertext block full of padding as you tried to push the very first suffix byte to its own block. This challenge pads properly. Watch out for that "decoy" block, and go solve it!

**NOTE:** The full-padding block will _only_ appear when the last block of plaintext perfectly fills 16 bytes. It'll vanish when one more byte is appended (replaced with the padded new block containing the last byte of plaintext), but will reappear when the new block reaches 16 bytes in length.
### Solution

```python
hacker@cryptography~aes-ecb-cpa-prefix-2:~$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

for n in range(31337):
    print("")
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Prepend something to the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        pt = input("Data? ").strip().encode() + flag
    else:
        break

    padded_pt = pad(pt, cipher.block_size)
    ct = cipher.encrypt(padded_pt)
    print(f"Result: {ct.hex()}")
```

```python
# Previous challenge
(Prefix-1): padded_pt = pad(pt, cipher.block_size) if len(pt)%cipher.block_size else pt 

# This challenge (Prefix-2):
padded_pt = pad(pt, cipher.block_size) # ALWAYS pads! 
```

Now it **always** calls `pad()`, which implements PKCS7 padding properly.

```bash
hacker@cryptography~aes-ecb-cpa-prefix-2:~$ /challenge/run

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 1
Data? AAAAAAAAAAAAAAAp
Result: 44bb5fc8392a69d7c6aaa901d76b72dab9bcba7901e98ad47e10a0b335da2566

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAAAAAAAAAA
Result: 44bb5fc8392a69d7c6aaa901d76b72da178fcc47998bd9320811a4b83eebd07a4d49940e1a24dc3c67253bbce950b856d8754738d9c632f1bcc83c1ba69d4358f1096640ba82085dfdcd2095c78bdad0
```

```bash
Block 1: 44bb5fc8392a69d7c6aaa901d76b72da  ← [15 A's][flag[0]]
Block 2: 178fcc47998bd9320811a4b83eebd07a
Block 3: 4d49940e1a24dc3c67253bbce950b856
Block 4: d8754738d9c632f1bcc83c1ba69d4358
Block 5: f1096640ba82085dfdcd2095c78bdad0
```

It might feel it is same as previous one but

```bash
Choice? 1
Data? AAAAAAAAAAAAAAAp  (16 bytes exactly!)
Result: 44bb5fc8392a69d7c6aaa901d76b72dab9bcba7901e98ad47e10a0b335da2566
```

Let's count:
- Input: 16 bytes (`AAAAAAAAAAAAAAAp`)
- Since `16 % 16 == 0` (perfect block), PKCS7 adds **FULL 16-byte padding block**

So the encryption is actually:

```bash
Block 1: AAAAAAAAAAAAAAAp  (16 bytes)
Block 2: 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10  (16 bytes of padding!)
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         THIS IS THE DECOY PADDING BLOCK
```

Result split:

```bash
Block 1: 44bb5fc8392a69d7c6aaa901d76b72da  ← Your actual data
Block 2: b9bcba7901e98ad47e10a0b335da2566  ← DECOY! (encryption of padding)
```

To test `p`:

```bash
Data: "AAAAAAAAAAAAAAAp" (16 bytes exactly)
Result: 44bb5fc8392a69d7c6aaa901d76b72da b9bcba7901e98ad47e10a0b335da2566
```

- Block1 (first 32 chars): `44bb5fc8392a69d7c6aaa901d76b72da` = Encrypt(`AAAAAAAAAAAAAAAp`)
- Block2: `b9bcba7901e98ad47e10a0b335da2566` = Encrypt(`16 bytes of 0x10 padding`)

```bash
Data: "AAAAAAAAAAAAAAA" (15 A's) + flag
Result: 44bb5fc8392a69d7c6aaa901d76b72da 178fcc47998bd9320811a4b83eebd07a 4d49940e1a24dc3c67253bbce950b856 d8754738d9c632f1bcc83c1ba69d4358 f1096640ba82085dfdcd2095c78bdad0
```

- Block1: `44bb5fc8392a69d7c6aaa901d76b72da` = Encrypt(`15 A's + flag[0]`)
- Block2: `178fcc47998bd9320811a4b83eebd07a` = Rest of flag in block1 + start of block2
- Block3: `4d49940e1a24dc3c67253bbce950b856`
- Block4: `d8754738d9c632f1bcc83c1ba69d4358`
- Block5: `f1096640ba82085dfdcd2095c78bdad0` = Likely padding block

```python
from pwn import *
from Crypto.Cipher import AES

io = process(['/challenge/run'])

def get_encrypted_flag_data(data):
    io.recvregex(br'.+\nChoice\? ')
    io.sendline(b'2')

    io.recvregex(br'Data\? ')
    io.sendline(data)

    return bytes.fromhex(io.recvregex(br'Result: (.+)\n', capture=True).group(1).decode())

def encrypt_data(data):
    io.recvregex(br'.+\nChoice\? ')
    io.sendline(b'1')

    io.recvregex(br'Data\? ')
    io.sendline(data)

    return bytes.fromhex(io.recvregex(br'Result: (.+)\n', capture=True).group(1).decode())
    
def generate_decrypt_table(prefix):
    decrypt_table = {}

    for flag_char in (string.ascii_letters + string.digits + string.punctuation + '\r'):
        data = (prefix + flag_char).encode()
        result = encrypt_data(data)

        # We provide exactly 16 bytes of data to encrypt, so it will be padded with another block
        # filled with 0x10 byte so that the PKCS7 works correctly.
        # It's not needed for lookup, so we remove it.
        result = result[:AES.block_size]

        decrypt_table[result] = flag_char

    return decrypt_table


# Calculate the number of blocks in which the flag is encoded.
ciphertext = get_encrypted_flag_data(b'')
number_of_blocks = len(ciphertext) // AES.block_size

# The "working block" is the last block that is used for iteration.
working_block_start = (number_of_blocks - 1) * AES.block_size
working_block_end = working_block_start + AES.block_size

flag = ''
padding = bytearray()

# Calculate the exact string that needs to be added to the beginning
# to encode the flag without padding.
while True:
    padding += b'A'
    padded_ciphertext = get_encrypted_flag_data(padding)
    if len(padded_ciphertext) // AES.block_size > number_of_blocks:
        padding = padding[:-1]
        break

# The original number of blocks remains the same, and we know the exact
# padding length, so we can now calculate the flag length.
flag_length = number_of_blocks * AES.block_size - len(padding)

# Adjust the fill string so that the last character of the working block
# (the one used for brute-force) contains the first character of the flag.
padding = padding + b'A'*(flag_length - 1)

# So now block_cleartext = 'AAAAAAAAAAAAAAA?' where '?' will be the first
# character of the flag.
block_cleartext = padding[-(AES.block_size - 1):].decode()

for _ in range(flag_length):
    # Encrypt the flag with the required padding and get the working block
    # from the ciphertext.
    current_ciphertext = get_encrypted_flag_data(padding)
    data_to_check = current_ciphertext[working_block_start : working_block_end]

    decrypt_table = generate_decrypt_table(block_cleartext)

    flag_char = decrypt_table[data_to_check]
    flag += flag_char

    # Add the next character found to block_cleartext and remove the first one,
    # a sort of homemade circular buffer.
    block_cleartext += flag_char
    block_cleartext = block_cleartext[1:]
    padding = padding[:-1]

    print(flag)
```
## AES-ECB-CPA-Prefix Miniboss

This is the miniboss of AES-ECB-CPA. You don't get an easy way to build your codebook anymore: you must build it _in the prefix_. If you can change the length of your own prefixed data based on how much of the secret you know, you can control entire blocks, and that's all you need! Other than that, the attack remains the same. Good luck!
### Solution

```bash
$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()
key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

while True:
    pt = bytes.fromhex(input("Data? ").strip()) + flag
    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Ciphertext: {ct.hex()}")
```

```bash
hacker@cryptography~aes-ecb-cpa-prefix-miniboss:~$ /challenge/run
Data? aaaaaaaaaaaaaaaaaaaa
Ciphertext: b2888de025589cb33289fda50233b7c9609daf8dadacf4295e14d9ddef1f4e8a19134fe7dca3d8786ca7c67525669c21979c9486bb423cecebf456a92dc6814a459e6e5a433c368d6fd3121165f95222
```

AES-ECB still has the same fatal property:

> If two plaintext blocks are equal, their ciphertext blocks are equal.

Even though everything is prefixed with the flag, **you still control part of the plaintext**.

So the goal becomes:

> Make **one full 16-byte block** of  
> `user_input || flag`  
> equal to another block whose contents you can predict.

```bash
[ controlled bytes ][ known flag bytes ][ guessed byte ]
```

You do **two encryptions**, both through the same oracle:

```python
from pwn import *

BLOCK = 16
charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-."

p = process("/challenge/run")

flag = b""

def encrypt(data: bytes) -> bytes:
    p.recvuntil(b"Data? ")
    p.sendline(data.hex().encode())
    line = p.recvline().decode()
    return bytes.fromhex(line.split("Ciphertext: ")[1].strip())

while True:
    pad_len = BLOCK - 1 - (len(flag) % BLOCK)
    padding = b"A" * pad_len

    # --- get target block ---
    ct = encrypt(padding)
    block_index = (pad_len + len(flag)) // BLOCK
    target_block = ct[block_index*BLOCK:(block_index+1)*BLOCK]

    # --- brute-force next byte ---
    for c in charset:
        test = padding + flag + bytes([c])
        ct_test = encrypt(test)
        test_block = ct_test[block_index*BLOCK:(block_index+1)*BLOCK]

        if test_block == target_block:
            flag += bytes([c])
            print(f"[+] Flag so far: {flag.decode(errors='ignore')}")
            break

    if flag.endswith(b"}"):
        break

print("\nFinal flag:", flag.decode())
```
## AES-ECB-CPA-Prefix-Boss

Okay, time for the AES-ECB-CPA final boss! Can you carry out this attack against an encrypted secret storage web server? Let's find out!

**NOTE:** Keep in mind that, unlike the previous levels, this level takes data in base64!
### Solution

```bash
$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE posts AS SELECT ? AS content""", [open("/flag", "rb").read().strip()])

@app.route("/", methods=["POST"])
def challenge_post():
    content = flask.request.form.get("content").encode('latin1')
    db.execute("INSERT INTO posts VALUES (?)", [content])
    return flask.redirect(flask.request.path)

@app.route("/reset", methods=["POST"])
def challenge_reset():
    db.execute("DELETE FROM posts WHERE ROWID > 1")
    return flask.redirect("/")

@app.route("/", methods=["GET"])
def challenge_get():
    pt = b"|".join(post["content"] for post in db.execute("SELECT content FROM posts ORDER BY ROWID DESC").fetchall())
    ct = cipher.encrypt(pad(pt, cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form method=post>Post a secret:<input type=text name=content><input type=submit value=Submit></form>
        <form method=post action=reset><input type=submit value="Reset Database"></form>
        <hr>
        <b>Encrypted backup:</b><pre>{b64encode(ct).decode()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```bash
/challenge/run > /dev/null 2>&1 &
```

```python
import string
import requests
import re

from Crypto.Cipher import AES
from base64 import b64decode

challenge_url = 'http://challenge.localhost'
result_rx = re.compile(r'.*Encrypted backup:.+<pre>(.+)</pre>\n.*')

def encrypt_data(data):
    if data is not None:
        requests.post(url = challenge_url, data = {'content' : data.decode()})

    r = requests.get(url = challenge_url)
    ciphertext = result_rx.search(r.text).group(1)

    if data is not None:
        requests.post(url = challenge_url + '/reset')

    return b64decode(ciphertext)
    
def generate_decrypt_table(prefix):
    decrypt_table = {}

    for flag_char in (string.ascii_letters + string.digits + string.punctuation):
        data = (prefix + flag_char).encode()
        
        # We are asking to encrypt data that is exactly 16 bytes long, and the remaining flag 
        # will be appended to it to form the plaintext. As a result, the data we need will be
        # in the first block of the ciphertext
        result = encrypt_data(data)[:AES.block_size]

        decrypt_table[result] = flag_char

    return decrypt_table

# Calculate the number of blocks in which the flag is encoded.
ciphertext = encrypt_data(None)
number_of_blocks = len(ciphertext) // AES.block_size

# The "working block" is the last block that is used for iteration.
working_block_start = (number_of_blocks - 1) * AES.block_size
working_block_end = working_block_start + AES.block_size

flag = ''
padding = bytearray()

# Calculate the exact string that needs to be added to the beginning
# to encode the flag without padding. Note that the server appends
# the '|' character by default.
while True:
    padded_ciphertext = encrypt_data(padding)
    if len(padded_ciphertext) // AES.block_size > number_of_blocks:
        padding = padding[:-1]
        break

    padding += b'A'

# The original number of blocks remains the same, and we know the exact
# padding length, so we can now calculate the flag length.
flag_length = number_of_blocks * AES.block_size - len(padding)

# Adjust the fill string so that the last character of the working block
# (the one used for brute-force) contains the first character of the flag.
# The server adds the | character by default, so we need to take that into
# account.
padding = padding + b'A'*(flag_length - 2)

# So now block_cleartext = 'AAAAAAAAAAAAAAA?' where '?' will be the first
# character of the flag.
# Again, the | character should be taken into account.
block_cleartext = padding[-(AES.block_size - 2):]
block_cleartext = (block_cleartext + b'|').decode()

for _ in range(flag_length - 2):
    # Encrypt the flag with the required padding and get the working block
    # from the ciphertext.
    current_ciphertext = encrypt_data(padding)
    data_to_check = current_ciphertext[working_block_start : working_block_end]

    decrypt_table = generate_decrypt_table(block_cleartext)

    flag_char = decrypt_table[data_to_check]
    flag += flag_char

    # Add the next character found to block_cleartext and remove the first one,
    # a sort of homemade circular buffer.
    block_cleartext += flag_char
    block_cleartext = block_cleartext[1:]
    padding = padding[:-1]

    print(flag)
```
## AES-CBC

Okay, hopefully we agree that ECB is a bad block cipher mode. Let's explore one that isn't _so_ bad: [Cipher Block Chaining (CBC)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_\(CBC\)). CBC mode encrypts blocks sequentially, and before encrypting plaintext block number N, it XORs it with the previous ciphertext block (number N-1). When decrypting, after decrypting ciphertext block N, it XORs the decrypted (but still XORed) result with the previous ciphertext block (number N-1) to recover the original plaintext block N. For the very first block, since there is no "previous" block to use, CBC cryptosystems generate a random initial block called an [_Initialization Vector_ (IV)](https://en.wikipedia.org/wiki/Initialization_vector). The IV is used to XOR the first block of plaintext, and is transmitted along with the message (often prepended to it). This means that if you encrypt one block of plaintext in CBC mode, you might get _two_ blocks of "ciphertext": the IV, and your single block of actual ciphertext.

All this means that, when you change any part of the plaintext, those changes will propagate through to all subsequent ciphertext blocks because of the XOR-based chaining, preserving ciphertext indistinguishability for those blocks. That will stop you from carrying out the chosen-plaintext prefix attacks from the last few challenges. Moreover, every time you re-encrypt, even with the same key, a new (random) IV will be used, which will propagate changes to all of the blocks anyways, which means that even your sampling-based CPA attacks from the even earlier levels will not work, either.

Sounds pretty good, right? The only relevant _disadvantage_ that CBC has over EBC is that encryption has to happen sequentially. With ECB, you could encrypt, say, only the last part of the message if that's all you have to send. With CBC, you must encrypt the message from the beginning. In practice, this does not tend to be a problem, and ECB should never be used over CBC.

This level is just a quick look at CBC. We'll encrypt the flag with CBC mode. Go and decrypt it!
### Solution

```bash
hacker@cryptography~aes-cbc:~$ /challenge/run
AES Key (hex): c37707c1985dbb8c3be093c414062948
Flag Ciphertext (hex): c855032cb346792dfc57f185b8362ee5c1a4dffefb537138c93fadf493bf08510e3709d47cd6428e018c6124ee9ca76b5a3ac0afd4e155c056b7cfa0526e3da9617721b17f4052c6e8df55248126a143
hacker@cryptography~aes-cbc:~$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(flag, cipher.block_size))

print(f"AES Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# values copied from the challenge output
key_hex = "c37707c1985dbb8c3be093c414062948"
ct_hex  = "c855032cb346792dfc57f185b8362ee5c1a4dffefb537138c93fadf493bf08510e3709d47cd6428e018c6124ee9ca76b5a3ac0afd4e155c056b7cfa0526e3da9617721b17f4052c6e8df55248126a143"

key = bytes.fromhex(key_hex)
ciphertext = bytes.fromhex(ct_hex)

# split IV and ciphertext
iv = ciphertext[:16]
ct = ciphertext[16:]

# decrypt
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = cipher.decrypt(ct)

# remove PKCS7 padding
flag = unpad(plaintext, 16)

print(flag.decode())
```
## AES-CBC Tampering

For CBC mode, let:

- `C₀ = IV`
- `Cᵢ` = ciphertext block _i_
- `Pᵢ` = plaintext block _i_
- `Dₖ(·)` = AES decryption with key _k_

Decryption rule

```bash
Pᵢ = Dₖ(Cᵢ) ⊕ Cᵢ₋₁
```

This XOR with the **previous ciphertext block** is the defining feature of CBC.
##### bit-flipping attack

```bash
P₂ = "admin=false;uid=10"
```

In ASCII:

```bash
... 66 61 6c 73 65 ...
```

Attacker wants:

`"admin=true;uid=10"`

Difference between `false` and `true`:

`Δ = false ⊕ true`

Attacker applies `Δ` to the **previous ciphertext block**:

`C₁′ = C₁ ⊕ Δ`

After decryption:

`P₂′ = P₂ ⊕ Δ = "admin=true;uid=10"`
### Solution

```bash
hacker@cryptography~aes-cbc-tampering:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~aes-cbc-tampering:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    print(f"Hex of plaintext: {plaintext.encode('latin1').hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "flag!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

Dispatcher:

```bash
ciphertext = IV || AES-CBC(key, pad("sleep"))
print(TASK: <ciphertext>)
```

Worker:

- Reads `TASK: <hex>`
- Decrypts using CBC
- Executes command:
    
    - `"sleep"` → sleep
    - `"flag!"` → prints flag

The worker **does not authenticate the ciphertext**.  
It blindly decrypts and trusts the result.

CBC decryption:

```bash
P₁ = D(C₁) ⊕ IV
```

This means:

- If we change the IV
- We **directly control the decrypted plaintext of block 1**
- Without corrupting padding or triggering errors

Since `"sleep"` fits in **one block**, this is perfect. Change decrypted plain text from `sleep` to `flag!` without knowing key.

If we modify IV → `IV'`:

```bash
P₁' = D(C₁) ⊕ IV'
```

We want:

```bash
P₁' = "flag!"
```

So:

```bash
IV' = IV ⊕ sleep ⊕ flag!
```

This works because XOR cancels out:

```bash
(D(C₁) ⊕ IV) ⊕ sleep ⊕ flag! = flag!
```

Original plaintext before padding:

`sleep`

Length = 5 bytes  
PKCS#7 padding = `0x0b` repeated 11 times

So actual plaintext block:

`sleep\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b`

Desired plaintext must preserve padding:

`flag!\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b`

```python
from pwn import *
from Crypto.Util.Padding import pad

# Start dispatcher
p = process("/challenge/dispatcher")
line = p.recvline().decode().strip()
print(line)

# Extract ciphertext
ct = bytes.fromhex(line.split()[1])
iv = ct[:16]
c1 = ct[16:]

# Original and target plaintexts (with padding)
old = pad(b"sleep", 16)
new = pad(b"flag!", 16)

# Compute modified IV
new_iv = xor(iv, xor(old, new))

# Build tampered ciphertext
payload = new_iv + c1

# Send to worker
w = process("/challenge/worker")
w.sendline(b"TASK: " + payload.hex().encode())

# Get flag
w.interactive()
```
## AES-CBC Resizing

So now you can modify AES-CBC encrypted data without knowing the key! But you got lucky: `sleep` and `flag!` were the same length. What if you want to achieve a different length?

**HINT:** Don't forget about the padding! How does the padding work?
### Solution

```bash
hacker@cryptography~aes-cbc-resizing:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~aes-cbc-resizing:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    print(f"Hex of plaintext: {plaintext.encode('latin1').hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "flag":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

- `"sleep"` → `"flag"`
- Length changes:
    
    - `"sleep"` = 5 bytes
        
    - `"flag"` = 4 bytes
        

```python
from pwn import *
from Crypto.Util.Padding import pad

# Start dispatcher
p = process("/challenge/dispatcher")
line = p.recvline().decode().strip()
print(line)

# Extract ciphertext
ct = bytes.fromhex(line.split()[1])
iv = ct[:16]
c1 = ct[16:]

# Original and desired plaintexts
old = pad(b"sleep", 16)
new = pad(b"flag", 16)

# Compute new IV
new_iv = xor(iv, xor(old, new))

# Build tampered ciphertext
payload = new_iv + c1

# Send to worker
w = process("/challenge/worker")
w.sendline(b"TASK: " + payload.hex().encode())
w.interactive()
```
## AES-CBC-POA-Partial-Block

So you can manipulate the padding... If you messed up somewhere along the lines of the previous challenge and created an invalid padding, you might have noticed that the worker _crashed_ with an error about the padding being incorrect!

It turns out that this one crash _completely_ breaks the Confidentiality of the AES-CBC cryptosystem, allowing attackers to decrypt messages without having the key. Let's dig in...

Recall that PKCS7 padding adds N bytes with the value N, so if 11 bytes of padding were added, they have the value `0x0b`. During unpadding, PKCS7 will read the value N of the last byte, make sure that the last N bytes (including that last byte) have that same value, and remove those bytes. If the value N is bigger than the block size, or the bytes don't all have the value N, most implementations of PKCS7, including the one provided by PyCryptoDome, will error.

Consider how careful you had to be in the previous level with the padding, and how this required you to know the letter you wanted to remove. What if you didn't know that letter? Your random guesses at what to XOR it with would cause an error 255 times out of 256 (as long as you handled the rest of the padding properly, of course), and the one time it did not, by known what the final padding had to be and what your XOR value was, you can recover the letter value! This is called a [_Padding Oracle Attack_](https://en.wikipedia.org/wiki/Padding_oracle_attack), after the "oracle" (error) that tells you if your padding was correct!

Of course, once you remove (and learn) the last byte of the plaintext, the second-to-last byte becomes the last byte, and you can attack it!

So, what are you waiting for? Go recover the flag!

**FUN FACT:** The only way to prevent a Padding Oracle Attack is to avoid having a Padding Oracle. Depending on the application, this can be surprisingly tricky: a failure state is hard to mask completely from the user/attacker of the application, and for some applications, the padding failure is the only source of an error state! Moreover, even if the error itself is hidden from the user/attacker, it's often _inferable_ indirectly (e.g., by detecting timing differences between the padding error and padding success cases.

Watch [this](https://www.youtube.com/watch?v=O5SeQxErXA4) and [this](https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/).

Padding:

```bash
Block size = 16 bytes

Example 1: 11 bytes of data
Data:    [A][B][C][D][E][F][G][H][I][J][K]
Padding:                                  [05][05][05][05][05]
Result:  [A][B][C][D][E][F][G][H][I][J][K][05][05][05][05][05]

Example 2: 15 bytes of data  
Data:    [A][B][C][D][E][F][G][H][I][J][K][L][M][N][O]
Padding:                                                [01]
Result:  [A][B][C][D][E][F][G][H][I][J][K][L][M][N][O][01]

Example 3: 16 bytes of data (full block)
Data:    [A][B][C][D][E][F][G][H][I][J][K][L][M][N][O][P]
Padding: [10][10][10][10][10][10][10][10][10][10][10][10][10][10][10][10]
Result:  Two full blocks!
```

Let's decrypt the **last byte** of a block with a concrete example.

```bash
Block size = 16 bytes (positions 0-15)
We want to decrypt position 15 (last byte)

Ciphertext block C: [??][??][??][??][??][??][??][??][??][??][??][??][??][??][??][C15]
Previous block   P: [P0][P1][P2][P3][P4][P5][P6][P7][P8][P9][P10][P11][P12][P13][P14][P15]

After AES decryption (unknown to us):
Intermediate     I: [I0][I1][I2][I3][I4][I5][I6][I7][I8][I9][I10][I11][I12][I13][I14][I15]

Plaintext = I ⊕ P
```

```bash
Let's say the true intermediate value is:
I[15] = 0xA7

Original previous block:
P[15] = 0x3C

True plaintext:
Plaintext[15] = 0xA7 ⊕ 0x3C = 0x9B

Now we attack:
- Try GUESS = 0x00: Plaintext'[15] = 0xA7 ⊕ 0x00 = 0xA7 (not 0x01, invalid padding)
- Try GUESS = 0x01: Plaintext'[15] = 0xA7 ⊕ 0x01 = 0xA6 (not 0x01, invalid padding)
- ...
- Try GUESS = 0xA6: Plaintext'[15] = 0xA7 ⊕ 0xA6 = 0x01 (valid padding!)

Found it! Now we calculate:
I[15] = GUESS ⊕ 0x01 = 0xA6 ⊕ 0x01 = 0xA7

And we can recover the original plaintext:
Plaintext[15] = I[15] ⊕ P[15] = 0xA7 ⊕ 0x3C = 0x9B
```
### Solution

```bash
hacker@cryptography~aes-cbc-poa-partial-block:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "pw":
    plaintext = open("/challenge/.pw", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~aes-cbc-poa-partial-block:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()
pw = open("/challenge/.pw").read().strip()

print(f"The password is {len(pw)} bytes long!")

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == pw:
        print("Correct! Use /challenge/redeem to redeem the password for the flag!")
    else:
        print("Unknown command!")
```

You **do not know** the plaintext (it’s a secret password). The password is **15 bytes long**, not 16 bytes (a full block).

```
Password: 15 bytes 
Padding: 1 byte (0x01) 
Total: 16 bytes = 1 complete block 
Structure: [IV (16 bytes)][Password + Padding (16 bytes)] 
```

1. **Partial block** means the plaintext doesn't fill complete blocks 
2. The last block contains **partial data** (15 bytes) + **padding** (1 byte) 
3. This is the **easiest case** for padding oracle attacks

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

def decrypt_block(io, block):
    # Initialize blocks: work_block is our modified IV, original_block stores intermediate values
    work_block = bytearray(AES.block_size)
    original_block = bytearray(AES.block_size)
    byte_index = AES.block_size - 1  # Start from last byte (position 15)
    pad_counter = 1  # Current padding value we're creating (0x01, 0x02, etc.)
    
    # Decrypt byte by byte from right to left
    while byte_index >= 0:
        # Send modified IV + ciphertext block to oracle
        io.sendline(("TASK: " + work_block.hex() + block.hex()).encode())
        response = io.recvline()
        
        # If padding is invalid, try next guess
        if not response.startswith(b"Unknown"):
            work_block[byte_index] += 1
            continue
        
        # Valid padding found! Calculate intermediate value
        # We know: intermediate[i] XOR work_block[i] = pad_counter
        # So: intermediate[i] = work_block[i] XOR pad_counter
        original_block[byte_index] = work_block[byte_index] ^ pad_counter
        
        # Move to next byte
        pad_counter += 1
        byte_index -= 1
        
        # Update all previously discovered bytes to create new padding value
        # For example: if pad_counter=2, make all discovered bytes produce 0x02
        for n in range(AES.block_size - 1, byte_index, -1):
            work_block[n] = original_block[n] ^ pad_counter
    
    return original_block  # Return intermediate state

# Get encrypted password from dispatcher
io = process(['/challenge/dispatcher', "pw"])
pw = io.recvregex(br'TASK: (.+)\n', capture=True).group(1).decode()
pw = bytes.fromhex(pw)
pw_blocks = len(pw) // AES.block_size  # Calculate number of blocks
io.kill()

# Start worker (our padding oracle)
io = process(['/challenge/worker'])
io.recvline()  # Skip password length message

# Decrypt all blocks (except IV which is block 0)
cleartext = bytearray()
for n in range(pw_blocks - 1, 0, -1):  # Work backwards through blocks
    # Extract current ciphertext block
    encrypted_block_start = n * AES.block_size
    encrypted_block_end = encrypted_block_start + AES.block_size
    encrypted_block = pw[encrypted_block_start : encrypted_block_end]
    
    # Extract previous block (needed for XOR to get plaintext)
    previous_block = pw[encrypted_block_start - AES.block_size : encrypted_block_start]
    
    # Get intermediate state using padding oracle attack
    original_block = decrypt_block(io, encrypted_block)
    
    # Recover plaintext: plaintext = intermediate XOR previous_block
    cleartext = strxor(original_block, previous_block) + cleartext

# Remove PKCS7 padding and print password
print("Password: " + unpad(cleartext, AES.block_size).decode())
```

```bash
hacker@cryptography~aes-cbc-poa-partial-block:~$ python3 main.py
[+] Starting local process '/challenge/dispatcher': pid 190
[*] Stopped process '/challenge/dispatcher' (pid 190)
[+] Starting local process '/challenge/worker': pid 192
Password: Fd6AQwqc0rFp9CR
[*] Stopped process '/challenge/worker' (pid 192)
hacker@cryptography~aes-cbc-poa-partial-block:~$ /challenge/redeem 
Password? Fd6AQwqc0rFp9CR
Victory! Your flag:
pwn.college{ARSh7T2KcBY2Cstvg_k6RCSd_IH.0FOxMjNxwCNxgjN0EzW}
```
## AES-CBC-POA-Full-Block

The previous challenge had you decrypting a partial block by abusing the padding at the end. But what happens if the block is "full", as in, 16-bytes long? Let's explore an example with the plaintext `AAAABBBBCCCCDDDD`, which is 16 bytes long! As you recall, PKCS7 adds a whole block of padding in this scenario! What we would see after padding is:

|Plaintext Block 1|Plaintext Block 2 (oops, just padding!)|
|---|---|
|`AAAABBBBCCCCDDDD`|`\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`|

When encrypted, we'd end up with three blocks:

|Ciphertext Block 1|Ciphertext Block 2|Ciphertext Block 3|
|---|---|---|
|IV|Encrypted `AAAABBBBCCCCDDDD`|Encrypted Padding|

If you know that the plaintext length is aligned to the block length like in the above example, you already know the plaintext of the last block (it's just the padding!). Once you know it's all just padding, you can discard it and start attacking the next-to-last block (in this example, Ciphertext Block 2)! You'd try tampering with the last byte of the plaintext (by messing with the IV that gets XORed into it) until you got a successful padding, then use that to recover (and be able to control) the last byte, then go from there. The same POA attack, but against the _second-to-last_ block when the last block is all padding!
### Solution

```bash
hacker@cryptography~aes-cbc-poa-full-block:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()
pw = open("/challenge/.pw").read().strip()

print(f"The password is {len(pw)} bytes long!")

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == pw:
        print("Correct! Use /challenge/redeem to redeem the password for the flag!")
    else:
        print("Unknown command!")
hacker@cryptography~aes-cbc-poa-full-block:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "pw":
    plaintext = open("/challenge/.pw", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
```
#### The Full Block Problem

When plaintext is **exactly 16 bytes** (one full block), PKCS7 padding adds an **entire second block** of padding:

```bash
Original plaintext: "AAAABBBBCCCCDDDD" (16 bytes)

After PKCS7 padding:
Block 1: [A][A][A][A][B][B][B][B][C][C][C][C][D][D][D][D]
Block 2: [10][10][10][10][10][10][10][10][10][10][10][10][10][10][10][10]
         (16 bytes of 0x10 padding)

After encryption:
Block 0: IV (16 bytes)
Block 1: Encrypted("AAAABBBBCCCCDDDD") (16 bytes)  
Block 2: Encrypted(0x10 * 16) (16 bytes)

Total: 48 bytes (IV + 2 ciphertext blocks)
```

**Block 2 is entirely padding!** We already know its plaintext is `0x10 * 16`.

So we:

1. **Skip Block 2** (we know it's all padding)
2. **Attack Block 1** (the actual data we want)
3. Use the **same padding oracle technique**

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

def decrypt_block(io, block):
    """
    Decrypt a single 16-byte block using padding oracle attack.
    
    This function tries all 256 possible byte values for each position,
    working from right to left (byte 15 down to byte 0), to discover
    the intermediate state that comes out of AES decryption.
    """
    work_block = bytearray(AES.block_size)      # Our crafted "previous block"
    original_block = bytearray(AES.block_size)  # Stores discovered intermediate values
    byte_index = AES.block_size - 1             # Start from last byte (position 15)
    pad_counter = 1                              # Padding value we're creating (0x01, 0x02, ...)
    
    while byte_index >= 0:
        # Send crafted IV + ciphertext block to oracle
        io.sendline(("TASK: " + work_block.hex() + block.hex()).encode())
        response = io.recvline()
        
        # Check if padding is valid
        # Valid responses: "Unknown command!", "Sleeping!", "Correct!"
        # Invalid response: "Error: PKCS#7 padding is incorrect."
        if not response.startswith(b"Unknown"):
            # Invalid padding or unexpected response, try next guess
            work_block[byte_index] += 1
            continue
        
        # Valid padding found!
        # Calculate: intermediate[i] = work_block[i] ⊕ pad_counter
        original_block[byte_index] = work_block[byte_index] ^ pad_counter
        
        # Move to next byte
        pad_counter += 1
        byte_index -= 1
        
        # Update all previously discovered bytes to create the new padding value
        # Example: if pad_counter=2, make bytes 14 and 15 both produce 0x02
        for n in range(AES.block_size - 1, byte_index, -1):
            work_block[n] = original_block[n] ^ pad_counter
    
    return original_block

# ============================================================================
# MAIN ATTACK
# ============================================================================

# Get encrypted password from dispatcher
io = process(['/challenge/dispatcher', "pw"])
pw = io.recvregex(br'TASK: (.+)\n', capture=True).group(1).decode()
pw = bytes.fromhex(pw)
pw_blocks = len(pw) // AES.block_size  # Total blocks including IV
io.kill()

print(f"[*] Total encrypted data: {len(pw)} bytes")
print(f"[*] Number of blocks: {pw_blocks} (including IV)")
print(f"[*] Expected structure: IV (16) + Data (16) + Padding (16) = 48 bytes")

# Start the padding oracle
io = process(['/challenge/worker'])
password_length_msg = io.recvline().decode()
print(f"[*] {password_length_msg.strip()}")

# ============================================================================
# KEY DIFFERENCE: Skip the last block (it's all padding!)
# ============================================================================
# For full block: pw_blocks = 3 (IV + Data + Padding)
# We want to decrypt: range(pw_blocks - 2, 0, -1) = range(1, 0, -1) = [1]
# This skips block 2 (padding) and only attacks block 1 (data)

cleartext = bytearray()

# Decrypt all data blocks (skip IV at position 0 and padding at position pw_blocks-1)
for n in range(pw_blocks - 2, 0, -1):  # Only decrypt data blocks, not padding block
    print(f"\n[*] Decrypting block {n}...")
    
    # Extract current ciphertext block
    encrypted_block_start = n * AES.block_size
    encrypted_block_end = encrypted_block_start + AES.block_size
    encrypted_block = pw[encrypted_block_start : encrypted_block_end]
    
    # Extract previous block (IV or previous ciphertext)
    previous_block = pw[encrypted_block_start - AES.block_size : encrypted_block_start]
    
    print(f"[*] Encrypted block: {encrypted_block.hex()}")
    print(f"[*] Previous block (IV): {previous_block.hex()}")
    
    # Use padding oracle to discover intermediate state
    print(f"[*] Running padding oracle attack (this takes ~2000 queries)...")
    original_block = decrypt_block(io, encrypted_block)
    
    print(f"[*] Intermediate state: {original_block.hex()}")
    
    # Recover plaintext: plaintext = intermediate ⊕ previous_block
    decrypted_chunk = strxor(original_block, previous_block)
    cleartext = decrypted_chunk + cleartext  # Prepend since working backwards
    
    print(f"[*] Decrypted chunk: {decrypted_chunk}")

# ============================================================================
# IMPORTANT: For full blocks, there's NO padding in the data blocks!
# The entire last block is padding (0x10 * 16), which we skipped.
# So cleartext already contains only the actual password, no padding to remove!
# ============================================================================

print(f"\n[+] Decrypted plaintext (hex): {cleartext.hex()}")
print(f"[+] Decrypted plaintext: {cleartext.decode('latin1')}")
print(f"\n{'='*60}")
print(f"PASSWORD: {cleartext.decode('latin1')}")
print(f"{'='*60}")
```

```bash
hacker@cryptography~aes-cbc-poa-full-block:~$ /challenge/redeem 
Password? bjzPoUASF55ZzD3z
Victory! Your flag:
pwn.college{cqamGHkndov-BwSae-plR8EhLHi.0VOxMjNxwCNxgjN0EzW}
```
## AES-CBC-POA-Multi-Block

Let's put the last two challenges together. The previous challenges had just one ciphertext block, whether it started like that or you quickly got there by discarding the all-padding block. Thus, you were able to mess with that block's plaintext by chaining up the IV.

This level encrypts the actual flag, and thus has multiple blocks that actually have data. Keep in mind that to mess with the decryption of block N, you must modify ciphertext N-1. For the first block, this is the IV, but not for the rest!

This is one of the hardest challenges in this module, but you can get your head around if you take it step by step. So, what are you waiting for? Go recover the flag!
### Solution

```bash
hacker@cryptography~aes-cbc-poa-multi-block:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "flag":
    plaintext = open("/flag", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~aes-cbc-poa-multi-block:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    else:
        print("Unknown command!")
```
#### The Multi-Block Challenge

Previous challenges had:

- **Partial block**: 1 data block (15 bytes + padding)
- **Full block**: 1 data block + 1 padding block

Now we have:

- **Multi-block**: Multiple data blocks + possibly padding

```bash
Flag: "pwn.college{...long_flag...}" (let's say 50 bytes)

After PKCS7 padding: 50 + 14 = 64 bytes (4 blocks)
Block 1: 16 bytes of flag
Block 2: 16 bytes of flag  
Block 3: 16 bytes of flag
Block 4: 2 bytes of flag + 14 bytes of 0x0E padding

Structure after encryption:
[IV][C1][C2][C3][C4]
  ↓   ↓   ↓   ↓   ↓
 16  16  16  16  16 bytes = 80 bytes total
```

In CBC mode, each block depends on the previous one:

```bash
Plaintext[1] = AES_Decrypt(Ciphertext[1]) ⊕ IV
Plaintext[2] = AES_Decrypt(Ciphertext[2]) ⊕ Ciphertext[1]
Plaintext[3] = AES_Decrypt(Ciphertext[3]) ⊕ Ciphertext[2]
Plaintext[4] = AES_Decrypt(Ciphertext[4]) ⊕ Ciphertext[3]
```

To attack block N, we manipulate block N-1! We must decrypt **from last block to first block**:

```bash
Step 1: Attack Block 4 (last block with padding)
        - Use Ciphertext[3] as our "IV"
        - Discover Intermediate[4]
        - Recover: Plaintext[4] = Intermediate[4] ⊕ Ciphertext[3]

Step 2: Attack Block 3
        - Use Ciphertext[2] as our "IV"
        - Discover Intermediate[3]
        - Recover: Plaintext[3] = Intermediate[3] ⊕ Ciphertext[2]

Step 3: Attack Block 2
        - Use Ciphertext[1] as our "IV"
        - Discover Intermediate[2]
        - Recover: Plaintext[2] = Intermediate[2] ⊕ Ciphertext[1]

Step 4: Attack Block 1 (first data block)
        - Use IV as our "IV"
        - Discover Intermediate[1]
        - Recover: Plaintext[1] = Intermediate[1] ⊕ IV
```

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor

def decrypt_block(io, block):
    """
    Decrypt a single 16-byte block using padding oracle attack.
    
    The oracle is the /challenge/worker that tells us if padding is valid or not.
    We try all 256 possible byte values for each position to discover the
    intermediate state (output of AES decryption before XOR).
    """
    work_block = bytearray(AES.block_size)      # Our crafted "previous block" (starts as zeros)
    original_block = bytearray(AES.block_size)  # Stores the intermediate values we discover
    byte_index = AES.block_size - 1             # Start from last byte (position 15)
    pad_counter = 1                              # Padding value: 0x01, 0x02, 0x03, ...
    
    # Decrypt byte by byte from right to left (15 → 0)
    while byte_index >= 0:
        # Send: modified_IV (work_block) + ciphertext_block
        # Oracle decrypts: plaintext = AES_Decrypt(block) ⊕ work_block
        io.sendline(("TASK: " + work_block.hex() + block.hex()).encode())
        response = io.recvline()
        
        # Check oracle's response:
        # - "Error: ..." = Invalid padding
        # - "Unknown command!" or "Sleeping!" = Valid padding
        if not response.startswith(b"Unknown"):
            # Invalid padding, try next guess
            work_block[byte_index] += 1
            continue
        
        # Valid padding found!
        # We know: intermediate[byte_index] ⊕ work_block[byte_index] = pad_counter
        # Therefore: intermediate[byte_index] = work_block[byte_index] ⊕ pad_counter
        original_block[byte_index] = work_block[byte_index] ^ pad_counter
        
        # Move to next byte (one position left)
        pad_counter += 1
        byte_index -= 1
        
        # Update all previously discovered bytes to produce the new padding value
        # Example: If pad_counter is now 2, make bytes 14 and 15 both produce 0x02
        for n in range(AES.block_size - 1, byte_index, -1):
            work_block[n] = original_block[n] ^ pad_counter
    
    return original_block  # Return the intermediate state

# ============================================================================
# MAIN ATTACK
# ============================================================================

# Step 1: Get encrypted flag from dispatcher
io_dispatcher = process(['/challenge/dispatcher', "flag"])
flag_encrypted = io_dispatcher.recvregex(br'TASK: (.+)\n', capture=True).group(1).decode()
flag_encrypted = bytes.fromhex(flag_encrypted)
total_blocks = len(flag_encrypted) // AES.block_size  # Total blocks including IV
io_dispatcher.kill()

print(f"[*] Encrypted flag length: {len(flag_encrypted)} bytes")
print(f"[*] Total blocks: {total_blocks} (including IV)")
print(f"[*] Data blocks to decrypt: {total_blocks - 1}")

# Step 2: Start the padding oracle
io_oracle = process(['/challenge/worker'])

# ============================================================================
# CRITICAL: Decrypt ALL data blocks from RIGHT TO LEFT
# ============================================================================
# Structure: [IV (block 0)][C1 (block 1)][C2 (block 2)]...[CN (block N)]
# 
# We decrypt: block N, block N-1, ..., block 2, block 1
# Loop: range(total_blocks - 1, 0, -1)
#
# Example with 4 blocks total (IV + 3 data blocks):
# range(3, 0, -1) = [3, 2, 1]
# This decrypts: block 3, then block 2, then block 1

cleartext = bytearray()

# Decrypt all ciphertext blocks (skip IV at position 0)
for block_num in range(total_blocks - 1, 0, -1):
    print(f"\n{'='*70}")
    print(f"[*] Decrypting block {block_num}/{total_blocks - 1}")
    print(f"{'='*70}")
    
    # --------------------------------------------------------
    # Extract the ciphertext block we want to decrypt
    # --------------------------------------------------------
    encrypted_block_start = block_num * AES.block_size
    encrypted_block_end = encrypted_block_start + AES.block_size
    encrypted_block = flag_encrypted[encrypted_block_start : encrypted_block_end]
    
    print(f"[*] Ciphertext block position: bytes {encrypted_block_start}-{encrypted_block_end}")
    print(f"[*] Ciphertext block: {encrypted_block.hex()}")
    
    # --------------------------------------------------------
    # Extract the previous block (needed for XOR to get plaintext)
    # --------------------------------------------------------
    # For block 1: previous = IV (block 0)
    # For block 2: previous = C1 (block 1)
    # For block 3: previous = C2 (block 2)
    # etc.
    previous_block_start = encrypted_block_start - AES.block_size
    previous_block_end = encrypted_block_start
    previous_block = flag_encrypted[previous_block_start : previous_block_end]
    
    print(f"[*] Previous block position: bytes {previous_block_start}-{previous_block_end}")
    print(f"[*] Previous block: {previous_block.hex()}")
    
    # --------------------------------------------------------
    # Use padding oracle attack to discover the intermediate state
    # --------------------------------------------------------
    print(f"[*] Running padding oracle attack...")
    print(f"[*] This will make ~2000 queries to the oracle (16 bytes × ~128 tries each)")
    
    intermediate_state = decrypt_block(io_oracle, encrypted_block)
    
    print(f"[+] Intermediate state discovered: {intermediate_state.hex()}")
    
    # --------------------------------------------------------
    # Recover plaintext using CBC decryption formula
    # --------------------------------------------------------
    # Plaintext[N] = Intermediate[N] ⊕ Ciphertext[N-1]
    decrypted_block = strxor(intermediate_state, previous_block)
    
    print(f"[+] Decrypted block: {decrypted_block.hex()}")
    print(f"[+] Decrypted text: {decrypted_block}")
    
    # Prepend to cleartext since we're working backwards
    cleartext = decrypted_block + cleartext

# ============================================================================
# Step 3: Remove PKCS7 padding and decode the flag
# ============================================================================
print(f"\n{'='*70}")
print(f"[*] All blocks decrypted!")
print(f"{'='*70}")

print(f"\n[*] Full cleartext (hex): {cleartext.hex()}")
print(f"[*] Full cleartext (with padding): {cleartext}")

# Remove PKCS7 padding
flag = unpad(cleartext, AES.block_size).decode('latin1')

print(f"\n{'='*70}")
print(f"FLAG: {flag}")
print(f"{'='*70}\n")
```
## AES-CBC-POA Encrypt

You're not going to believe this, but... a Padding Oracle Attack doesn't just let you decrypt arbitrary messages: it lets you _encrypt_ arbitrary data as well! This sounds too wild to be true, but it is. Think about it: you demonstrated the ability to modify bytes in a block by messing with the previous block's ciphertext. Unfortunately, this will make the previous block decrypt to garbage. But is that so bad? You can use a padding oracle attack to recover the exact values of this garbage, and mess with the block before that to fix this garbage plaintext to be valid data! Keep going, and you can craft fully controlled, arbitrarily long messages, all without knowing the key! When you get to the IV, just treat it as a ciphertext block (e.g., plop a fake IV in front of it and decrypt it as usual) and keep going! Incredible.

Now, you have the knowledge you need to get the flag for this challenge. Go forth and forge your message!

**FUN FACT:** Though the Padding Oracle Attack was [discovered](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf) in 2002, it wasn't until 2010 that researchers [figured out this arbitrary encryption ability](https://static.usenix.org/events/woot10/tech/full_papers/Rizzo.pdf). Imagine how vulnerable the web was for those 8 years! Unfortunately, padding oracle attacks are _still_ a problem. Padding Oracle vulnerabilities come up every few months in web infrastructure, with the latest (as of time of writing) [just a few weeks ago](https://www.cvedetails.com/cve/CVE-2024-45384/)!

Watch this [video](https://youtu.be/U8xZE6tcygo).
### Solution

```bash
hacker@cryptography~aes-cbc-poa-encrypt:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
hacker@cryptography~aes-cbc-poa-encrypt:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "please give me the flag, kind worker process!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

A Padding Oracle Attack doesn't just decrypt - it lets you **encrypt arbitrary messages without the key!**
##### How Encryption Works

Remember CBC decryption:

```
Plaintext[N] = AES_Decrypt(Ciphertext[N]) ⊕ Ciphertext[N-1]
```

We can rearrange this:

```
Ciphertext[N-1] = AES_Decrypt(Ciphertext[N]) ⊕ Plaintext[N]
                = Intermediate[N] ⊕ Plaintext[N]
```

**Key Insight**: If we know the intermediate state and our desired plaintext, we can calculate the exact ciphertext we need!

Forge a message: `"please give me the flag, kind worker process!"`
##### Steps

1. **Pick any random ciphertext block** as our target block
2. **Use padding oracle to discover its intermediate state**
3. **Calculate the previous block** that will make it decrypt to our desired text
4. **Repeat for all blocks**, working backwards

```bash
Desired plaintext: "please give me the flag, kind worker process!"
Length: 47 bytes
After padding: 48 bytes (3 blocks)

Block 1: "please give me t" (16 bytes)
Block 2: "he flag, kind wo" (16 bytes)
Block 3: "rker process!\x01\x01\x01\x01" (12 data + 4 padding)

Now we forge:
```

```bash
STEP 1: Create Block 3 (with padding)
├─ Generate random ciphertext: C3 = random 16 bytes
├─ Discover intermediate: I3 = decrypt_block(oracle, C3)
├─ Calculate C2: C2 = I3 ⊕ "rker process!\x01\x01\x01\x01"
└─ Now: C3 decrypts to "rker process!\x01\x01\x01\x01" when XORed with C2 ✓

STEP 2: Create Block 2
├─ C2 is already set from previous step
├─ Discover intermediate: I2 = decrypt_block(oracle, C2)
├─ Calculate C1: C1 = I2 ⊕ "he flag, kind wo"
└─ Now: C2 decrypts to "he flag, kind wo" when XORed with C1 ✓

STEP 3: Create Block 1
├─ C1 is already set from previous step
├─ Discover intermediate: I1 = decrypt_block(oracle, C1)
├─ Calculate IV: IV = I1 ⊕ "please give me t"
└─ Now: C1 decrypts to "please give me t" when XORed with IV ✓

RESULT: [IV][C1][C2][C3] decrypts to our message!
```

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

def decrypt_block(io, block):
    work_block = bytearray(AES.block_size)
    original_block = bytearray(AES.block_size)

    byte_index = AES.block_size - 1
    pad_counter = 1

    while byte_index >= 0:
        io.sendline(("TASK: " + work_block.hex() + block.hex()).encode())

        response = io.recvline()
        if not response.startswith(b"Unknown"):
            work_block[byte_index] += 1
            continue

        original_block[byte_index] = work_block[byte_index] ^ pad_counter

        pad_counter += 1
        byte_index -= 1

        for n in range (AES.block_size - 1, byte_index, -1):
            work_block[n] = original_block[n] ^ pad_counter

    return original_block


io = process(['/challenge/worker'])

cleartext = pad(b'please give me the flag, kind worker process!', AES.block_size)
ct_blocks = len(cleartext) // AES.block_size

guess_block = bytearray(os.urandom(16))
ciphertext = bytearray(guess_block)

for n in range (ct_blocks - 1, -1, -1):
    ct_block_start = n * AES.block_size
    ct_block_end = ct_block_start + AES.block_size

    ct_block = cleartext[ct_block_start : ct_block_end]

    decrypted_guess = decrypt_block(io, guess_block)
    previous_block = strxor(ct_block, decrypted_guess)

    ciphertext = previous_block + ciphertext
    guess_block = previous_block

io.sendline(("TASK: " + ciphertext.hex()).encode())

flag = io.recvregex(br'Your flag:\n(.+)\n', capture=True).group(1).decode()
print(flag)
```
## AES-CBC-POA-Encrypt-2

Now, you've previously started from a single valid input (the encrypted `sleep` command). What if you have _zero_ valid inputs? Turns out that all this still works!

Why? Random data decrypts to ... some other random data. Likely, this has a padding error. You can control the IV just like before to figure out the right 16th byte to xor in to resolve that padding error, and now you have a ciphertext that represents a 15-byte random message. For you, there's no real difference between that random message and `sleep`: the attack is the same!

Go try this now. No dispatcher, just you and the flag.
### Solution

```bash
hacker@cryptography~aes-cbc-poa-encrypt-2:~$ cat /challenge/.key
cat: /challenge/.key: Permission denied
hacker@cryptography~aes-cbc-poa-encrypt-2:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "please give me the flag, kind worker process!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

This time:

```bash
# NO DISPATCHER!
$ cat /challenge/dispatcher
cat: /challenge/dispatcher: No such file or directory

# We have NOTHING to start with!
# We must create our own valid ciphertext from scratch!
```

```bash
Goal: Forge message "please give me the flag, kind worker process!"
After padding: 48 bytes (3 blocks)

Block 1: "please give me t" (16 bytes)
Block 2: "he flag, kind wo" (16 bytes)
Block 3: "rker process!\x01\x01\x01\x01" (12 + 4 padding)
```

```bash
START: Generate random ciphertext block
guess_block = [random 16 bytes]

ITERATION 1: Make guess_block decrypt to Block 3
├─ Current guess_block = [random]
├─ Discover intermediate: I3 = decrypt_block(oracle, guess_block)
├─ Calculate C2: C2 = I3 ⊕ "rker process!\x01\x01\x01\x01"
├─ Build ciphertext: ciphertext = C2 + guess_block
└─ Update: guess_block = C2 (for next iteration)

ITERATION 2: Make C2 decrypt to Block 2
├─ Current guess_block = C2
├─ Discover intermediate: I2 = decrypt_block(oracle, C2)
├─ Calculate C1: C1 = I2 ⊕ "he flag, kind wo"
├─ Build ciphertext: ciphertext = C1 + C2 + guess_block
└─ Update: guess_block = C1

ITERATION 3: Make C1 decrypt to Block 1
├─ Current guess_block = C1
├─ Discover intermediate: I1 = decrypt_block(oracle, C1)
├─ Calculate IV: IV = I1 ⊕ "please give me t"
└─ Build ciphertext: ciphertext = IV + C1 + C2 + guess_block

RESULT: [IV][C1][C2][C3] decrypts to our message!
```

```bash
INITIAL STATE
═════════════
guess_block = 0x3F7A8B2C... (random 16 bytes)
ciphertext = 0x3F7A8B2C... (same as guess_block)


ITERATION 1 (n=2, working on Block 2)
═══════════════════════════════════════
Target plaintext: "rker process!\x01\x01\x01\x01"

Step 1: Identify target block
ct_block_start = 2 * 16 = 32
ct_block_end = 32 + 16 = 48
ct_block = cleartext[32:48] = "rker process!\x01\x01\x01\x01"

Step 2: Discover intermediate of guess_block
decrypted_guess = decrypt_block(oracle, guess_block)
# Makes ~2000 queries
# Result: decrypted_guess = 0xA1B2C3D4E5F6... (intermediate state)

Step 3: Calculate previous block
previous_block = ct_block ⊕ decrypted_guess
               = "rker process!\x01\x01\x01\x01" ⊕ 0xA1B2C3D4...
               = 0xC7D8E9FA... (this is C2)

Explanation:
- We want: Plaintext[2] = Intermediate[guess_block] ⊕ Previous_Block
- We know: Intermediate[guess_block] and desired Plaintext[2]
- So: Previous_Block = Plaintext[2] ⊕ Intermediate[guess_block]

Step 4: Update ciphertext and guess_block
ciphertext = previous_block + ciphertext
           = 0xC7D8E9FA... + 0x3F7A8B2C...
           = [C2][C3]

guess_block = previous_block = 0xC7D8E9FA... (C2)

State after iteration 1:
ciphertext = [C2][C3] (32 bytes)
guess_block = C2


ITERATION 2 (n=1, working on Block 1)
═══════════════════════════════════════
Target plaintext: "he flag, kind wo"

Step 1: Identify target block
ct_block_start = 1 * 16 = 16
ct_block_end = 16 + 16 = 32
ct_block = cleartext[16:32] = "he flag, kind wo"

Step 2: Discover intermediate of C2
decrypted_guess = decrypt_block(oracle, guess_block)
                = decrypt_block(oracle, C2)
# Makes ~2000 queries
# Result: 0x12345678... (intermediate of C2)

Step 3: Calculate previous block (C1)
previous_block = ct_block ⊕ decrypted_guess
               = "he flag, kind wo" ⊕ 0x12345678...
               = 0xABCDEF01... (this is C1)

Step 4: Update ciphertext and guess_block
ciphertext = previous_block + ciphertext
           = 0xABCDEF01... + [C2][C3]
           = [C1][C2][C3]

guess_block = previous_block = 0xABCDEF01... (C1)

State after iteration 2:
ciphertext = [C1][C2][C3] (48 bytes)
guess_block = C1


ITERATION 3 (n=0, working on Block 0)
═══════════════════════════════════════
Target plaintext: "please give me t"

Step 1: Identify target block
ct_block_start = 0 * 16 = 0
ct_block_end = 0 + 16 = 16
ct_block = cleartext[0:16] = "please give me t"

Step 2: Discover intermediate of C1
decrypted_guess = decrypt_block(oracle, guess_block)
                = decrypt_block(oracle, C1)
# Makes ~2000 queries
# Result: 0x98765432... (intermediate of C1)

Step 3: Calculate previous block (IV)
previous_block = ct_block ⊕ decrypted_guess
               = "please give me t" ⊕ 0x98765432...
               = 0xFEDCBA98... (this is the IV!)

Step 4: Update ciphertext
ciphertext = previous_block + ciphertext
           = 0xFEDCBA98... + [C1][C2][C3]
           = [IV][C1][C2][C3]

Final state:
ciphertext = [IV][C1][C2][C3] (64 bytes)


VERIFICATION
═════════════
Send: TASK: [IV][C1][C2][C3]

Oracle decrypts:
- Decrypt C1, XOR with IV     → "please give me t"
- Decrypt C2, XOR with C1     → "he flag, kind wo"
- Decrypt C3, XOR with C2     → "rker process!\x01\x01\x01\x01"
- Unpad                       → "please give me the flag, kind worker process!"
- Match target                → "Victory! Your flag: ..."
```

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor

def decrypt_block(io, block):
    work_block = bytearray(AES.block_size)
    original_block = bytearray(AES.block_size)

    byte_index = AES.block_size - 1
    pad_counter = 1

    while byte_index >= 0:
        io.sendline(("TASK: " + work_block.hex() + block.hex()).encode())

        response = io.recvline()
        if not response.startswith(b"Unknown"):
            work_block[byte_index] += 1
            continue

        original_block[byte_index] = work_block[byte_index] ^ pad_counter

        pad_counter += 1
        byte_index -= 1

        for n in range (AES.block_size - 1, byte_index, -1):
            work_block[n] = original_block[n] ^ pad_counter

    return original_block


io = process(['/challenge/worker'])

cleartext = pad(b'please give me the flag, kind worker process!', AES.block_size)
ct_blocks = len(cleartext) // AES.block_size

guess_block = bytearray(os.urandom(16))
ciphertext = bytearray(guess_block)

for n in range (ct_blocks - 1, -1, -1):
    ct_block_start = n * AES.block_size
    ct_block_end = ct_block_start + AES.block_size

    ct_block = cleartext[ct_block_start : ct_block_end]

    decrypted_guess = decrypt_block(io, guess_block)
    previous_block = strxor(ct_block, decrypted_guess)

    ciphertext = previous_block + ciphertext
    guess_block = previous_block

io.sendline(("TASK: " + ciphertext.hex()).encode())

flag = io.recvregex(br'Your flag:\n(.+)\n', capture=True).group(1).decode()
print(flag)
```
# Asymmetric Cryptography
## DHKE

So, you now (hopefully!) understand the use of AES and the various hurdles, but there has been one thing that we have not considered. If person A (commonly referred to as [Alice](https://en.wikipedia.org/wiki/Alice_and_Bob)) wants to encrypt some data and send it to person B (commonly referred to as Bob) using AES, they must first agree on a key. If Alice and Bob see each other in person, one might write the key down and hand it to the other. But this rarely happens --- typically, the key must be established remotely, with Alice and Bob on either end of a (not yet encrypted!) network connection. In these common cases, Alice and Bob must securely generate a key even if they are being eavesdropped upon (think: network sniffing)! Fun fact: typically, the eave_sdropper is referred to as Eve.
#### What is Diffie-Hellman Key Exchange (DHKE)?

It's a method that allows two people (traditionally **Alice** and **Bob**) to **create a shared secret number** over a public, insecure channel (where an eavesdropper, **Eve**, can hear everything). This shared secret can then be used as a key to encrypt their future messages.

The security is based on the **Discrete Logarithm Problem**, which is computationally hard to solve with classical computers.

1. **Finite Field (Modulo Arithmetic)**: Think of a clock. On a 12-hour clock, 14:00 is the same as 2:00. We say "14 mod 12 = 2". DHKE uses a clock with `p` hours, where `p` is a huge prime number. All calculations "wrap around" this clock.    
2. **Generator (`g`)**: A special number (a _primitive root modulo p_) that, when you calculate `g¹ mod p`, `g² mod p`, `g³ mod p`... up to `g^(p-1) mod p`, it will generate _every_ number from 1 to `p-1` in some scrambled order. This is crucial for security.

**Step 1: Public Parameters (Agreed Openly)**  
Alice and Bob publicly agree on two numbers:

- **`p`** = A large prime number. _(Example: `p = 23`)_
- **`g`** = A generator (primitive root) modulo `p`. _(Example: `g = 5`)_  
    Eve sees `p` and `g`.

**Step 2: Private Secrets (Kept Hidden)**

- **Alice** chooses a **private key `a`**. _(She picks: `a = 6`)_
- **Bob** chooses a **private key `b`**. _(He picks: `b = 15`)_  
    They never share `a` and `b` with anyone

**Step 3: Public Keys (Exchanged Openly)**  
They each compute their **public key** using their private key:

**Alice** computes: **`A = g^a mod p`**

- `A = 5⁶ mod 23`
- `5⁶ = 15625`
- `15625 mod 23 = 8` *(because 15625 ÷ 23 = 679 with a remainder of 8)*

- So, **`A = 8`**. Alice sends `A=8` to Bob.

- **Bob** computes: **`B = g^b mod p`**
    
    - `B = 5¹⁵ mod 23`
    - `5¹⁵ mod 23 = 19` _(trust the math, this is a big number!)_

    - So, **`B = 19`**. Bob sends `B=19` to Alice.  
        Eve now also sees `A=8` and `B=19`.

**Step 4: Calculating the Shared Secret**  
Now, Alice and Bob use the other person's public key and their own private key to compute the _same_ secret.

- **Alice** computes the **shared secret `s`**:
    
    - `s = B^a mod p`
    - `s = 19⁶ mod 23`
    - `19⁶ mod 23 = 2` _(Again, trust the calculation)_
    - Alice gets **`s = 2`**.

- **Bob** computes the **shared secret `s`**:
    
    - `s = A^b mod p`
    - `s = 8¹⁵ mod 23`
    - `8¹⁵ mod 23 = 2`
    - Bob also gets **`s = 2`**.

Because `A` and `B` are public, they are termed _public keys_, with `a` and `b` being _private keys_. Furthermore, you may noticed in this level that the prime number `p` that we use is hardcoded and, in fact, there are recommended DHKE [for many bitsizes](https://datatracker.ietf.org/doc/html/rfc3526). The standardization of these primes allows Alice and Bob to just publish `A` and `B` (though, in practice, `p` is also transmitted to support the use of different `p`s in certain scenarios).

In real-world use (like in HTTPS, VPNs, SSH), `p` and `g` are standardized for different security levels (e.g., 2048-bit primes). The parties often only need to exchange their public keys (`A` and `B`), as the other parameters are already agreed upon.

In this challenge you will perform a Diffie-Hellman key exchange. Good luck!
### Solution

```bash
hacker@cryptography~dhke:~$ /challenge/run
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0xd256a7bff5774d6659024876056065c64e1c744e77fc7c447d2567e7bee441f980d756ff6f816524486bbbcac668f74d853bc5111bd41390aab76ef802f2288b589263ff78ccd36ef9925cf11f3a6d4bdbaeefc97f176bc574425315a0e515ae9f20e96f5b9626127e0c8f6e430d7ee9dfcc3048f52c39d88d1175b226ba9c75e306296d69e7a85337785cce178febd6a9df293ac3c6500f6cd8a7a13cdcd7b34955ec929b05aa1ac768136b0acc390bb385e95f95699142771735f883fbcfd558cad6d370f68d0da6f76b06c4676ceeb3da5f024d56449a137328456ff30dac526d5d133a0099aed47cd4eb2af94922b76dea61de28364147bce05ce8d2eed4
B? 
```

```python
from pwn import *
from Crypto.Random.random import getrandbits

# Create a process to run the challenge binary
io = process(['/challenge/run'])

# --- STEP 1: Read the public parameters from the server ---
# The server (acting as Alice) sends: p, g, A
# We use regex to capture the hex values

# Read prime p (large prime number defining the finite field)
p_hex = io.recvregex(br'p = (.+)\n', capture=True).group(1).decode()
# Read generator g (primitive root modulo p)
g_hex = io.recvregex(br'g = (.+)\n', capture=True).group(1).decode()
# Read Alice's public key A = g^a mod p
A_hex = io.recvregex(br'A = (.+)\n', capture=True).group(1).decode()

p = int(p_hex, 16)
g = int(g_hex, 16)
A = int(A_hex, 16)

# --- STEP 2: Generate Bob's key pair ---
# Generate Bob's private key b (random 2048-bit number)
b = getrandbits(2048)
# Compute Bob's public key B = g^b mod p
B = pow(g, b, p)

# --- STEP 3: Compute the shared secret ---
# Shared secret s = A^b mod p = (g^a)^b mod p = g^(ab) mod p
# This matches what Alice computes: s = B^a mod p = (g^b)^a mod p = g^(ba) mod p
s = pow(A, b, p)

# --- STEP 4: Send Bob's public key to the server ---
# Wait for the "B? " prompt from the server
io.recvn(len('B? '))
# Send Bob's public key B as hex (without '0x' prefix)
io.sendline(hex(B).encode())

# --- STEP 5: Send the computed shared secret ---
# Wait for the "s? " prompt from the server
io.recvn(len('s? '))
# Send the shared secret s as hex
io.sendline(hex(s).encode())

flag = io.recvregex(br'your flag:\n(.+)\n', capture=True).group(1).decode()
print(flag)
```
## DHKE-to-AES

You might have noticed that DH doesn't actually allow you to encrypt data directly: all it does is facilitate the generation of the same secret value for both Alice and Bob. This value cannot be _chosen_, what Alice and Bob get for `s` is uniquely determined by the values of `a`, `b`, `p`, and `g`!

This single-secret nature isn't necessarily a drawback of DHKE. That's just what it's for: letting you exchange a secret for further use.

So how do Alice and Bob actually exchange information using DHKE? Well, the hint is in the name: Diffie-Hellman _Key Exchange_. That secret value, of course, can be used as a key for, e.g., a symmetric cipher, and information can be encrypted with that cipher between Alice and Bob!

Armed with your knowledge of DHKE, you will now build your first cryptosystem that resembles something real! You'll use DHKE to negotiate an AES key, and the challenge will use that key to encrypt the flag. Decrypt it, and win!
### Solution

```bash
hacker@cryptography~dhke-to-aes:~$ /challenge/run 
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0xe2dea786a5b97df6487f5a00de4e121b4763dc886156f58881eac21f0f2740caeba7357ef6da406a653ccca676e32d2909d04947e0e4a29d45f8ac73803a8f82eafde4608ddd564cdfe43ca5d574eeb958b318fc78d3d73cf74d1e10085df12eb4607d4dd403b9ffa81ca3db404ae7673e3f75e3b0949a10fb6b6ee59b749d76e8ee43b5099c9224e869876dc4526cfa34faf0e40b4fb5a8580dd718eae28187d97bc40b3725e8cc697dcaefad8720ec4cfcad42d09008ffa7364316461022589a6f23527724213ba163d4a02707221df5c20c97fe8da1084897b31c16a6f4fa86ed6d907e05449d2a9c63f428c667f232ca5d7ca29f5c0dfab1a4522c2d6022
B? 
```

```bash
hacker@cryptography~dhke-to-aes:~$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

flag = open("/flag", "rb").read()
assert len(flag) <= 256

# 2048-bit MODP Group from RFC3526
p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
g = 2
print(f"p = {p:#x}")
print(f"g = {g:#x}")

a = getrandbits(2048)
A = pow(g, a, p)
print(f"A = {A:#x}")

try:
    B = int(input("B? "), 16)
except ValueError:
    print("Invalid B value (not a hex number)", file=sys.stderr)
    sys.exit(1)
if B <= 2**1024:
    print("Invalid B value (B <= 2**1024)", file=sys.stderr)
    sys.exit(1)

s = pow(B, a, p)
key = s.to_bytes(256, "little")[:16]

# friendship ended with DHKE, AES is my new best friend
cipher = AES.new(key=key, mode=AES.MODE_CBC)
flag = open("/flag", "rb").read()
ciphertext = cipher.iv + cipher.encrypt(pad(flag, cipher.block_size))
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```python
#!/usr/bin/env python3
from pwn import *
from Crypto.Random.random import getrandbits
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Start the challenge process
io = process(['/challenge/run'])

# --- STEP 1: Parse Diffie-Hellman Parameters ---
# The server sends three values: p (prime), g (generator), A (Alice's public key)

# Extract prime p from the server output using regex
# Example output: "p = 0xffffffffffffffffc90fdaa2..."
p_hex = io.recvregex(br'p = (.+)\n', capture=True).group(1).decode()
# Convert hex string to integer
p = int(p_hex, 16)

# Extract generator g (primitive root modulo p)
g_hex = io.recvregex(br'g = (.+)\n', capture=True).group(1).decode()
g = int(g_hex, 16)

# Extract Alice's public key A = g^a mod p
A_hex = io.recvregex(br'A = (.+)\n', capture=True).group(1).decode()
A = int(A_hex, 16)

# --- STEP 2: Perform Diffie-Hellman Key Exchange as Bob ---
# Generate Bob's private key (random 2048-bit number)
b = getrandbits(2048)

# Compute Bob's public key B = g^b mod p
B = pow(g, b, p)

# Compute the shared secret s = A^b mod p = (g^a)^b mod p = g^(ab) mod p
# This will match what Alice computes: s = B^a mod p = (g^b)^a mod p = g^(ba) mod p
s = pow(A, b, p)

# --- STEP 3: Derive AES Key from Shared Secret ---
# Convert the shared secret integer to bytes
# Using "little" endian: least significant byte first
# Taking first 16 bytes for a 128-bit AES key
key = s.to_bytes(256, "little")[:16]
# Note: Alternative approach would be to use hash function like SHA-256
# to ensure uniform key distribution

# --- STEP 4: Send Bob's Public Key to Server ---
# Wait for the server to prompt for Bob's public key
io.recvn(len('B? '))
# Send Bob's public key in hex format
io.sendline(hex(B).encode())

# --- STEP 5: Receive and Decrypt the Encrypted Flag ---
# The server encrypts the flag with AES-CBC using the shared secret as key
# and sends the ciphertext in hex format

# Extract the ciphertext hex from the server output
# Example: "Flag Ciphertext (hex): a55d77d58283..."
ciphertext = io.recvregex(br'Flag Ciphertext .*: (.+)\n', capture=True).group(1).decode()
# Convert hex string to bytes
ciphertext = bytes.fromhex(ciphertext)

# --- STEP 6: Decrypt the Flag using AES-CBC ---
# In AES-CBC mode, the first 16 bytes (AES.block_size) are the Initialization Vector (IV)
# The remaining bytes are the actual encrypted data

# Create AES cipher object with our derived key
# Mode: CBC (Cipher Block Chaining)
# IV: First 16 bytes of the ciphertext
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=ciphertext[:AES.block_size])

# Decrypt the actual encrypted data (everything after the IV)
encrypted_data = ciphertext[AES.block_size:]
flag_encrypted = cipher.decrypt(encrypted_data)

# Remove PKCS7 padding (standard padding for block ciphers)
# PKCS7 adds bytes where each added byte equals the number of padding bytes
flag = unpad(flag_encrypted, cipher.block_size)

# --- STEP 7: Print the Flag ---
print(flag.decode())
```
## RSA 1

Diffie-Hellman allow Alice and Bob to generate a single (but uncontrolled) shared secret with no pre-shared secret information. Next, we'll learn about another cryptosystem, [RSA (Rivest–Shamir–Adleman)](https://en.wikipedia.org/wiki/RSA_\(cryptosystem\)), that allows Alice and Bob to generate arbitrary amounts of controlled messages, with no pre-shared secret information!

RSA uses a clever interaction of modular exponentiation (which you've experienced in DH) and [Euler's Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem) to give Bob or Alice _asymmetric_ control over an entire finite field. Alice generates two primes, `p` and `q`, _and keeps them secret_, then multiplies them to create `n = p*q`, which Alice publishes to define a Finite Field modulo `n`. Euler's Theorem and knowledge of `p` and `q` gives Alice, _and only Alice_, full abilities within this specific field (which is a difference from DH, where all actors have equal capabilities in the field!).
#### Step 1: Key Generation (Alice's Setup)

Let's use small primes for demonstration (real RSA uses primes with 1024+ bits):

1. **Choose two prime numbers**  
    `p = 61`  
    `q = 53`  
    (These are kept **secret**)
    
2. **Compute public modulus**  
    `n = p × q = 61 × 53 = 3233`  
    This is **public**
    
3. **Compute Euler's totient**  
    `φ(n) = (p-1) × (q-1) = (61-1) × (53-1) = 60 × 52 = 3120`  
    This is kept **secret** (requires knowing p and q)
    
4. **Choose public exponent e**  
    `e = 17` (commonly 65537 in practice)  
    Requirements:
    
    - `1 < e < φ(n)`
        
    - `gcd(e, φ(n)) = 1` (coprime)  
        `gcd(17, 3120) = 1` ✓
        
5. **Compute private exponent d**  
    Find `d` such that:  
    `e × d ≡ 1 mod φ(n)`  
    `17 × d ≡ 1 mod 3120`  
    Solving: `d = 2753` (since `17 × 2753 = 46801 = 15×3120 + 1`)
    
#### Step 2: Key Distribution

**Public Key (Alice gives this to everyone):** `(e, n) = (17, 3233)`  
**Private Key (Alice keeps this secret):** `(d, n) = (2753, 3233)`
#### Step 3: Encryption (Bob → Alice)

Bob wants to send message `m = 123` to Alice:

**Encryption formula:** `c ≡ m^e mod n`  
`c ≡ 123¹⁷ mod 3233`

Calculate:

```
123² mod 3233 = 15129 mod 3233 = 15129 - 4×3233 = 15129 - 12932 = 2197
123⁴ mod 3233 = 2197² mod 3233 = 4826809 mod 3233 = 288
123⁸ mod 3233 = 288² mod 3233 = 82944 mod 3233 = 1753
123¹⁶ mod 3233 = 1753² mod 3233 = 3073009 mod 3233 = 1916

Now 123¹⁷ = 123¹⁶ × 123
c ≡ 1916 × 123 mod 3233 = 235668 mod 3233
235668 ÷ 3233 ≈ 72.88
235668 - 72×3233 = 235668 - 232776 = 2892
c = 2892
```

Bob sends ciphertext `c = 2892` to Alice.
#### Step 4: Decryption (Alice reads Bob's message)

**Decryption formula:** `m ≡ c^d mod n`  
`m ≡ 2892²⁷⁵³ mod 3233`

This looks huge, but using Euler's theorem and modular exponentiation tricks:

We know: `m^(e×d) ≡ m mod n` when `e×d ≡ 1 mod φ(n)`


`2892²⁷⁵³ mod 3233 = 123`

Let's verify with a smaller intermediate calculation:  
Since `e×d = 17×2753 = 46801 = 15×3120 + 1`  
And by Euler's theorem: `m^φ(n) ≡ 1 mod n` when gcd(m, n) = 1

So: `m^(e×d) = m^(15×3120 + 1) = (m^3120)^15 × m ≡ 1^15 × m ≡ m mod n`

Therefore, decryption recovers: `m = 123`

In this challenge you will decrypt a secret encrypted with RSA (Rivest–Shamir–Adleman). You will be provided with both the public key and private key this time, to get a feel for how all this works. Go for it!
## Solution

```
hacker@cryptography~rsa-1:~$ /challenge/run
(public)  n = 0xcbfd48b151969a4813bb98ad0d60b796d62ba48ca9fe23d63e4f2ab3049cfaced4020a1bbc4f17599bddaccefae47b8bbe76b94ebccec4aee4f22d81fde5c1d1013cc4190c10e1f3e0d3e9eb1ab1c3c1dc9d22a800746711273bba9e3df32b958e17f5118c7852af01f3afa18031c74b05a2ddd3c21d8878b15e613359c08f16e9a96661260ac99c5a995c20ccaf5b3e93c42f344b1cea475ee414fc1beedcab095c8d4bdf92fe41de6bd71277bee616068498cc28c65e5fc55a28c40555f03e654927f91e676e4552a2f932a5d27646e0f733574a062dda91891c80da17a033fa5438de423bb5d7449a28ae1bc75a3875bfa44a072f076e527c41b2b54e10a9
(public)  e = 0x10001
(private) d = 0x518aba83b3370e0e30e1251b4c0534ee3547b5dbcada3dce17134360d33fc31c697035453805afb250d5908e1e89b5ff3b102f6c139a5dd201cff3340adfcc95b5366ab70e7533356f5296a7b600885d96c83381cfc8b82889b3dd1a036e90a6146a6c3aeb197007e83256ab2ad8fb2ef89e4da927e7f15539a59e1a4e4ee4834f2b2ac1e2cd09fa7cd416ed34349d09379aacfe21b16348dff0c3793ce3fe9280efc6f43bcb6a3168aef7aa19e0b1690ca3b3a69b948601d68f84316472723875ccf39105a8cc678094a8b39747560747e05a65fd9798c1215ebdb321ba84ac1d6f163862ad0bb94bdd2cd58561c695cfe414048c0ba4a516cf22800827b7cf
Flag Ciphertext (hex): 5d1fd3d5f870d37260e7ca9f01a22686d2cb8b2b09cdeafe5e59c1b1e294aeceb4b8db9ca72a24e65c0b82f2a631af711b0681620415140dbe18e3ac2b34ede2185993b303d0cb7ef1f61390acb9052f83e5acfb48a4e814d8c62e1dea9147b15cbb8eb3104a3d7bbdd3cf6d81aa27c7d9f8c3030e73c72a8512862e92ecc76e164c05200e91ad8e503cc2f501077c65b76be077f1f070c59d09ce6e00fad5cbaec0f6d664adef23b55efe86196271021a4e7c9f6b420aeeef6f47bec56c4a506b9a5890d72cab0c2b26c7ec8688c07242967b8b7f5469a5f55b407b22b043a2fc75ee45f2f393ad795be841b96df27d882b911c237e81f5e381140530f93379
```

**Decryption formula:** `m ≡ c^d mod n`  

```python
from pwn import *

io = process(['/challenge/run'])

n_hex = io.recvregex(br'.+ n = (.+)\n', capture=True).group(1).decode()
e_hex = io.recvregex(br'.+ e = (.+)\n', capture=True).group(1).decode()
d_hex = io.recvregex(br'.+ d = (.+)\n', capture=True).group(1).decode()

n = int(n_hex, 16)
d = int(d_hex, 16)

flag_ciphertext = io.recvregex(br'Flag Ciphertext .*: (.+)\n', capture=True).group(1).decode()
flag_ciphertext = bytes.fromhex(flag_ciphertext)

flag = pow(int.from_bytes(flag_ciphertext, "little"), d, n).to_bytes(256, "little")
print(flag.decode().rstrip('\0'))
```
## RSA 2

Alice's superpower under modulo `n` comes from knowledge of `p` and `q`, and, thus, the ability to compute the multiplicative inverse of `e` in the exponent. One worry of everyone who uses RSA is that their `n` will get factored, and attackers will gain `p` and `q`.

This is not an unreasonable worry. While we _believe_ that factoring is hard, we have no actual proof that it is. It is not outside of the realm of possibility that, tomorrow, Euler 2.0 will publish an algorithm for doing just this. However, we _do_ know that functional quantum computers can factor: Euler 2.0 (actually, [Peter Shor](https://en.wikipedia.org/wiki/Peter_Shor)) already came up with the [algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)! When quantum computers get to a sufficient power level, RSA is cooked.

In this challenge, we give you the quantum computer (or, at least, we give you `n`'s factors)! Use them to decrypt the flag that we encrypted with RSA (Rivest–Shamir–Adleman).
### Solution

```bash
hacker@cryptography~rsa-2:~$ /challenge/run
e = 0x10001
p = 0xdc71458fd4f34ffb7274417ee3b85d6fc960b02ba431826cddd6a5c47f38c66dcf4e5113b4edddcc75ffbba8ff5e3fc62026960f68676cb3a8ac7ff20a0ea348c9ff5bd56fd51a7bc9dc2c63cb8da1dab4d7af183aefff1ec70e5aec590c27cf8299e81d436d1e4e32d8ec29e9a632e5eb2ac263a44915a74a85f7660afc09d5
q = 0xe12e9ed57889cee222536bbb6c98c02968cf2b760529b2f8d3edf55c50ef0a211ca30c01e634baecbf1219ad6e9340f4ad203ad27051904789c9478bf06a4e2086f226e8aaead1be8032613c8cfdde1ccb6c2dee18675b182921d2cc9bdd81d6725e906af59d8a79220923679996c22d2bc8229231517bcb13791788f1de001d
Flag Ciphertext (hex): ce0293be9ba12d014046e433398fd7cb98329cb2b80c9e4be799e39ed2bf2c8eefb1a6def083b7a1cb32cd5c58bae6c9083e3f2b46f00f769f4300bed3a72e800df6e0329c715527f374e6ff623bb4a813887a9b919d9c6b58dff2d02da39b9aff6cac15c2e686cf7e4b16e3fd87069cfefcbd5d04ff358163b736ca6b115f8505eadc840402b4faa7e65e2ec3dd98904f27d077a9807003bdce4fbeea253fb4c42bf79aeb587af25037f09f873ff956045f499a6cc2118169f2e2aae4c469eaf07a847202ba6fe89914bf65d31a0a9fceaa207c2f9ab552e270724d5e47391c2380ccc11fc90b7b20b445319d17eeaa36c1dcc0360e4c16026b08e4345e2751
```

```python
from pwn import *

io = process(['/challenge/run'])

e_hex = io.recvregex(br'e = (.+)\n', capture=True).group(1).decode()
p_hex = io.recvregex(br'p = (.+)\n', capture=True).group(1).decode()
q_hex = io.recvregex(br'q = (.+)\n', capture=True).group(1).decode()

e = int(e_hex, 16)
p = int(p_hex, 16)
q = int(q_hex, 16)

n = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

flag_ciphertext = io.recvregex(br'Flag Ciphertext .*: (.+)\n', capture=True).group(1).decode()
flag_ciphertext = bytes.fromhex(flag_ciphertext)

flag = pow(int.from_bytes(flag_ciphertext, "little"), d, n).to_bytes(256, "little")
print(flag.decode().rstrip('\0'))
```
## RSA 3

In this challenge you will complete an RSA challenge-response. You will be provided with both the public key and private key.
### Solution

```bash
hacker@cryptography~rsa-3:~$ /challenge/run
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will complete an RSA challenge-response.
You will be provided with both the public key and private key.


e: 0x10001
d: 0x33b2245cb59136e5f7be840c98d1009f6880118d78cd5cb5c4de152a610dcb52619d4a8d3bd046c35b9d77da5b9a3a475e59b5d673ae3a7837f2411310e3bce8365f7e162679a9bab9d0c33216ca8a91ed0a24ff11034c3b545693ad25123104a6d343e91cad7c5b99bc5f261eecb341f417c43cc0d7f117233f86a08f031181abf2f05fe8cb118ec6691093cd43d5eb307068e4e95b624fc3a1ebcee276076c0281e54d35399224885c930363701fdb613b10d26f1402f43131e1df0667ddbe727f609e719e1fc4b2a870a16feaa83c0deb0b7d680bbdff9f92108268e5c1f7c3aa8cfa0095927250206edccb02192d86d6b20a19f3897401c18d96ac85f621
n: 0x9d0ff67dfcd18b0b8e13331aa1350de0d938c3a5986d88abc4f1b3203f541c8840d779364081e9602b4db12c0f0201164886649df45a99b784397fea2fc3f8676e5ae39289c863d6200361e84fce74ceec0d14276cc5c7907317b94fea27c82903619f0b6f8757349c6ac5e9bca5f0028e44874c8641b303be0bf6145c5fd9b4a844f60c0e99c065d8097291ca4b15ec29749cb115caa3e94177092545f4df86ec1e93f07671b9ca46a105dbcbc4604ac84ec181611ba1b903e01ad2a07ab4de785fbe9432450cf0cec62aebd9d9a0fbee5bce0bbf0b2c79917fe29f179a115844423a05bc6c48a19a8dc285b5085eadcab0d7704f129dc747d3a379cbff32c7
challenge: 0x808737f71c19a46ec42a18da90e5077f42371646a5df021ad4b3b758cd8bd8ac6461c065375420a51e87ad3337009640ab372390bf05df9d51b20a2d7107578ab7692bba830eded7cf03ca31ae126596098b9d5d78a6a903c9d2742356f50f68d618be4c561b814f0d64bbb5be712e02dbd261724dcba71969c94b2d8c786e7ed9b21ee86f7f85dd62409df3d7cb177e0881b76a8c8485363b14b1619a512a0f184032829412b1e636d514fedb4c251a089c991e57ba5bcd0a5d57f97afb8c893763684af6be7cf15b766209512f22a7dcceb76716fd5345b1456908c28c6119c5b67ce31856e48417dbeee87504d5ea228ba5c5197fb83047320bc7ee58411b
response: 
```

```python
import base64

# Given values from the challenge
e = 0x10001
d = 0xbe64834108f73f5a0cb4167131c194dda5296d8f5b1be26ee45b66dc430590df4afd7ccebb4c07749d1699c4657c6c3fc0c878f245c6052d022d9aba0a4cea2a8fabe145b3f330297fc1508866b981eb6a41f6f9d611a06bab3c3f2c43a5c22bb6b59979c8556315dbfb336ed78edba04c26d2a5e0c40de1a554ee99a44493bac89094eb75a2bc5b4ddef2a70194bb0f51b1e39c00522dec43fc50c1261dc0ac5ec7fb521d1a2fc191bbf20d425788b247c3ae00c3c7369a461e3677c35e2819ea1821d376c81c2cac98067bac146bc00baab915f0b7c183c014dfa748a6cee2a8b7681fffd934e238cb73615a1c79fc062d55477f1835fac0a21bad7bcb03
n = 0xe8f55b80328bb8167fa683e06bea420dd8fdcf299d441705580178c923f354cbb716088a32122bf7aa597857c22197e5850455fc20ea63d2fc7bfea8f8a2e643c42e5e087fdad396b9c45fca09e185a79652ffac8e19098d9204032b485be7c065a1642b11bb05765fbdab14af9fc044600e0d1a46232d7397977b5411f825d2bdee4b7c68d741d848258b1162dc250a0e5c9bbbb767b1ba649479300d484de73f5fdabf635afa76d4170c54665f47f28a983d40b353f7579b6ab190dfabc1763cb6c1004df5ec8919e565ff5433dbd10beb058a908d3d7d458e80ca9c7d8e4e89a8fd96131f60d5cfe4d5c8a68c4dcf3edb1e6fc3783b7bc0495b057cb27e41
challenge = 0x5903d94d3acc79850bc5fb0b806839a007e1e2dd14c3823cfdecb82cd941d1fbb931460a0be1a12fd693fc000f9c9250fd5ae4f2d1540a37e8dd3072ff71b4ae66d7bd467cfc12abe84ad665e7194ce20efa8556496afd52172d45ec6c0e0733f7eff356261bc131859626d30198fd8ecc6e0fc0ef8c9497393c20bd3c50fc2f9204b479171ec37d215226f13ad105d9e1240a93eb0a0b3363c66b395490a7f00a3558e364e3821761078d933028869c125cadb85f97f259a93890d0d1130df41d420c9efa27780e32d738ad127550a85a82497adf786ae1074b745aa99910a21880ed9220b21b982b28f9b7c2368d7af2be39a6bae8c6a09d9fefb245d0e047

# Compute response = challenge^d mod n
response = pow(challenge, d, n)

# Convert to hex string (remove '0x' prefix)
response_hex = hex(response)[2:]

print(f"Response: {response_hex}")
```
## RSA 4

In this challenge you will complete an RSA challenge-response. You will provide the public key.
### Solution

```python
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, GCD
import sys

# Choose public key
e = 65537

# Generate a prime n (simplest - n is prime itself)
# n must be between 2^512 and 2^1024
n = getPrime(513)  # 513-bit prime

# Since n is prime, phi = n-1
phi = n - 1

# Make sure e and phi are coprime
while GCD(e, phi) != 1:
    n = getPrime(513)
    phi = n - 1

# Compute private key d
d = pow(e, -1, phi)

print(f"Send this to server:")
print(f"e: {hex(e)[2:]}")
print(f"n: {hex(n)[2:]}")
print()
print(f"Your private key d: {hex(d)[2:]}")
print()
print("When server sends challenge c:")
print("response = c^d mod n")
print("Python: response = pow(c, d, n)")
print("Send hex(response)[2:] as response")
print()
print("Then server will give: ciphertext = flag^e mod n")
print("Decrypt: flag = ciphertext^d mod n")
print("flag = long_to_bytes(pow(ciphertext, d, n)).rstrip(b'\\x00')")
```

```bash
$ python3 main.py
Send this to server:
e: 10001
n: 1b896d1bcf32298eb2ac3ebb0a1de29b5c3f1611196d282a2a3a29334651902149543e37c1defeb56c71b1aa53b24ee6042ccdfdbf882b383bf3525981406f6e7

Your private key d: 46a2cf6f769f865ab5998190e8f2a04746e9cd012fe8020fa7226a6d4d040c645665f2f3b42d01d300cae4a3b6eebdd4eb00c3a7159986c4498470c987f471e3

When server sends challenge c:
response = c^d mod n
Python: response = pow(c, d, n)
Send hex(response)[2:] as response

Then server will give: ciphertext = flag^e mod n
Decrypt: flag = ciphertext^d mod n
flag = long_to_bytes(pow(ciphertext, d, n)).rstrip(b'\x00')
```

```bash
e: 10001
n: 1b896d1bcf32298eb2ac3ebb0a1de29b5c3f1611196d282a2a3a29334651902149543e37c1defeb56c71b1aa53b24ee6042ccdfdbf882b383bf3525981406f6e7
challenge: 0x6e3e6009c3da988fcf2f1480494eb27902b391f4e8f6858fbce20e85bc89a37feba3b4245a279f35f0563adb26702497260e9559fa525658b1bf73b952f1b7d9
```

```bash
# Actually compute it
e = 65537
n = int("1b896d1bcf32298eb2ac3ebb0a1de29b5c3f1611196d282a2a3a29334651902149543e37c1defeb56c71b1aa53b24ee6042ccdfdbf882b383bf3525981406f6e7", 16)
challenge = int("6e3e6009c3da988fcf2f1480494eb27902b391f4e8f6858fbce20e85bc89a37feba3b4245a279f35f0563adb26702497260e9559fa525658b1bf73b952f1b7d9", 16)

phi = n - 1
d = pow(e, -1, phi)
response = pow(challenge, d, n)

print(f"Response hex: {hex(response)[2:]}")
```

```bash
┌──(venv)─(at0m㉿DESKTOP-RA9DG2K)-[~/CS50]
└─$ python3 main.py
Response hex: 3c7d4ad2a111109d8ab0874c3e14d4326249821b3a73a9a4f2c4e2b87936094fce6b8cec59b95fac124fe82e66e434bd7dd6e9e18ef2fd6378548c116615f477
```

```bash
hacker@cryptography~rsa-4:~$ /challenge/run
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will complete an RSA challenge-response.
You will provide the public key.


e: 10001
n: 1b896d1bcf32298eb2ac3ebb0a1de29b5c3f1611196d282a2a3a29334651902149543e37c1defeb56c71b1aa53b24ee6042ccdfdbf882b383bf3525981406f6e7
challenge: 0x6e3e6009c3da988fcf2f1480494eb27902b391f4e8f6858fbce20e85bc89a37feba3b4245a279f35f0563adb26702497260e9559fa525658b1bf73b952f1b7d9
response: 3c7d4ad2a111109d8ab0874c3e14d4326249821b3a73a9a4f2c4e2b87936094fce6b8cec59b95fac124fe82e66e434bd7dd6e9e18ef2fd6378548c116615f477
secret ciphertext (b64): tcJuDHY8cQ8kBKdwfmwiZ6hc/OGXVp1vbzzYpyXmy+vcSethxXGSiJ55aq84Ir4RZp2WbhkN4OYHeeiOOCv4wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
```

```python
# Actually compute it
import base64
from Crypto.Util.number import bytes_to_long, long_to_bytes

e = 65537
n = 0x1b896d1bcf32298eb2ac3ebb0a1de29b5c3f1611196d282a2a3a29334651902149543e37c1defeb56c71b1aa53b24ee6042ccdfdbf882b383bf3525981406f6e7
ciphertext_b64 = "tcJuDHY8cQ8kBKdwfmwiZ6hc/OGXVp1vbzzYpyXmy+vcSethxXGSiJ55aq84Ir4RZp2WbhkN4OYHeeiOOCv4wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

ciphertext_bytes = base64.b64decode(ciphertext_b64)
ciphertext_int = int.from_bytes(ciphertext_bytes, 'little')

phi = n - 1
d = pow(e, -1, phi)

flag_int = pow(ciphertext_int, d, n)
flag_bytes = flag_int.to_bytes(256, 'little').rstrip(b'\x00')

print(f"Flag: {flag_bytes.decode()}")
```
## RSA Signature

So by using `d`, Alice can encrypt data that (because `n` and `e` are in the public key) anyone can decrypt... This might seem silly, but it actually enables a capability that we haven't yet seen in the module: the ability to attest to multiple people that a message came from Alice. This can serve as a sort of cryptographic version of a pen-and-ink signature and, in fact, it is called a _signature_!

This level will explore one application (and pitfall) of RSA signatures. Recall that `c == m**e mod n`, and recall from middle school that `(x**e)*(y**e) == (x*y)**e`. This holds just as well in `mod n`, and you can probably see the issue here...
#### Vuln

In RSA, if you have two signatures:

- `sig1 = m1^d mod n` (signature on message m1)
- `sig2 = m2^d mod n` (signature on message m2)

Then due to the multiplicative property:

```bash
sig1 * sig2 mod n = (m1^d mod n) * (m2^d mod n) mod n
                  = (m1 * m2)^d mod n
```

This means if you multiply two valid signatures, you get a valid signature for the product of their messages!

Let's say:

1. Alice signs message `m1` giving signature `s1 = m1^d mod n`
2. Alice signs message `m2` giving signature `s2 = m2^d mod n`
3. An attacker can compute `s3 = s1 * s2 mod n`
4. Now `s3` is a valid signature for message `m3 = m1 * m2 mod n`

This level gives you a signing oracle. Go use it to craft a flag command!
### Solution

```bash
hacker@cryptography~rsa-signatures:~$ /challenge/dispatcher 
Usage: /challenge/dispatcher [command-b64]
hacker@cryptography~rsa-signatures:~$ /challenge/worker 
Usage: /challenge/worker [signature-b64]
```

```bash
hacker@cryptography~rsa-signatures:~$ cat /challenge/dispatcher 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys

from base64 import b64encode, b64decode

n = int(open("/challenge/key-n").read(), 16)
d = int(open("/challenge/key-d").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [command-b64]")
    sys.exit(1)

command = b64decode(sys.argv[1].strip("\0"))

if b"flag" in command:
    print(f"Command contains 'flag'")
    sys.exit(1)

signature = pow(int.from_bytes(command, "little"), d, n).to_bytes(256, "little")
print(f"Signed command (b64): {b64encode(signature).decode()}")
hacker@cryptography~rsa-signatures:~$ cat /challenge/worker 
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys

from base64 import b64decode

n = int(open("/challenge/key-n").read(), 16)
e = int(open("/challenge/key-e").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [signature-b64]")
    sys.exit(1)

signature = b64decode(sys.argv[1])
c = int.from_bytes(signature, "little")
assert c < n, "Message too big!"
command = pow(c, e, n).to_bytes(256, "little").rstrip(b"\x00")

print(f"Received signed command: {command}")
if command == b"flag":
    print(open("/flag").read())
```

We need to find two messages `m1` and `m2` such that:

1. Neither contains "flag"
2. Their product `m1 * m2 mod n` equals the integer representation of `"flag"`
3. Both can be signed by the dispatcher

```bash
>>> int.from_bytes(b"flag", "little")
1734437990
```

```bash
>>> 1734437990 // 2
867218995
```

```bash
$ # 1. Get signature for m1=2
echo -ne '\x02\x00\x00\x00' | base64
AgAAAA==
```

```bash
$ /challenge/dispatcher AgAAAA==
Signed command (b64): IsmDqh8Deju6CWUJfaXBO0EkduxqDAmfXmUATv8Ole0DIlu+Jx/ydFd8QNRJqHpOc3FN7CiCIUF2n1AkaFeSj+P/8yLCGDi7VQGLqmDMs46ZFOtmRHBUIm0qwp2R195uV34VoXUDmOB8/pcCRBUVWOFwgsgQM+1/YXm4AWakSqkq6tgWy43mZh3BB1TD4IHj7r34ExoJHQbpdiKmAlI6kjOGZ9MX3OxbnNbVPgtebf85h656blWoJJJrPV16NGHutz1Ru4OqShjY/MmOtF/RetbG/5E9zv2xpOtyv6f5ib6xznxi+H7NX/0WTU/k+xG7teTOfE9oze0NIRuRIx651g==
```

```bash
>>> m2 = 867218995
>>> bytes_le = m2.to_bytes(256, 'little').rstrip(b'\x00')
>>> bytes_le.hex()
'33b6b033'
>>> bytes_le
b'3\xb6\xb03'
```

```bash
$ echo -ne '\x33\xb6\xb0\x33' | base64
M7awMw==
```

```bash
hacker@cryptography~rsa-signatures:~$ /challenge/dispatcher AgAAAA==
Signed command (b64): IsmDqh8Deju6CWUJfaXBO0EkduxqDAmfXmUATv8Ole0DIlu+Jx/ydFd8QNRJqHpOc3FN7CiCIUF2n1AkaFeSj+P/8yLCGDi7VQGLqmDMs46ZFOtmRHBUIm0qwp2R195uV34VoXUDmOB8/pcCRBUVWOFwgsgQM+1/YXm4AWakSqkq6tgWy43mZh3BB1TD4IHj7r34ExoJHQbpdiKmAlI6kjOGZ9MX3OxbnNbVPgtebf85h656blWoJJJrPV16NGHutz1Ru4OqShjY/MmOtF/RetbG/5E9zv2xpOtyv6f5ib6xznxi+H7NX/0WTU/k+xG7teTOfE9oze0NIRuRIx651g==
hacker@cryptography~rsa-signatures:~$ /challenge/dispatcher M7awMw==
Signed command (b64): fR5nD7edR9ET8xguLAyJMzlhCyEUA6NpZmDu66wL5L4Or6tZMyoDvyATGdZOK5653/raU1TX2WrM3V6/XGYyZB7IcCd1l4IAqNjRCRuAczzjfR0rmNnpW8R++E0jVEBAdv6KP9NrH92q5A7YaIXDfUOhquQWowHotNwHOpTZIgw3MaLDS9B2EknJ3q5Lv8mvJaTmCtfabmz7N3/wflbMtg9epcTeOwKMxx2AZ8NU+0lFwhQqruxS3i87ctJZU0P3EcF3fwfR6wBgAyCLXCRl2xKbiOsOhA9ujAJehVNMiwRC5qiYaXWg6M9vdZcOMrBFdDIZB2u1iizVRvmWRC/ePA==
```

```python
import base64
import subprocess

# Get n from file
with open("/challenge/key-n") as f:
    n = int(f.read(), 16)

# The two signatures we got
sig1_b64 = "IsmDqh8Deju6CWUJfaXBO0EkduxqDAmfXmUATv8Ole0DIlu+Jx/ydFd8QNRJqHpOc3FN7CiCIUF2n1AkaFeSj+P/8yLCGDi7VQGLqmDMs46ZFOtmRHBUIm0qwp2R195uV34VoXUDmOB8/pcCRBUVWOFwgsgQM+1/YXm4AWakSqkq6tgWy43mZh3BB1TD4IHj7r34ExoJHQbpdiKmAlI6kjOGZ9MX3OxbnNbVPgtebf85h656blWoJJJrPV16NGHutz1Ru4OqShjY/MmOtF/RetbG/5E9zv2xpOtyv6f5ib6xznxi+H7NX/0WTU/k+xG7teTOfE9oze0NIRuRIx651g=="
sig2_b64 = "fR5nD7edR9ET8xguLAyJMzlhCyEUA6NpZmDu66wL5L4Or6tZMyoDvyATGdZOK5653/raU1TX2WrM3V6/XGYyZB7IcCd1l4IAqNjRCRuAczzjfR0rmNnpW8R++E0jVEBAdv6KP9NrH92q5A7YaIXDfUOhquQWowHotNwHOpTZIgw3MaLDS9B2EknJ3q5Lv8mvJaTmCtfabmz7N3/wflbMtg9epcTeOwKMxx2AZ8NU+0lFwhQqruxS3i87ctJZU0P3EcF3fwfR6wBgAyCLXCRl2xKbiOsOhA9ujAJehVNMiwRC5qiYaXWg6M9vdZcOMrBFdDIZB2u1iizVRvmWRC/ePA=="

# Decode signatures
sig1_bytes = base64.b64decode(sig1_b64)
sig2_bytes = base64.b64decode(sig2_b64)

sig1 = int.from_bytes(sig1_bytes, "little")
sig2 = int.from_bytes(sig2_bytes, "little")

print(f"sig1 integer: {sig1}")
print(f"sig2 integer: {sig2}")
print(f"n: {n}")

# Multiply signatures mod n to get signature for "flag"
sig3 = (sig1 * sig2) % n
print(f"\nForged signature integer: {sig3}")

# Convert to bytes and base64
sig3_bytes = sig3.to_bytes(256, "little")
sig3_b64 = base64.b64encode(sig3_bytes).decode()
print(f"\nForged signature (b64): {sig3_b64}")

# Send to worker
print("\nSending to worker...")
result = subprocess.run(["/challenge/worker", sig3_b64], 
                       capture_output=True, text=True)
print(f"Worker output:\n{result.stdout}")
```
# Cryptographic Hashes
## SHA 1

As you saw, raw RSA signatures are a bad idea, as they can be forged. In practice, what people sign are [_cryptographic hashes_](https://en.wikipedia.org/wiki/Cryptographic_hash_function) of things. A hash is a one-way function that takes an arbitrary amount of input (e.g., bytes or gigabytes or more) and outputs a short (e.g., 32 bytes) of output hash. Any changes in the input to the hash will _diffuse_ all over the resulting cryptographic hash in a way that is not reversible.

Thus, secure hashes are a good representation for the original data: if Alice signs a hash of a message, that message can be seen as being signed as well. Better yet, since hashes are not controllably reversible or modifiable, an attacker being able to modify a hash does not allow them to forge a signature on a new message.

The bane of cryptographic hashing algorithms is _collision_. If an attacker can craft two messages that hash to the same thing, the security of any system that depends on the hash (such as the RSA signature scheme described above) might be compromised. For example, consider that the security of bitcoin depends fully on the collision resistance of SHA256...

While full collisions of SHA256 don't exist, some applications use _partial_ hash verification. This is not a great practice, as it makes it easier to brute-force a collision.

Read [paper](https://helix.stormhub.org/papers/SHA-256.pdf) for working.

SHA-256 is part of the **SHA-2 family** and produces a **256-bit (32-byte) hash**. It's widely used in security applications today (SSL/TLS, Bitcoin, etc.).

In this challenge you will do just that, hashing data with a Secure Hash Algorithm (SHA256). You will find a small hash collision. Your goal is to find data, which when hashed, has the same hash as the secret. Only the first 3 bytes of the SHA256 hash will be checked.
### Solution

```bash
hacker@cryptography~sha-1:~$ cat /challenge/run
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import hashlib


flag = open("/flag").read()
prefix_length = 6
flag_hash = hashlib.sha256(flag.encode("latin")).hexdigest()
print(f"{flag_hash[:prefix_length]=}")

collision = bytes.fromhex(input("Colliding input? ").strip())
collision_hash = hashlib.sha256(collision).hexdigest()
print(f"{collision_hash[:prefix_length]=}")
if collision_hash[:prefix_length] == flag_hash[:prefix_length]:
    print("Collided!")
    print(flag)
```

We have a SHA-256 challenge where:

- The flag is hashed with SHA-256
- We only get the **first 6 hex characters** (3 bytes, 24 bits) of the hash
- We need to provide **any input** that produces a SHA-256 hash with the same first 6 hex characters
- If we succeed, we get the flag

This is a **partial hash collision** problem. We need to find any message that collides on the first 24 bits (6 hex characters) of SHA-256.

The **birthday paradox** tells us that for an n-bit hash:

- We need about 2^(n/2) attempts to find a collision for the full hash
- For **partial collisions** (first k bits), we need about 2^(k/2) attempts

Here k = 24 bits, so we need about 2^12 = 4,096 attempts on average.

```bash
hacker@cryptography~sha-1:~$ /challenge/run
flag_hash[:prefix_length]='b5d723'
Colliding input? 
```

```python
import itertools

from pwn import *

def find_colliding(flag_hash):
    for k in range (10):
        for bf_data in itertools.combinations([i for i in range(1,255)], k):
            bf_data_hash = hashlib.sha256(bytes(bf_data)).hexdigest()
            if flag_hash == bf_data_hash[:len(flag_hash)]:
                return bytes(bf_data)

    return None

io = process(['/challenge/run'])

flag_hash = io.recvregex(br'flag_hash.*=\'(.+)\'\n', capture=True).group(1).decode()

colliding_data = find_colliding(flag_hash)

io.readn(len('Colliding input? '))
io.sendline(colliding_data.hex().encode())

flag = io.recvregex(br'Collided.+\n(.+)\n', capture=True).group(1).decode()
print(flag)
```
## SHA 2

In this challenge you will hash data with a Secure Hash Algorithm (SHA256). You will compute a small proof-of-work. Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.
### Solution

```bash
hacker@cryptography~sha-2:~$ /challenge/run 
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will compute a small proof-of-work.
Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


challenge (b64): /5kQUKmNrqkCtz5J9V1P6BES37Yugjb7u5wPh1iOVP4=
response (b64): 
```

We need to find `response` bytes such that:

`SHA256(challenge∥response)` starts with `0x0000`

That means the first two bytes of the hash must be `00 00`.

```bash
$ echo "/5kQUKmNrqkCtz5J9V1P6BES37Yugjb7u5wPh1iOVP4=" | base64 -d | xxd
00000000: ff99 1050 a98d aea9 02b7 3e49 f55d 4fe8  ...P......>I.]O.
00000010: 1112 dfb6 2e82 36fb bb9c 0f87 588e 54fe  ......6.....X.T.
```

So `challenge_bytes =`  
`ff991050a98daea902b73e49f55d4fe81112dfb62e8236fbbb9c0f87588e54fe`

Let `R` be the **response** bytes (variable length, we choose).  
We want:

First two bytes zero → first 4 hex chars zero.

We can try random or incremental `R` until condition satisfied.  
We need output like:  
`0000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

```python
import base64
import hashlib

challenge_b64 = "/5kQUKmNrqkCtz5J9V1P6BES37Yugjb7u5wPh1iOVP4="
challenge_bytes = base64.b64decode(challenge_b64)

# Try 4-byte responses starting from 0
import struct

for i in range(0, 1000000):  # Try first million possibilities
    resp = struct.pack("<I", i)  # 4 bytes, little-endian
    data = challenge_bytes + resp
    h = hashlib.sha256(data).hexdigest()
    if h.startswith("0000"):
        print(f"Found at i={i}")
        print(f"Response bytes (hex): {resp.hex()}")
        print(f"Response b64: {base64.b64encode(resp).decode()}")
        print(f"Hash: {h}")
        break
```

```bash
$ python3 main.py                                                     Found at i=108324
Response bytes (hex): 24a70100
Response b64: JKcBAA==
Hash: 00003dec5b33ce2a9f113d8441d3318f7e3fd6510d30261505cd264f0303c686
```

We solved it by **brute force** trying many responses until we got lucky!

```bash
hacker@cryptography~sha-2:~$ /challenge/run 
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will compute a small proof-of-work.
Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


challenge (b64): /5kQUKmNrqkCtz5J9V1P6BES37Yugjb7u5wPh1iOVP4=
response (b64): JKcBAA==
flag: pwn.college{k3pRiG-Ewla4qSkRXHoEwIqlRwh.QXygzMzwCNxgjN0EzW}
```
# Trust
## TLS 1

In this challenge you will work with public key certificates. You will be provided with a self-signed root certificate. You will also be provided with the root private key, and must use that to sign a user certificate.
### Solution

```bash
hacker@cryptography~tls-1:~$ /challenge/run
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will work with public key certificates.
You will be provided with a self-signed root certificate.
You will also be provided with the root private key, and must use that to sign a user certificate.


root key d: 0xac4364524f2ef580d2cb4d599e4758b04fcf19d390fe5176bc1236ffbecc541e734f52ebffb2df6a58e1ae6edd0e53a69421d227d48eed73eb6325a07bc10530b0d60131809c022effc6406bbfbbc9d983f6dbad9863ca8537e925b06acd5f1e7e09e44df46dc147d2aacaf84ac4419b8325dee92e7e75fa0629c4ba4d4fdcbf8f1d394832968a71f8e0b6189000d10e1e32eca3546155d27d0de481c5fc76ddc99e3e604da068428f5656424280748809ad79b6678f25ef174b9485a5e52fdef60b071592ac37ca5710f429ee75370d6c67c0c6567a0b60f02274fbc663f92b1a14a597bc0b3126a65871159b01c32cd754ed31c24282ca98b2c2ed44ba671
root certificate (b64): eyJuYW1lIjogInJvb3QiLCAia2V5IjogeyJlIjogNjU1MzcsICJuIjogMjk1NTY2NDYwMDI0NzY5ODUzNTEyMDkxOTA5ODA1NTU1NzQ2NDkwNTQ1OTUwMDg4NjI0Njc1MTM1MTUyMTI4NDMzODgxMjQ5NDM0NTU1MzIzOTk2ODI3NDcyNzE3NzE1MDc2OTMyMjEyODQxNzI2ODk5MjY4NzA2ODg4NTEwMTE3NTQwMDQ4NDA0NTU0NTg2ODA2NjA0OTU5OTMxNjU0MjM0Njg4MzkxODEzMDI3Nzc1OTY1Mzg1NjgxMzY1NDU3MjQ3NzIzNjYxMTU5MTYzMjM4NDAzMjc3NzMzNzUyMDM5NjA1MTYwNDIwOTcxNDQwMjMwODUxMzk0MTE2OTU3NjA1Njc0MTkxMjQ5MjQ0NzMwODc5NzUyNTM2ODE5ODcyNjIwODAyODAyODYwNzk4Njc5MTA5OTU1OTE0NDU1OTQ1NDc3MDMzODc5NjYyNzIzNDEwNTQ4NzYwNTY5MzY1NTgwMDIwODQ1Nzg1NTk5NjQ3MTU2NzM1NDEzMzE3NjY0MDQyMjU2NjAxNjcwNTc4NTc5NzIzODcwMDE3MDA4Mzc1Nzc0NjIzNTc2NzAyNjcwMDM2OTMxODU2MDIzNTI3NzE4NjA5OTE2OTI5NzcwNDMwNTg0MTgwNzUwMDA4MDYyNjY0MTM4Mzc3MTI3ODY5ODcxNzQyMjQ1ODkwNDMwNjQ3OTQ0NDMwNzQwMzQ0NTExNTA0ODE1MjU3NzYxNjk3NDM1NjY3MDY0MzA5MTYwOTM2MjcwMTI0MTcyMzQ3NDc3MTAyNzk4MTEwNDU4OTk2NDU3Mjc4MTMzNzg4MDEyOTU5NTQwMTA0NzN9LCAic2lnbmVyIjogInJvb3QifQ==
root certificate signature (b64): rHrLhML0AVhHuPQJs/cn/kGu/82jYVELscfHZJl5BGc0LChO0BmH6+fmbdJYoCf2WeGFJrHO92ebJj9IaFywJNVE9XJtygqb4m+UmHSNF3JYOJs7EibzvCDpGRGxckBQffMZCk3uJn8uTu7DfWgcSQoWkzC2prQOLEWFoGEoVfbHGfkkmCl6R507j69mqO3yFupM17UYBZFuR2AsZoQcIaMATS+ho45J98FohQB8ZiJqS+i6u9sF7pVRWhToKvt9ovdwQEUWTf6aiTIqxiaedo0FDEKReQ8R+QbUVX6XgVmz3rOF+WdVyaF1Hokf+jiX4yirUkzwhgRrPGzVRSdhbw==
user certificate (b64): 
```

You're acting as a **Certificate Authority (CA)** that needs to sign a user certificate. Here's how it works:

```bash
Root CA (You)
    ├── Has its own self-signed certificate
    ├── Has private key (d)
    └── Signs → User Certificate
```
##### How Certificate Signing Works

User provides:

```json
{
  "name": "user",
  "key": {
    "e": 65537,      # User's RSA public exponent
    "n": 123456...   # User's RSA modulus
  },
  "signer": "root"   # Who should sign this
}
```

(This gets base64-encoded)

CA checks:

- Checks user's identity (in real world)
- Decides if user is trustworthy

**Process:**

1. **Take certificate data** (JSON string)
2. **Hash it** using SHA256
3. **Encrypt hash** with CA's private key

```bash
signature = RSA_Private_Encrypt(SHA256(certificate_data))
```

User gets:

- Certificate data (unchanged)
- Signature (base64-encoded)
##### Verification Process (How clients check):

```bash
# Client receives user certificate + signature
# They have root CA's public key (from root certificate)

# Step 1: Extract signature
signature = base64decode(received_signature)

# Step 2: Decrypt signature using root CA's PUBLIC key
decrypted_hash = RSA_Public_Decrypt(signature, root_public_key)

# Step 3: Hash the certificate data
computed_hash = SHA256(certificate_data)

# Step 4: Compare
if decrypted_hash == computed_hash:
    # Valid! Root CA really signed this
    # Trust the user certificate
```

```python
import json

from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Hash.SHA256 import SHA256Hash
from base64 import b64decode, b64encode

io = process(['/challenge/run'])

d_hex = io.recvregex(br'root key d: (.+)\n', capture=True).group(1).decode()
cert_b64 = io.recvregex(br'root certificate \(b64\): (.+)\n', capture=True).group(1).decode()
cert_signature_b64 = io.recvregex(br'root certificate signature \(b64\): (.+)\n', capture=True).group(1).decode()

root_d = int(d_hex, 16)
root_cert = json.loads(b64decode(cert_b64))
root_cert_signature = b64decode(cert_signature_b64)

user_key = RSA.generate(1024)

user_certificate = {
    "name": "user",
    "key": {
        "e": user_key.e,
        "n": user_key.n,
    },
    "signer": root_cert["signer"],
}

user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"),
    root_d,
    int(root_cert["key"]["n"])
).to_bytes(256, "little")

user_cert_b64 = b64encode(user_certificate_data)
user_sign_b64 = b64encode(user_certificate_signature)

io.readn(len('user certificate (b64): '))
io.sendline(user_cert_b64)

io.readn(len('user certificate signature (b64): '))
io.sendline(user_sign_b64)

ciphertext = io.recvregex(br'.+ ciphertext.*: (.+)\n', capture=True).group(1).decode()
ciphertext = b64decode(ciphertext)

flag = pow(int.from_bytes(ciphertext, "little"), user_key.d, user_key.n).to_bytes(256, "little")
print(flag.decode().rstrip('\0'))
```
## TLS 2

In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server. You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key. The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange. The server must complete the key exchange, and derive an AES-128 key from the exchanged secret. Then, using the encrypted channel, the server must supply the requested user certificate, signed by root. Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.
### Solution

```bash
hacker@cryptography~tls-2:~$ /challenge/run
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will perform a simplified Transport Layer Security (TLS) handshake, acting as the server.
You will be provided with Diffie-Hellman parameters, a self-signed root certificate, and the root private key.
The client will request to establish a secure channel with a particular name, and initiate a Diffie-Hellman key exchange.
The server must complete the key exchange, and derive an AES-128 key from the exchanged secret.
Then, using the encrypted channel, the server must supply the requested user certificate, signed by root.
Finally, using the encrypted channel, the server must sign the handshake to prove ownership of the private user key.


p: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g: 0x2
root key d: 0x2ec672ecf84365c8054a732377c68fc1615c189906d4cd0c564bc0511666e8c61ff986818a4cd9e6a017af347863586edaca242dbd482b2b410ec1a1c8508f8965da085e0975a407e43456e2bf55ef2ce7efdf208b02f29976bab152c4317998edc1fa87fe8a65ba0e751956e2acd70aa45b5a962a4648301366ce8b8eb080545a39475f586f543919af01c779bab2b9d181e4ba6490d253e1106cd13edc80a27e09f9c5927fead2f960210c54f4fea15952665efcc0163a842c3f32b1e748c453708ec586fd64cca4fefd28604fd781ce506ced5097282640e6c70b7a6087247e14882c39a46bcf082d03b24e2f3517193c7d33f398598a50edf672845747d
root certificate (b64): eyJuYW1lIjogInJvb3QiLCAia2V5IjogeyJlIjogNjU1MzcsICJuIjogMzA2Mzg0NjUzOTE2MTA4NDIyMjkwODkzNTEwODY1NzQ1MDk5ODIyNDI0NzQ0NTQ4OTAxNTE3Nzg1NjA2MTIyNDMwOTE3OTkxNjgzMjc4Mjc3ODI0OTM5MjE5NDk2NTg0MTE3OTY5NzAxMjA4NjU3NTk3MTc3NTAxMjgyNTQ2MDcyODgwODkyNjEwODEwNDM2Njk2NTA2MzgyMTU2NzEyMzIyNTQzMDM1NzM0NzgxNzU1MTM0ODAxOTQ0NjAyNzg0NTAyNjI3OTA3NTU3NDExMDk4NDQ3MzMxMzM2MzUwNTQxMTA5NjUyMTk3MDIxMDE1NDU3NTcyNDUxNDY0Mzk2MTU0Mjk2MDE2MTE0Mzc4MDU0NDM0OTQ1OTQ0ODQ0ODk3NzA5OTc3ODgzNTM0ODU3NTIwNTE3MDM0OTI4MTQ1MjEwMTA0NjU1MjQ0MTgwMjI4MzYzNjc0OTc3ODEyMTU3ODA5MDQwNzIzMDIxNzU3NjEwMzI1Mjk1NjQ1MDYwMzU3NzI5Mzc2MjA2MzM2NjE5NTIwMjg5NDI4Mzc5MzMxMjgyNTg3MDcxOTE2ODgxMDMxNTMzNTA5MDIwNzY3MDk2ODIxODEwODgzMzg1MTM2MzkyNzA0MzAxMTI0MjYwMzg0NjYxMTM2NTI1NzgzNjMwNzM3MjE0OTE4MTQ4MTI2MzM5Nzg4NDc5ODE3Nzk0MzI0MDkxODc1ODk3NjI5NTIxNTQyOTMxOTg0ODgyNTkwMjAwMTAzMDc5ODg2Mzc4NDMwMjg0Mzg4MjA4ODExOTExMTg5NzM2ODg2NTkzNDU0MDM3NTA5MjMwODF9LCAic2lnbmVyIjogInJvb3QifQ==
root certificate signature (b64): kc04zmLgYLYD/Az7r0hKMJcEqu3OInoBW/hNErfE84FWKHNdhHcHtzJl1JL2yDDmhy0pTDnlwISmcscgoJ5Gveyc57egzLOlnq629yTbmmKEJ0F87L6lswEJ3e1tyc/Gl26hukc2nI/WUEwJIyzycqYCcPRD5P3ssRMzLDphzi72ZSrnbS7KkiRfRLA9mKTVbQbDfIeruswxqWTa+saKtOeHLXgxUlU27DgXc8PK0qMZB7YWfWKb9UeYZ9xyOdu3K3aBzvvioNMPT4oH01vO2uNAtO5tZvNDWkxI1nr7nM3hTYGFfy6j1m4QhrhttsZDy7HMMkjK/eshigxevcXjGQ==
name: zpipcbnmekzpuoth
A: 0xcb0bea5abe646c8cfbe25ed57db92d21d6c3d1c59d98c8f43809cae711a732bf0af6f93f1dc485d4bc2b4fdfd038f22af4b26d21eb90025fcda4b18dc7617a80f924b13552266733cecb9b3298707528334ca8def3343918082a80243cc6cfd0a9815a9dc26954feb6ad6b80a9d85a96b2303840f43ce966a20a6d0c1e93123f9468280443a78086f42cc941c0ec358c8f6f9e63cec5514e96e3a7994a69dc91a4301cf817685d33511db333ad9ff71116753ea99a32e693a64d0c92cbb2ef75d566f90184d5234846aad0fa117f02d57e0671a061147a40437fae26e5983caec1742765e17337fee77ee1d0bea0a2c52b9019e0bf6b145dd30741108241633f
B: 
```
#### TLS 1.3 Handshake

```bash
Client                              Server
------                              ------
ClientHello         ----------->
(random, cipher_suites, SNI)
                    
                    <-----------   ServerHello
                                    (random, cipher_suite)
                    <-----------   Certificate
                                    (signed by CA)
                    <-----------   CertificateVerify
                                    (signs handshake transcript)
                    <-----------   ServerFinished
                    
KeyExchange         ----------->
(DH public value)
                    
Certificate         ----------->
(optional client auth)
                    
CertificateVerify   ----------->
(signs transcript)
                    
ClientFinished      ----------->
```

```python
import json
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import random
import base64

def encrypt_input(cipher, data):
    """Encrypt data with AES in CBC mode"""
    return cipher.encrypt(pad(data, cipher.block_size))

# Start the challenge process
io = process(['/challenge/run'])

# --- PHASE 1: Extract all given parameters from the challenge ---
p_hex = io.recvregex(br'p: (.+)\n', capture=True).group(1).decode()
g_hex = io.recvregex(br'g: (.+)\n', capture=True).group(1).decode()

d_hex = io.recvregex(br'root key d: (.+)\n', capture=True).group(1).decode()
cert_b64 = io.recvregex(br'root certificate \(b64\): (.+)\n', capture=True).group(1).decode()
cert_signature_b64 = io.recvregex(br'root certificate signature \(b64\): (.+)\n', capture=True).group(1).decode()

name = io.recvregex(br'name: (.+)\n', capture=True).group(1).decode()
A_hex = io.recvregex(br'A: (.+)\n', capture=True).group(1).decode()

# Convert hex strings to integers
p = int(p_hex, 16)  # DH prime modulus
g = int(g_hex, 16)  # DH generator
A = int(A_hex, 16)  # Client's DH public value

# Root CA private key and certificate
root_d = int(d_hex, 16)  # Root's RSA private exponent
root_cert = json.loads(b64decode(cert_b64))  # Decode root certificate
root_cert_signature = b64decode(cert_signature_b64)

# --- PHASE 2: Complete Diffie-Hellman Key Exchange ---
# Generate server's private DH key
b = random.getrandbits(1024)  # Server's private exponent
B = pow(g, b, p)  # Server's public value: g^b mod p
s = pow(A, b, p)  # Shared secret: A^b mod p = (g^a)^b = g^(ab)

# Send server's public value B to client
io.readn(len('B: '))
io.sendline(hex(B).encode())

# --- PHASE 3: Derive AES Key from Shared Secret ---
# Use SHA256 of shared secret, take first 16 bytes for AES-128
key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]

# Create AES cipher objects for encryption/decryption
# Using zero IV (simplified - real TLS would use proper IV management)
cipher_encrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)

# --- PHASE 4: Create User Certificate ---
# Generate RSA key pair for the requested user
user_key = RSA.generate(1024)

# Create user certificate data structure
user_certificate = {
    "name": name,  # The requested name "zpipcbnmekzpuoth"
    "key": {
        "e": user_key.e,  # User's RSA public exponent
        "n": user_key.n,  # User's RSA modulus
    },
    "signer": root_cert["signer"],  # Signed by root CA
}

# Sign the user certificate with root's private key
user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()

# RSA signature: hash^d mod n (encrypt with private key)
user_certificate_signature = pow(
    int.from_bytes(user_certificate_hash, "little"),  # Hash as integer
    root_d,  # Root's private exponent
    int(root_cert["key"]["n"])  # Root's modulus
).to_bytes(256, "little")

# Encrypt and encode user certificate and signature
user_cert_b64 = base64.b64encode(encrypt_input(cipher_encrypt, user_certificate_data))
user_sign_b64 = base64.b64encode(encrypt_input(cipher_encrypt, user_certificate_signature))

# --- PHASE 5: Prove Ownership of User Private Key ---
# Create handshake data to sign (name + A + B)
user_signature_data = (
    name.encode().ljust(256, b"\0") +  # Name padded to 256 bytes
    A.to_bytes(256, "little") +       # Client's DH public value
    B.to_bytes(256, "little")         # Server's DH public value
)

# Hash the handshake data
usd_data_hash = SHA256Hash(user_signature_data).digest()

# Sign with user's private key to prove ownership
usd_signature = pow(
    int.from_bytes(usd_data_hash, "little"),  # Hash as integer
    user_key.d,  # User's private exponent
    user_key.n   # User's modulus
).to_bytes(256, "little")

# Encrypt and encode the signature
usd_signature_b64 = base64.b64encode(encrypt_input(cipher_encrypt, usd_signature))

# --- PHASE 6: Send All Responses to Challenge ---
# Send encrypted user certificate
io.readn(len('user certificate (b64): '))
io.sendline(user_cert_b64)

# Send encrypted certificate signature
io.readn(len('user certificate signature (b64): '))
io.sendline(user_sign_b64)

# Send encrypted handshake signature
io.readn(len('user signature (b64): '))
io.sendline(usd_signature_b64)

# --- PHASE 7: Receive and Decrypt Flag ---
# Challenge sends back encrypted flag
ciphertext = io.recvregex(br'.+ ciphertext.*: (.+)\n', capture=True).group(1).decode()
ciphertext = b64decode(ciphertext)

# Decrypt flag using the shared AES key
flag = unpad(cipher_decrypt.decrypt(ciphertext), cipher_decrypt.block_size)
print(flag.decode())
```

---
