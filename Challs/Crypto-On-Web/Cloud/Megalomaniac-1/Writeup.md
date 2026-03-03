# CryptoHack Megalomaniac-1 

## Challenge Summary

We are given a server-side simulation of MEGA-style login crypto. The goal is to recover the user's **ShareKey** (RSA private material) and then decrypt the encrypted flag.

Service:
- `socket.cryptohack.org 13408`

Given file:
- `13408.py`

Flag format:
- `crypto{...}`


## 1. RecFuckingOn

### 1.1 What gets published at registration

On startup, the service instantiates `Client(PASS, SALT)` and prints this JSON:

- `auth_key_hashed`
- `master_key_enc`
- `share_key_pub = (n, e)`
- `share_key_enc`

From code:

- `enc_key = PBKDF2(password, salt, ... )[:16]`
- `master_key` is random 16 bytes
- `master_key_enc = AES-ECB(enc_key).encrypt(master_key)`
- `share_key_enc = AES-ECB(master_key).encrypt(format_rsa_privkey())`

So the RSA private key is wrapped under `master_key`, which is wrapped under `enc_key`.

### 1.2 Login flow and attacker control

Relevant endpoint logic:

- `wait_login`: creates a fresh `Client_new_login(PASS, SALT)`
- `send_challenge`: user supplies
  - `SID_enc`
  - `share_key_enc`
  - `master_key_enc`

The server then does:

1. `master_key = AES-ECB(enc_key).decrypt(master_key_enc)`
2. `share_key = unpad(AES-ECB(master_key).decrypt(share_key_enc))`
3. parse `(p, q, d, u)` from `share_key`
4. compute `SID = RSA_CRT_decrypt(SID_enc, p, q, d, u)`
5. **truncate**: `SID = SID[:-16]`
6. return `SID.hex()`

Critical issue: we can submit arbitrary encrypted key material into a decryption path and get output back.

### 1.3 Flag encryption

Flag is encrypted as:

- `secret = SHA256(long_to_bytes(p) + long_to_bytes(q)).digest()`
- `flag_ct = AES-ECB(secret).encrypt(pad(FLAG,16))`

Therefore, recovering `(p, q)` is enough to decrypt the flag.

---

## 2. Cryptographic Weakness 

The attack combines:

- ECB malleability on `share_key_enc`
- CRT-RSA recombination sensitivity to `u`
- leakage of almost full decrypted plaintext (`SID[:-16]`)
- small-root recovery (Coppersmith) on a linear modular equation

### 2.1 Why ECB matters here

`share_key_enc` is AES-ECB under unknown `master_key`.

Even without the key, ECB lets us flip bits in any ciphertext block, which flips the corresponding plaintext block after decryption in a predictable XOR way.

Because `format_rsa_privkey()` packs `p || q || d || u`, and the payload is long (~640 bytes padded), later blocks belong to `u`.

So we can inject a fault into `u` **without changing p/q/d** by flipping a byte in a late block (block index `39` worked reliably in this instance).

### 2.2 Faulted CRT decrypt relation

Server decrypt uses:

- `dp = d mod (p-1)`
- `dq = d mod (q-1)`
- `mp = c^dp mod p`
- `mq = c^dq mod q`
- `t = (mq - mp) mod q`
- `h = (t * u) mod q`
- `s = h*p + mp`

With correct `u = p^{-1} mod q`, `s = m`.

With faulted `u'`, output `s'` still satisfies:

- `s' ≡ mp (mod p)`
- and for RSA ciphertext `c = m^e mod n`, `mp ≡ m (mod p)`
- hence `(s' - m) ≡ 0 (mod p)`

So:

- `p | (s' - m)`
- but generally `q ∤ (s' - m)`

If we had full `s'`, we could do `gcd(s' - m, n)` directly.

### 2.3 Why truncation still leaks enough

Server returns `SID = long_to_bytes(s')[:-16]`.

Interpret this as revealing the high part:

- `s' = (S_hi << 128) + x`
- unknown `x` is the last 128 bits (`0 <= x < 2^128`)
- we know `S_hi` from returned `SID`

Then:

- `s' - m = (S_hi << 128) - m + x`
- define `A = (S_hi << 128) - m`
- then `A + x ≡ 0 (mod p)`

So `x` is a small root of:

- `f(X) = X + A (mod p)`

We do not know `p`, but we know `n = p*q`, so we solve over `Z_n` using Coppersmith small roots for bounded `x < 2^128`.

Once candidate `x` is found:

- `g = gcd(A + x, n)` gives a non-trivial factor (`p` or `q`).

---

## 3. Exploit Plan

1. Connect and parse registration JSON.
2. Read `n,e`, `master_key_enc`, `share_key_enc`.
3. Query `get_encrypted_flag`.
4. Choose random large plaintext integer `m` in `[1, n-1]`.
5. Compute `c = m^e mod n`.
6. Fault `share_key_enc` by flipping one byte in block 39 (inside `u`).
7. Call `wait_login`, then `send_challenge` with:
   - `SID_enc = c`
   - original `master_key_enc`
   - faulted `share_key_enc`
8. Parse returned truncated `SID` high bits -> `S_hi`.
9. Build `A = (S_hi << 128) - m`.
10. Solve `x` via Coppersmith (`X < 2^128`) on linear polynomial over `Z_n`.
11. Compute `p = gcd(A + x, n)`, `q = n/p`.
12. Derive AES key from `SHA256(long_to_bytes(p)+long_to_bytes(q))` (try both orders).
13. Decrypt flag ciphertext and unpad.

---
