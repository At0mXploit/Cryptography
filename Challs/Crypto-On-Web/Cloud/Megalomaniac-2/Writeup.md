# CryptoHack Megalomaniac-2 
## Challenge Context

This is the sequel to Megalomaniac-1 with the same cryptographic structure, but now the server limits the number of login attempts:

- `remaining_logins = 4`
- each `wait_login` consumes one attempt

Goal remains the same: recover enough of Alice's ShareKey-derived secret to decrypt the flag.

Service:
- `socket.cryptohack.org 13409`

Given source:
- `13409.py`

## 1. Source Analysis

## 1.1 Registration output

On new challenge instance, server prints:

- `auth_key_hashed`
- `master_key_enc`
- `share_key_pub = (n, e)`
- `share_key_enc`

Internals:

1. `enc_key, auth_key` from `PBKDF2(password, salt, 32, SHA512)`
2. random 16-byte `master_key`
3. random RSA 2048 key (`p, q, d, u`)
4. `master_key_enc = AES-ECB(enc_key).encrypt(master_key)`
5. `share_key_enc = AES-ECB(master_key).encrypt(format_rsa_privkey())`

`format_rsa_privkey()` serializes:

- `len(p)||p||len(q)||q||len(d)||d||len(u)||u`, padded to block size.

## 1.2 Login endpoint (decryption oracle)

At `send_challenge`, server accepts attacker-provided:

- `SID_enc`
- `share_key_enc`
- `master_key_enc`

Then computes:

1. `master_key = Dec_enc(master_key_enc)`
2. `share_key = Unpad(Dec_master(share_key_enc))`
3. parse `p,q,d,u`
4. `SID = RSA_CRT_decrypt(SID_enc, p,q,d,u)`
5. returns `SID[:-16]` (last 16 bytes removed)

So attacker fully controls inputs to private-key operation and gets almost full plaintext output.

## 1.3 Flag encryption

Flag key is:

- `K = SHA256(long_to_bytes(p) || long_to_bytes(q))`

Flag ciphertext:

- `Cflag = AES-ECB(K).encrypt(pad(FLAG,16))`

Hence recovering `(p,q)` is sufficient.

---

## 2. Vulnerability Chain

The exploit uses four facts:

1. **AES-ECB malleability** on `share_key_enc` allows block-local plaintext corruption after decryption.
2. We can target the serialized RSA private key field `u` while leaving `p,q,d` intact.
3. Faulted `u` breaks CRT recombination in a way that keeps a congruence modulo one prime.
4. Returned plaintext is truncated by only 128 bits, so unknown part is a small integer recoverable by Coppersmith-style small roots.

The 4-login limit is irrelevant because a single successful oracle query is enough.

---

## 3. Math Derivation

## 3.1 CRT recombination used by server

Server computes for ciphertext integer `c`:

- `dp = d mod (p-1)`
- `dq = d mod (q-1)`
- `mp = c^dp mod p`
- `mq = c^dq mod q`
- `t = (mq - mp) mod q`
- `h = (t * u) mod q`
- `s = h*p + mp`

When `u = p^{-1} mod q`, this reconstructs RSA plaintext `m` exactly.

If we fault `u -> u'`, then reconstructed value becomes `s'`.

## 3.2 Invariant under faulty `u`

Regardless of `u'`, formula still has:

- `s' = h*p + mp`
- therefore `s' ≡ mp (mod p)`

For RSA-consistent ciphertext `c = m^e mod n`:

- `mp = c^dp mod p ≡ m (mod p)`

So:

- `s' ≡ m (mod p)`
- equivalently `p | (s' - m)`

Normally this would give factor directly:

- `gcd(s' - m, n) = p`

But service removes the last 16 bytes.

## 3.3 Truncation model

Server returns `SID = long_to_bytes(s')[:-16]`.

Let returned integer be `S_hi`, then:

- `s' = (S_hi << 128) + x`
- unknown `x` satisfies `0 <= x < 2^128`

Define:

- `A = (S_hi << 128) - m`

Then:

- `s' - m = A + x`
- and since `p | (s' - m)`, we get
- `A + x ≡ 0 (mod p)`

So `x` is a small root of:

- `f(X) = X + A` modulo unknown prime factor `p` of `n`.

## 3.4 Recovering small root modulo factor of `n`

We know only `n = p*q`. Standard small-root approach over `Z_n` can still recover `x` (when bound is sufficiently small), then:

- compute `g = gcd(A + x, n)`
- obtain nontrivial factor `g = p` (or `q`)

In code (Sage):

- polynomial ring `R = Zmod(n)[x]`
- `f = x + (A mod n)`
- `roots = f.small_roots(X=2^128, beta≈0.49)`

For candidate root `r`, test:

- `g = gcd(A + r, n)`
- valid if `1 < g < n`

Then `q = n // p`.

---

## 4. Why One Query Is Enough

We need exactly one login oracle call (`wait_login` + `send_challenge`) because:

1. We already get `n,e,share_key_enc,master_key_enc` at registration.
2. We can choose any RSA plaintext `m` and compute `c = m^e mod n` ourselves.
3. One faulted decrypt output gives `S_hi`.
4. `S_hi` + known `m` uniquely forms the small-root equation.
5. One recovered factor breaks flag key derivation.

So even with `remaining_logins = 4`, attack succeeds in a single attempt.

---

## 5. Exploit Construction

## 5.1 Fault placement in `share_key_enc`

`share_key_enc` is ECB-encrypted serialized `(p,q,d,u)`.

To avoid destroying parser-critical early fields, flip one byte in a late block known to be inside `u` region:

- in solved script: block index `39` (`blocks[39][0] ^= 1`)

This preserves parseability while altering `u`.

## 5.2 Choice of `m`

Pick random large `m in [1, n-1]`:

- prevents degenerate cases where CRT branches accidentally align (`mp == mq`)
- gives stable faulty behavior

## 5.3 End-to-end sequence

1. connect and parse registration JSON
2. query `get_encrypted_flag`
3. sample random `m`, compute `c = m^e mod n`
4. create faulted `share_key_enc`
5. call `wait_login`
6. call `send_challenge` with
   - `SID_enc = c`
   - original `master_key_enc`
   - faulted `share_key_enc`
7. parse returned truncated SID (`S_hi`)
8. solve small root for `x`
9. factor `n` by gcd
10. derive AES key and decrypt flag

---

## 6. Flag Decryption

After factorization:

- candidate key 1: `SHA256(p||q)`
- candidate key 2: `SHA256(q||p)`

Try both orders against `encrypted_flag`, unpad, check prefix `crypto{`.

For this run, output was:

```text
crypto{W4s_th4t_rea11y_Any_hard3r??}
```

---

