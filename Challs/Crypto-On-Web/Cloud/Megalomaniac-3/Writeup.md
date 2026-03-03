# CryptoHack Megalomaniac-3 (Port 13410) - Writeup

## Challenge Goal

Recover the actual uploaded file data (which contains the flag) from the MEGA-like protocol implementation.

Service:
- `socket.cryptohack.org 13410`

Given source:
- `13410.py`

---

## 1. What the Server Leaks

When connecting, the challenge prints three JSON blobs:

1. Registration crypto material:
- `master_key_enc`
- `share_key_pub = (n, e)`
- `share_key_enc`

2. Uploaded file material:
- `node_key_enc`
- `file_enc`

3. Extra leak:
- `share_key = (n, e, p)`

That third leak gives one RSA prime `p` directly.

---

## 2. Crypto Layout in Code

From `Client.prepare_file`:

- random `node_key` (16 bytes)
- `file_enc = AES-ECB(node_key).encrypt(pad(FILE, 16))`
- `node_key_enc = AES-ECB(master_key).encrypt(node_key)`

From `Client.prepare_crypto_material`:

- `share_key_enc = AES-ECB(master_key).encrypt(format_rsa_privkey())`

`format_rsa_privkey()` serializes and pads:

- `len(p)||p||len(q)||q||len(d)||d||len(u)||u`

So both `share_key_enc` and `node_key_enc` are under the same AES-ECB key (`master_key`).

---

## 3. Oracle Behavior

At login, attacker controls:

- `SID_enc`
- `share_key_enc`
- `master_key_enc`

Server does:

1. decrypt `master_key_enc` to get `master_key`
2. decrypt + parse `share_key_enc` into `(p,q,d,u)`
3. compute CRT RSA decrypt result `SID`
4. return `SID[:-16]` (drops last 16 bytes)

CRT recombination in code:

- `mp = c^dp mod p`
- `mq = c^dq mod q`
- `t = (mq - mp) mod q`
- `h = (t * u) mod q`
- `s = h*p + mp`

---

## 4. Main Idea

Because ECB is blockwise and both values use the same key:

- Replace one ciphertext block inside `share_key_enc` (specifically inside serialized `u`) with `node_key_enc`.
- After decryption, that 16-byte chunk of `u` becomes exactly `node_key`.

So parsed `u'` becomes:

- original `u`, except one 16-byte window replaced by unknown `node_key`.

If we can recover that replaced chunk, we recover the file key.

---

## 5. Why the Leak `(n,e,p)` Makes This Easy

From leaked `p` and public `n,e`:

- `q = n / p`
- `phi = (p-1)(q-1)`
- `d = e^{-1} mod phi`
- original `u = p^{-1} mod q`

So we can reconstruct exact serialized private key, including exact byte layout and where `u` starts.

This lets us choose a block entirely inside `u` and model the resulting `u'` algebraically.

---

## 6. Math to Recover the Injected 16 Bytes

Pick random plaintext integer `m`, encrypt `c = m^e mod n`, and query oracle once with forged `share_key_enc`.

Let server output be truncated high part `S_hi`, so:

- `s' = (S_hi << 128) + x`, with unknown `0 <= x < 2^128`

But modulo `p`, CRT formula always gives:

- `s' ≡ mp (mod p)` where `mp = c^dp mod p`

Hence:

- `x ≡ mp - (S_hi << 128) (mod p)`

Since true `x` is 128-bit, we recover exact `x` by checking this residue is `< 2^128`.

Then exact `s'` is known.

Now from CRT recombination:

- `s' = h*p + mp`
- `h = (t * u') mod q`
- `t = (mq - mp) mod q` (computable, because `p,q,d` known)

Define:

- `r = (s' - mp) / p`

Then:

- `r ≡ t*u' (mod q)`
- `u' ≡ r * t^{-1} (mod q)`

So we obtain `u' mod q`.

### 6.1 Express `u'` as linear function of unknown chunk

Let `u` byte length be `L`, and replaced chunk starts at byte offset `off` inside `u`.

Write:

- `u' = A + coeff * X`

Where:

- `X` is the unknown 16-byte integer (`node_key`)
- `A` = known integer with that 16-byte region zeroed
- `coeff = 2^{8*(L-(off+16))}`

Modulo `q`:

- `X ≡ (u' - A) * coeff^{-1} (mod q)`

Because `X < 2^128`, this yields the exact 16-byte node key.

Finally decrypt:

- `FILE = unpad(AES-ECB(node_key).decrypt(file_enc), 16)`

---

## 7. Exploit Steps Used

1. Connect and parse the three printed JSON objects.
2. Extract `n,e,p`, compute `q,d,u`.
3. Rebuild serialized private key bytes to locate a full block inside `u`.
4. Forge `share_key_enc` by replacing that block with `node_key_enc`.
5. Choose random `m`, compute `c = m^e mod n`.
6. `wait_login` then `send_challenge` once with forged share key.
7. Reconstruct exact `s'` from truncated output using modulo-`p` relation.
8. Recover `u' mod q`, then solve linear equation for the inserted 16-byte chunk.
9. Use recovered chunk as AES key to decrypt `file_enc`.
10. Read flag from decrypted file text.

Only one oracle query (`send_challenge`) is needed.

---


