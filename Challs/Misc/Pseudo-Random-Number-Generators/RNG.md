# Pseudo-Random Number Generators: A Complete Technical Reference

---

## Table of Contents

1. What Is Randomness
2. True Randomness vs Pseudo-Randomness
3. What Is a PRNG
4. Seeds and State
5. Statistical Properties of Good Randomness
6. Linear Congruential Generator (LCG)
7. Multiplicative Congruential Generator and Lehmer
8. Lagged Fibonacci Generator (LFG)
9. Xorshift Generators
10. Xorshift128+, Xoshiro, Xoroshiro Family
11. Mersenne Twister (MT19937)
12. Linear Feedback Shift Register (LFSR)
13. Galois LFSR
14. Non-Linear Feedback Shift Register (NLFSR)
15. Geffe Generator and Correlation Attacks
16. Shrinking Generator and Self-Shrinking Generator
17. Blum-Blum-Shub (BBS)
18. Stream Ciphers as PRNGs: RC4
19. ChaCha20 as a CSPRNG
20. Fortuna CSPRNG
21. Yarrow CSPRNG
22. Hash-DRBG, HMAC-DRBG, CTR-DRBG
23. What Makes a CSPRNG
24. Entropy Sources and Entropy Pools
25. /dev/random and /dev/urandom on Linux
26. The Birthday Problem and Output Collisions
27. Period, State Space, and Why They Matter
28. Lattice Attacks on LCG
29. Berlekamp-Massey Algorithm and LFSR Reconstruction
30. Cryptographic Failures from Bad PRNGs
31. Dual EC DRBG and the NSA Backdoor
32. Testing Randomness: NIST, Diehard, TestU01
33. Implementation in Code
34. Summary Table

---

## 1. What Is Randomness

Before anything else, you need to understand what randomness actually means, because it is surprisingly hard to define precisely.

Intuitively, a sequence of numbers is random if you cannot predict the next number from looking at the previous ones. But this is a property about information and predictability, not about the numbers themselves. The sequence 1, 2, 3, 4, 5 is completely predictable. The sequence 4, 1, 3, 7, 2 might look random but it could be the first five terms of a deterministic formula.

Formally, a sequence is considered random if it passes a battery of statistical tests: equal frequency of each digit, no detectable patterns, no autocorrelation between values, and so on. But any finite sequence can be produced by some deterministic formula, so the concept of randomness for finite sequences is really about complexity and unpredictability rather than some platonic notion of "true" randomness.

For practical purposes, we care about two distinct things:

- Statistical randomness: the output looks like it was sampled uniformly from the intended distribution, with no exploitable patterns
- Unpredictability: an adversary who sees some outputs cannot predict future or past outputs

These are different requirements and different tools serve different purposes.

---

## 2. True Randomness vs Pseudo-Randomness

**True random number generators (TRNGs)** harvest randomness from physical processes that are genuinely non-deterministic or at least so chaotic that they are computationally irreproducible. Examples include:

- Thermal noise in resistors
- Radioactive decay timing
- Photon arrival times
- Mouse movements and keyboard timing
- Hard disk seek time jitter
- Atmospheric noise (what random.org uses)

The key property is that these processes are not deterministic functions of accessible prior state. Even if you knew all prior outputs, you could not predict the next one.

**Pseudo-random number generators (PRNGs)** are deterministic algorithms. They take an initial value called a seed and produce a sequence that looks statistically random but is completely determined by the seed. If you give the same seed to the same algorithm, you always get the same sequence.

This determinism is both a feature and a bug.

Feature: you can reproduce simulations, debug code, share seeds for reproducibility.

Bug: if an attacker learns the seed or internal state, they can predict every output ever generated.

In practice, true randomness is slow and hard to gather in large quantities. Pseudo-randomness is fast and arbitrarily long. Most systems combine both: use a TRNG to gather a small amount of true randomness, then use it to seed a PRNG that generates large volumes of output.

---

## 3. What Is a PRNG

A PRNG is a deterministic function that maps an internal state to an output value and a new state:

```
state_0       = seed
state_{n+1}   = f(state_n)
output_n      = g(state_n)
```

The function `f` is the state transition function. The function `g` is the output function. Sometimes they are the same function; sometimes `g` is a projection that only reveals part of the state.

The entire security, quality, and utility of a PRNG depends on the choice of `f` and `g`. A bad `f` produces patterns. A `g` that exposes too much state allows state reconstruction. A small state space causes the sequence to repeat too quickly.

---

## 4. Seeds and State

The seed is the initial input to a PRNG. It fully determines the output sequence.

The state is the internal memory of the PRNG at any point in time. For simple generators, state and seed are the same size. For more complex ones, the state may be much larger than the seed.

The state space is the set of all possible states. If the state is k bits, there are at most 2^k possible states, so the sequence must repeat within 2^k steps. This maximum length is called the period.

For a PRNG to be useful:

- The period must be much larger than the amount of output you will ever need
- The state must be large enough that an attacker cannot enumerate all possible states
- The state must not be recoverable from a reasonable amount of output

Seeding is critical. A PRNG seeded with poor randomness is only as unpredictable as its seed. If your seed is a 32-bit Unix timestamp, there are only about 2^32 possible seeds, meaning an attacker can try all of them in seconds on modern hardware.

---

## 5. Statistical Properties of Good Randomness

When we say output looks random, we mean it satisfies several measurable properties.

**Uniform distribution**: Each possible output value appears with equal frequency over the long run. For a k-bit output, each value should appear with probability 1/2^k.

**Independence**: Outputs at different positions should be uncorrelated. Knowing output at position n should give no information about output at position n+1.

**Long period**: The sequence should not repeat for an astronomically long time.

**Equidistribution in higher dimensions**: If you take k consecutive outputs and plot them as a point in k-dimensional space, the points should fill the space uniformly. Many weak generators look fine in 1D but cluster along hyperplanes in higher dimensions. This is the spectral test.

**Avalanche effect**: A 1-bit change in the seed should produce an entirely different output sequence, not just a slightly shifted one.

The spectral test is worth understanding in detail. Take an LCG output sequence and plot consecutive pairs (x_n, x_{n+1}) as 2D points. For a good LCG these points should tile the plane. For a bad LCG they cluster into parallel lines. The spacing between those lines is the spectral gap and it is a measurable property of the generator's constants. George Marsaglia showed in 1968 that every LCG has this lattice structure in higher dimensions; the only question is how severe it is.

---

## 6. Linear Congruential Generator (LCG)

The LCG is the oldest and most widely studied PRNG. It is used in many standard library implementations including Java's `java.util.Random`, glibc's `rand()`, and many others.

### The Formula

```
X_{n+1} = (a * X_n + c) mod m
```

Where:
- X_n is the current state (also the output)
- a is the multiplier
- c is the increment
- m is the modulus
- X_0 is the seed

### Example

Let a = 5, c = 3, m = 16, X_0 = 7:

```
X_1 = (5 * 7  + 3) mod 16 = 38  mod 16 = 6
X_2 = (5 * 6  + 3) mod 16 = 33  mod 16 = 1
X_3 = (5 * 1  + 3) mod 16 = 8   mod 16 = 8
X_4 = (5 * 8  + 3) mod 16 = 43  mod 16 = 11
X_5 = (5 * 11 + 3) mod 16 = 58  mod 16 = 10
X_6 = (5 * 10 + 3) mod 16 = 53  mod 16 = 5
X_7 = (5 * 5  + 3) mod 16 = 28  mod 16 = 12
...
```

### Hull-Dobell Theorem

For an LCG with modulus m, multiplier a, increment c, and seed X_0, the generator has full period m (visits all values before repeating) if and only if:

1. c and m are coprime: gcd(c, m) = 1
2. a - 1 is divisible by all prime factors of m
3. If m is divisible by 4, then a - 1 must also be divisible by 4

For m = 2^k (power of 2, which is common for speed):
- c must be odd
- a mod 4 must equal 1

### Weaknesses of LCG

**Low-order bits are terrible.** When m = 2^k, the low-order j bits of X_n form their own independent LCG with modulus 2^j. This means the lowest bit alternates 0, 1, 0, 1, ... and the second-lowest bit has period 4. If you need random bits, never use the low-order bits of an LCG.

**State is the output.** In a plain LCG, the output IS the state. If you know any output, you know the state, and you can compute all future and past outputs.

**Lattice structure.** If you take k consecutive outputs and interpret them as a point in k-dimensional space, all these points lie on a small number of hyperplanes. The number of hyperplanes is at most (k! * m)^(1/k). For large m and small k, this gives many hyperplanes and looks fine. But it is always a lattice, not a uniform filling.

**Predictability from few outputs.** Given as few as 2-3 consecutive outputs, you can reconstruct a and c via:

```
X_2 = a * X_1 + c  (mod m)
X_3 = a * X_2 + c  (mod m)

Subtracting:
X_3 - X_2 = a * (X_2 - X_1)  (mod m)

If gcd(X_2 - X_1, m) = 1:
a = (X_3 - X_2) * modular_inverse(X_2 - X_1, m)  mod m
c = X_2 - a * X_1  mod m
```

### Common Parameters in Real Systems

ANSI C (used by many systems):
```
m = 2^31,  a = 1103515245,  c = 12345
```

Java `java.util.Random`:
```
m = 2^48,  a = 25214903917,  c = 11
Output is top 32 bits of 48-bit state
```

Numerical Recipes:
```
m = 2^32,  a = 1664525,  c = 1013904223
```

---

## 7. Multiplicative Congruential Generator and Lehmer

When c = 0, the LCG becomes a Multiplicative Congruential Generator (MCG):

```
X_{n+1} = a * X_n  mod m
```

This cannot have full period m because 0 is a fixed point: if X_n = 0 ever, all future values are 0. So the maximum period is m - 1 (or some divisor thereof). The seed must be nonzero.

For prime moduli, the period can be m - 1 (Fermat's little theorem guarantees this if a is a primitive root mod m, meaning a generates the entire multiplicative group of integers modulo m).

### Lehmer Generator (MINSTD)

The Lehmer generator uses m = 2^31 - 1 = 2147483647 (a Mersenne prime) with a = 16807. The period is exactly 2^31 - 2 (all values from 1 to 2^31 - 2 appear exactly once before repeating).

The implementation challenge is computing 16807 * X without overflow on a 32-bit machine. The Schrage method decomposes this:

```
m = 2147483647
a = 16807
q = m div a = 127773
r = m mod a = 2836

X_{n+1} = a * (X mod q) - r * (X div q)
if X_{n+1} < 0:
    X_{n+1} += m
```

This computes the same result but never requires a product larger than approximately m. Both terms a*(X mod q) and r*(X div q) are bounded by m, so their difference is in (-m, m).

While statistically better than naive LCGs for many purposes, Lehmer is completely predictable from a single output since the state is the output.

---

## 8. Lagged Fibonacci Generator (LFG)

The Fibonacci sequence is X_n = X_{n-1} + X_{n-2}. The Lagged Fibonacci Generator generalizes this:

```
X_n = X_{n-j}  op  X_{n-k}   (mod m)
```

Where j < k are the lags, op is some binary operation (usually +, -, *, or XOR), and the state consists of the last k values.

### Example with Addition

With j = 3, k = 5, m = 2^32, seed = [1, 2, 3, 4, 5]:

```
X_6 = X_3 + X_1 = 3 + 1 = 4
X_7 = X_4 + X_2 = 4 + 2 = 6
X_8 = X_5 + X_3 = 5 + 3 = 8
X_9 = X_6 + X_4 = 4 + 4 = 8
```

### Period

For the additive LFG with m = 2^b, if the characteristic polynomial x^k + x^j + 1 is primitive over GF(2), the period is (2^k - 1) * 2^(b-1). For well-chosen lags, the polynomial is primitive and the period is enormous.

Good lag pairs where x^k + x^j + 1 is primitive over GF(2):
- (j=7, k=10)
- (j=5, k=17)
- (j=24, k=55)
- (j=65, k=71)

### Properties

LFGs have very long periods with large k. The state is k words, so more memory is needed but more entropy is mixed in.

LFGs fail some statistical tests when the lags are poorly chosen. They also require a good method to initialize the k initial values; a bad initialization can produce poor output for many steps. Common practice is to seed a simple LCG and use its output to fill the initial state of the LFG.

---

## 9. Xorshift Generators

George Marsaglia introduced xorshift generators in 2003. They are extremely fast because they use only XOR and bit shifts, which are single-cycle CPU instructions.

### Basic 32-bit Xorshift

```
x ^= x << 13
x ^= x >> 17
x ^= x << 5
```

Return x. The state is a single 32-bit integer. The shifts and XORs are chosen so that the state transition is a maximal-period linear recurrence, giving period 2^32 - 1.

### Why This Works: GF(2) Linear Algebra

Think of the 32-bit state as a vector in GF(2)^32. XOR is addition in GF(2). A left shift by s corresponds to multiplication by a shift matrix. Composing several shift-XOR operations gives a matrix T over GF(2)^32.

The sequence has period 2^32 - 1 (all states except 0) if and only if T is a primitive matrix over GF(2), meaning its characteristic polynomial is a primitive polynomial of degree 32.

Marsaglia tested many combinations of triple shifts to find those whose combined matrix has a primitive characteristic polynomial. The condition is: for the sequence to visit all 2^32 - 1 nonzero states, the composition of the three xorshift operations must form a primitive element of the matrix ring GF(2)^(32x32).

### 64-bit Xorshift

```
x ^= x << 13
x ^= x >> 7
x ^= x << 17
```

Period = 2^64 - 1.

### Weakness: Linearity

Xorshift generators are entirely linear over GF(2). This means:
- If s and t are both valid state sequences, so is s XOR t (superposition holds)
- The Berlekamp-Massey algorithm can recover the feedback polynomial from 64 output bits (or 128 bits for 64-bit xorshift), and then predict all future output

For non-cryptographic use (simulations, games, procedural generation), they are excellent: fast, long period, good statistical properties. For cryptography, never use them.

---

## 10. Xorshift128+, Xoshiro, Xoroshiro Family

These are improvements on plain xorshift that add nonlinearity to fix the linear shortcomings.

### Xorshift128+

State: two 64-bit values (s0, s1).

```
s1  ^= s0
s0   = rotate_left(s0, 55) ^ s1 ^ (s1 << 14)
s1   = rotate_left(s1, 36)
return s0 + s1
```

The addition at the output step introduces nonlinearity. Period = 2^128 - 1. Used in V8 (Chrome's JavaScript engine) and Firefox for `Math.random()`.

### Xoshiro256**

State: four 64-bit values.

```
result = rotate_left(s1 * 5, 7) * 9
t = s1 << 17
s2 ^= s0
s3 ^= s1
s1 ^= s2
s0 ^= s3
s2 ^= t
s3 = rotate_left(s3, 45)
return result
```

Period = 2^256 - 1. Passes all BigCrush tests. The `**` means a multiply-rotate-multiply scrambler is applied to produce the output. There is also a `++` variant (add-rotate-add) which is slightly slower.

### Xoroshiro128+

State: two 64-bit values. Faster than xoshiro256 due to smaller state.

```
result = s0 + s1
s1 ^= s0
s0 = rotate_left(s0, 24) ^ s1 ^ (s1 << 16)
s1 = rotate_left(s1, 37)
return result
```

Period = 2^128 - 1.

### Jump Functions

You can compute a "jump" that advances the state by 2^64 or 2^128 steps without iterating. This is done by multiplying by a precomputed polynomial over GF(2), the same matrix exponentiation trick as fast Fibonacci. Useful for parallelism: give each thread a different jump-point in the sequence so their subsequences never overlap.

---

## 11. Mersenne Twister (MT19937)

Developed by Matsumoto and Nishimura in 1998, the Mersenne Twister was the standard general-purpose PRNG for decades. Python's `random`, Ruby, PHP, R, and MATLAB all use it by default.

### Parameters

```
w = 32       (word size in bits)
n = 624      (state size in words)
m = 397      (middle word offset)
r = 31       (separation point)
a = 0x9908B0DF  (twist matrix coefficient)
b = 0x9D2C5680  (tempering mask 1)
c = 0xEFC60000  (tempering mask 2)
s = 7, t = 15   (tempering shifts)
u = 11, l = 18  (tempering shifts)
```

The name comes from the period: 2^19937 - 1, a Mersenne prime.

### Generation (twist step, run when all 624 values are consumed)

```
for i in range(0, 624):
    x = (state[i] & 0x80000000) | (state[(i+1) % 624] & 0x7FFFFFFF)
    xA = x >> 1
    if x & 1:
        xA ^= 0x9908B0DF
    state[i] = state[(i + 397) % 624] ^ xA
```

The upper bit of state[i] and lower 31 bits of state[i+1] are combined, right-shifted, and conditionally XORed with the twist constant. This is a linear recurrence over GF(2).

### Tempering (output step)

State values are not output directly. A tempering transform is applied to improve equidistribution:

```
y = state[index]
y ^= (y >> 11)
y ^= (y << 7)  & 0x9D2C5680
y ^= (y << 15) & 0xEFC60000
y ^= (y >> 18)
return y
```

MT is 623-dimensionally equidistributed with 32-bit precision, meaning every 623-tuple of consecutive 32-bit values appears with equal frequency.

### State Recovery Attack

After observing 624 consecutive 32-bit outputs, an attacker can fully recover the internal state by inverting the tempering transform. The inverse exists because each step is an invertible operation:

```python
def untemper(y):
    # Invert y ^= y >> 18
    y ^= y >> 18
    # Invert y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # Invert y ^= (y << 7) & 0x9D2C5680  (requires iteration)
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp
    # Invert y ^= y >> 11  (requires iteration)
    tmp = y
    for _ in range(2):
        tmp = y ^ (tmp >> 11)
    return tmp & 0xFFFFFFFF
```

After recovering all 624 state values, you know every future and past output. MT has no forward secrecy and no security properties beyond statistical quality.

---

## 12. Linear Feedback Shift Register (LFSR)

An LFSR is a shift register whose input bit is a linear function (XOR) of certain bits of its current state. They are central to hardware design and stream cipher cryptography.

### How It Works

An n-bit LFSR has n flip-flops holding bits b_0, b_1, ..., b_{n-1}. At each clock cycle:

1. The output bit is b_0
2. Each bit shifts: new b_i = old b_{i+1}
3. The new input bit at position n-1 is the XOR of selected "tap" positions

The tap positions are described by the feedback polynomial:

```
p(x) = x^n + c_{n-1} x^{n-1} + ... + c_1 x + 1
```

where c_i = 1 means position i is a tap.

### Example: 4-bit LFSR

Polynomial: x^4 + x + 1, taps at positions 4 and 1.
Feedback: b_new = b_3 XOR b_0

State evolution with initial state 1101 (b_3 b_2 b_1 b_0):

```
State     Output  New input (b3 XOR b0)
1101      1       1 XOR 1 = 0
0110      0       0 XOR 0 = 0
0011      1       0 XOR 1 = 1
1001      1       1 XOR 1 = 0
0100      0       0 XOR 0 = 0
0010      0       0 XOR 0 = 0
0001      1       0 XOR 1 = 1
1000      0       1 XOR 0 = 1
1100      0       1 XOR 0 = 1
1110      0       1 XOR 0 = 1
1111      1       1 XOR 1 = 0
0111      1       0 XOR 1 = 1
1011      1       1 XOR 1 = 0
0101      1       0 XOR 1 = 1
1010      0       1 XOR 0 = 1
1101      1       (back to start)
```

Period = 15 = 2^4 - 1. This is the maximum possible period for a 4-bit LFSR.

### Maximal-Length LFSRs

An LFSR of length n achieves maximum period 2^n - 1 if and only if its feedback polynomial is primitive over GF(2). Primitive polynomials generate the entire multiplicative group of GF(2^n).

The all-zero state is excluded from the cycle (it maps to itself). So the period is 2^n - 1, not 2^n.

Some primitive polynomials:

```
n=4:   x^4 + x + 1
n=8:   x^8 + x^4 + x^3 + x^2 + 1
n=16:  x^16 + x^12 + x^3 + x + 1
n=32:  x^32 + x^22 + x^2 + x + 1
n=64:  x^64 + x^4 + x^3 + x + 1
n=128: x^128 + x^7 + x^2 + x + 1
```

### LFSR as GF(2) Matrix

The state b = [b_0, ..., b_{n-1}] evolves as b_{n+1} = C * b_n where C is the companion matrix of p(x) over GF(2):

```
C = | 0  1  0  0  ... 0      |
    | 0  0  1  0  ... 0      |
    | 0  0  0  1  ... 0      |
    | .  .  .  .      .      |
    | c0 c1 c2 c3 ... c_{n-1}|
```

The sequence has maximal period if and only if C is a primitive matrix, i.e., the order of C in GF(2)^(nxn) is exactly 2^n - 1.

### Berlekamp-Massey Attack

The fatal weakness: given 2n consecutive output bits, the Berlekamp-Massey algorithm recovers the feedback polynomial in O(n^2) time. Once you know the polynomial and 2n bits, you can predict all future output.

This means a single LFSR is completely insecure as a stream cipher. All practical LFSR-based designs add nonlinearity.

### Hardware Efficiency

LFSRs are extremely fast in hardware. An n-bit LFSR requires only n flip-flops and a handful of XOR gates. A 128-bit maximal-length LFSR can run at gigahertz speeds, generating one bit per clock cycle. This is why LFSRs appear in GPS (Gold codes), CDMA, CRC computation, and as components in stream ciphers.

---

## 13. Galois LFSR

The standard LFSR described above is called the Fibonacci LFSR (external XOR). There is an equivalent but different arrangement called the Galois LFSR (internal XOR).

In a Galois LFSR, the XOR taps are placed between flip-flops along the chain, rather than feeding back to the input:

For polynomial x^4 + x + 1:

```
Fibonacci form:
  b0 --> b1 --> b2 --> b3 --+-> output
   ^                        |
   +-----------XOR----------+
                  ^--- tap at position 1 (x^1 term)

Galois form:
  output <- b0 <-XOR- b1 <--- b2 <--- b3
                        ^-- b3 tapped here
```

The Galois form produces the same sequence (with a possible time offset) as the Fibonacci form for the same polynomial. The advantage is that the XOR operations are distributed along the chain and can be done in parallel in hardware, whereas Fibonacci XOR is sequential.

In software, the Galois form is implemented as:

```c
if (state & 1) {
    state = (state >> 1) ^ polynomial_mask;
} else {
    state >>= 1;
}
output_bit = old_lsb;
```

where polynomial_mask has 1-bits at the positions corresponding to the nontrivial terms of p(x) excluding x^n and x^0.

---

## 14. Non-Linear Feedback Shift Register (NLFSR)

A plain LFSR is entirely linear over GF(2). An NLFSR replaces the linear feedback function with a nonlinear Boolean function of the state bits:

```
b_new = f(b_0, b_1, ..., b_{n-1})
```

where f is not a simple XOR of subsets of the bits.

Choosing a good f requires satisfying several competing properties:

**High algebraic degree**: f should not be approximable by a low-degree polynomial over GF(2). If f has degree d, an algebraic attack requires roughly 2^d known output bits.

**High nonlinearity**: The nonlinearity of f is the minimum Hamming distance between f and all affine functions over GF(2)^n. The maximum achievable nonlinearity for an n-variable function is 2^(n-1) - 2^(n/2-1) (achieved by bent functions). High nonlinearity resists linear approximation attacks.

**Correlation immunity**: f is t-th order correlation immune if the output is statistically independent of any t inputs. Formally, for every set of t input indices S, the output is uncorrelated with the XOR of inputs in S. This resists correlation attacks.

**Balance**: f outputs 0 and 1 with equal probability. An unbalanced function introduces bias that leaks information.

Siegenthaler's theorem establishes a fundamental tradeoff: a balanced n-variable Boolean function of algebraic degree d has correlation immunity at most n - d. You cannot have both maximum degree and high-order correlation immunity simultaneously.

Functions achieving maximum nonlinearity are called bent functions. They cannot be balanced, so they are used in constructions that combine them with other elements to restore balance.

---

## 15. Geffe Generator and Correlation Attacks

The Geffe generator (1973) was one of the first attempts to combine LFSRs for cryptographic strength.

### Structure

Three LFSRs: R1 (selector), R2, R3 with pairwise coprime lengths.

```
Output = (R1 AND R2) XOR ((NOT R1) AND R3)
```

Equivalently:
- If R1 = 1, output = R2
- If R1 = 0, output = R3

### Correlation Attack (Siegenthaler, 1985)

The output z is equal to R2 with probability 3/4:
- When R1 = 1 (probability 1/2): z = R2, so P(z = R2) = 1
- When R1 = 0 (probability 1/2): z = R3, which agrees with R2 with probability 1/2

Overall: P(z = R2) = (1/2)(1) + (1/2)(1/2) = 3/4

Similarly, P(z = R3) = 3/4.

An attacker can break R2 independently:
1. Try all 2^|R2| initial states for R2
2. For each candidate, generate the R2 sequence
3. Count how many positions it agrees with z (expect 75% for correct state, ~50% for wrong state)
4. Select the state with the highest agreement score

The R2 LFSR is broken in time 2^|R2| instead of 2^(|R1| + |R2| + |R3|). Then R3 breaks similarly. Finally R1 is recovered.

This attack exploits correlation between the output and individual inputs. The Geffe function has correlation immunity of order 0, meaning each individual input is correlated with the output.

### Designing Correlation-Immune Functions

To resist this attack, you need a combining function that is at least 1st order correlation immune (no individual input is correlated with the output). The function must satisfy:

For all i, for all (b_1, ..., b_{i-1}, b_{i+1}, ..., b_n):
  sum over b_i of (-1)^(b_i + f(b_1,...,b_n)) = 0

The Maiorana-McFarland construction and other algebraic methods produce correlation-immune functions of arbitrary order.

---

## 16. Shrinking Generator and Self-Shrinking Generator

### Shrinking Generator

Two LFSRs: A (control) and S (sequence generator).

Clock both at each step. If the current output of A is 1, output the current bit of S. If A outputs 0, discard the current bit of S and output nothing that step.

The irregular clocking breaks the linear structure. The output bit rate is variable (roughly half the clock rate on average). An attacker who sees only the output does not know which S bits were used.

The period of the output is (2^|A| - 1) * 2^(|S| - 1) for good choices of polynomials.

For security, |S| should be roughly twice |A| to prevent exhaustive search over A states.

### Self-Shrinking Generator

Only one LFSR. Take output bits in pairs (b_1, b_2), (b_3, b_4), etc. If b_{2i-1} = 1, output b_{2i}. If b_{2i-1} = 0, discard b_{2i}.

Simpler construction. The period is at least 2^(n/2 - 1) for an n-bit LFSR. The output has good statistical properties. The main advantage over the shrinking generator is that only one LFSR needs to be implemented, reducing hardware cost.

Both generators have been attacked by various methods and are not considered secure for modern cryptography, but they are historically important as the first irregular clocking constructions.

---

## 17. Blum-Blum-Shub (BBS)

Blum-Blum-Shub is a CSPRNG with provable security based on the hardness of the quadratic residuosity problem, which is equivalent to integer factorization.

### Setup

Choose two large primes p and q, both congruent to 3 mod 4. Compute n = p * q (this is called a Blum integer). The condition p ≡ q ≡ 3 mod 4 ensures that -1 is a quadratic non-residue modulo both p and q, which gives the generator its security property.

Choose a seed s with gcd(s, n) = 1. Compute:

```
X_0 = s^2  mod n
X_{i+1} = X_i^2  mod n
b_i = LSB(X_i)   (least significant bit)
```

Output the bits b_1, b_2, b_3, ...

### Why the Low-Order Bit

For a Blum integer n = p*q with p ≡ q ≡ 3 mod 4, computing the square root modulo n requires knowing the factorization. Given X_{i+1} = X_i^2 mod n, finding X_i from X_{i+1} is as hard as factoring n. The lowest bit of X_i cannot be determined from X_{i+1} without solving this hard problem.

### Security Reduction

If you can predict the (k+1)-th output bit with probability 1/2 + epsilon, you can factor n in time polynomial in the security parameter (the bit length of n). This is a formal cryptographic reduction: breaking BBS = factoring.

This makes BBS the most theoretically justified PRNG, but the reduction is asymptotic and the constant factors matter.

### Multiple Bits Per Step

You can safely extract the low-order O(log log n) bits from each X_i. For a 2048-bit n, that is about 11 bits per squaring. Still much slower than other generators.

### Practical Issues

For 2048-bit n, each squaring takes hundreds of microseconds on software. A fast stream cipher generates gigabytes per second. BBS is therefore impractical for most applications and is primarily of theoretical importance.

---

## 18. Stream Ciphers as PRNGs: RC4

A stream cipher generates a keystream that is XORed with the plaintext to produce ciphertext. The keystream generator is a CSPRNG keyed with the secret key.

### RC4

RC4 (Rivest Cipher 4, 1987) was the most widely used stream cipher for decades, appearing in WEP, WPA, SSL/TLS, and many other protocols.

**Key Scheduling Algorithm (KSA):**

```python
S = list(range(256))  # Identity permutation
j = 0
for i in range(256):
    j = (j + S[i] + key[i % len(key)]) % 256
    S[i], S[j] = S[j], S[i]
```

**Pseudo-Random Generation Algorithm (PRGA):**

```python
i = 0
j = 0
while True:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i], S[j] = S[j], S[i]
    yield S[(S[i] + S[j]) % 256]
```

**Weaknesses:**

Initial bytes are biased. The first few hundred bytes of keystream are not uniformly distributed. In WEP, the IV was prepended to the key in a way that made this bias exploitable for key recovery.

The Fluhrer-Mantin-Shamir (FMS) attack (2001) exploited weak IV structure to recover the WEP key from around 40,000 captured packets. Tools like Aircrack-ng reduced this to minutes.

Even discarding the initial bytes, RC4 has subtle biases throughout its output. At certain positions, pairs of output bytes have non-uniform joint distributions. Modern analysis shows that RC4's bias is detectable in as little as 2^25 bytes. For attackers recovering plaintext with RC4, statistical distinguishers require at most 2^34 bytes of keystream from the same key.

RC4 is now prohibited in TLS 1.2 (RFC 7465) and not present in TLS 1.3.

---

## 19. ChaCha20 as a CSPRNG

ChaCha20 (Bernstein, 2008) is a stream cipher used as a CSPRNG in modern systems including TLS 1.3, Linux kernel, and many other applications.

### State

ChaCha20 operates on a 4x4 matrix of 32-bit words (512 bits = 64 bytes total):

```
"expa"  "nd 3"  "2-by"  "te k"   <- constants (little-endian ASCII)
key[0]  key[1]  key[2]  key[3]
key[4]  key[5]  key[6]  key[7]
ctr[0]  ctr[1]  nonce[0] nonce[1]
```

The constants are the ASCII bytes of "expand 32-byte k" split into four 32-bit little-endian words.

### Quarter Round

The core operation applied to 4 words (a, b, c, d):

```
a += b;  d ^= a;  d <<<= 16;
c += d;  b ^= c;  b <<<= 12;
a += b;  d ^= a;  d <<<=  8;
c += d;  b ^= c;  b <<<=  7;
```

Where `<<<=` is left rotation. The mix of addition (nonlinear mod 2^32), XOR (linear mod 2), and rotation (diffusion) is called an ARX design. The nonlinearity comes from the carries in modular addition.

### Double Round

Apply the quarter round to each column, then each diagonal:

```
Column rounds:   QR(0,4,8,12)  QR(1,5,9,13)  QR(2,6,10,14)  QR(3,7,11,15)
Diagonal rounds: QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13)   QR(3,4,9,14)
```

Twenty rounds (10 double rounds) are applied. Then the original input state is added word-by-word to the output (this addition prevents inverting the round function to recover the key).

### As a PRNG

Increment the counter for each 64-byte block. With a 64-bit counter, you get 2^64 * 64 = 2^70 bytes of output from a single key/nonce pair before needing to change the key. Combine with a system entropy source for the key and nonce, and reseed periodically. ChaCha20 with Poly1305 is also used as an authenticated encryption scheme (AEAD) in TLS 1.3.

ChaCha20 is 3-5x faster than AES on systems without AES hardware instructions (AES-NI).

---

## 20. Fortuna CSPRNG

Fortuna (Ferguson and Schneier, 2003) is a CSPRNG designed to be secure even if internal state is partially compromised. It is used in FreeBSD, macOS, and iOS.

### Architecture

Fortuna has three components.

**Entropy Accumulator**: 32 entropy pools P_0, P_1, ..., P_31. Each pool accumulates entropy from various sources. When adding an event, the accumulator cycles through pools in a round-robin fashion.

**Reseed Control**: The generator reseeds from the pools according to a schedule:
- P_0 is used in every reseed
- P_k is used in every 2^k-th reseed
- Reseeds do not happen more often than 100ms apart (rate limiting)

This means an attacker who can observe and poison some entropy events cannot control all pools simultaneously. If P_0 is fully compromised, eventually a reseed will incorporate P_1, then P_2, diluting the attacker's influence geometrically.

**Generator**: Uses AES-256 in counter mode:

```
key      = 256-bit AES key
counter  = 128-bit counter

to generate n blocks:
    output_block_i = AES_key(counter + i)

after generating, rotate key:
    new_key_low  = AES_key(counter + n)
    new_key_high = AES_key(counter + n + 1)
    key = new_key_low || new_key_high
    counter += n + 2
```

The key rotation after each generation request provides forward secrecy: if an attacker learns the current key, they cannot determine past outputs because the old key is overwritten.

### Security Properties

Forward secrecy: compromising current state reveals nothing about past outputs.

Recovery from compromise: once new entropy is mixed in, the generator produces unpredictable output again. The design guarantees that after incorporating P_k with good entropy, no adversary who controlled all prior pool contents can predict the output.

Rate limiting prevents denial-of-service through forced reseeds.

---

## 21. Yarrow CSPRNG

Yarrow (Ferguson and Schneier, 1999) was Fortuna's predecessor, used in older macOS and iOS.

### Architecture

Two entropy pools: fast pool and slow pool.

Entropy is added to the fast pool. When the fast pool has accumulated a threshold amount of entropy (measured by an explicit estimator), it reseeds the generator. The slow pool reseeds only when it has accumulated even more entropy.

The generator uses a block cipher (3DES or AES) in counter mode, similar to Fortuna.

### Difference from Fortuna

Yarrow relies on entropy estimation to decide when to reseed. Estimating the actual entropy in physical events is difficult and error-prone; the estimators used in practice are conservative and tend to underestimate.

Fortuna avoids this problem by using 32 pools with a schedule that guarantees eventual recovery without requiring accurate entropy estimates. This was the main motivation for designing Fortuna.

---

## 22. Hash-DRBG, HMAC-DRBG, CTR-DRBG

NIST SP 800-90A specifies three deterministic random bit generators standardized for cryptographic use.

### Hash-DRBG

Uses a hash function (typically SHA-256 or SHA-512). State: (V, C, reseed_counter) where V and C are fixed-length values derived from the seed.

**Generate:**

```
data = V
while output_length_needed > 0:
    output_block = Hash(data)
    output = output || output_block
    data = (data + 1) mod 2^seedlen

V = (V + Hash(0x03 || V) + C + reseed_counter) mod 2^seedlen
reseed_counter += 1
```

Security: as hard as finding second preimages in the hash function.

### HMAC-DRBG

Uses HMAC. State: (K, V) where K is the HMAC key and V is the working value.

**Update function (called after each generation and on reseed):**

```python
K = HMAC(K, V || 0x00 || provided_data)
V = HMAC(K, V)
if provided_data is not empty:
    K = HMAC(K, V || 0x01 || provided_data)
    V = HMAC(K, V)
```

**Generate:**

```python
while output_length_needed > 0:
    V = HMAC(K, V)
    output = output || V
(K, V) = update(K, V, additional_input)
reseed_counter += 1
```

HMAC-DRBG has a clean security proof: its security reduces to the pseudorandomness of HMAC. It is the recommended choice among the three for new implementations.

### CTR-DRBG

Uses a block cipher in counter mode. State: (Key, V) where Key is the cipher key and V is the counter.

**Generate:**

```python
while output_length_needed > 0:
    V = (V + 1) mod 2^blocklen
    output = output || Encrypt(Key, V)
(Key, V) = update(provided_data, Key, V)
reseed_counter += 1
```

With AES-256, CTR-DRBG is extremely fast and parallelizable. It is widely used in hardware security modules and embedded systems. The block cipher provides excellent diffusion and nonlinearity.

---

## 23. What Makes a CSPRNG

A CSPRNG must satisfy two properties that ordinary PRNGs do not.

### The Next-Bit Test

A generator passes the next-bit test if there is no polynomial-time algorithm that, given the first k output bits, can predict the (k+1)-th bit with probability greater than 1/2 + 1/poly(k) where poly is any polynomial.

In other words: outputs are computationally indistinguishable from true random bits by any efficient algorithm.

Yao's theorem (1982): a PRNG passes every polynomial-time statistical test if and only if it passes the next-bit test. So the next-bit test is the universal test for computational pseudorandomness. Any generator that fails any poly-time test (including all of the statistical tests in the NIST suite) also fails the next-bit test.

### State Compromise Extension (Backward Security)

Even if an attacker learns the current internal state, they cannot determine past outputs.

This requires that state transitions incorporate one-way operations so that inverting the state transition is computationally infeasible. CSPRNGs achieve this through periodic reseeding with fresh entropy and by using cryptographic one-way functions in the state update.

### Why Ordinary PRNGs Fail

- LCG: state equals output. Know one output, know all future and past outputs.
- LFSR: the Berlekamp-Massey algorithm reconstructs the state from 2n bits in O(n^2) time.
- MT19937: 624 outputs reconstruct state. The tempering transform is invertible. No forward secrecy.
- Xorshift family: linear over GF(2), state reconstructed in time proportional to state size.

None of these pass the next-bit test under any standard hardness assumption. There are no known polynomial-time predictors for ChaCha20, AES-CTR-DRBG, or HMAC-DRBG (assuming the underlying primitives are secure).

---

## 24. Entropy Sources and Entropy Pools

Hardware entropy sources include the following.

**Timing jitter**: The exact timing of hardware interrupts varies at the nanosecond scale due to uncontrollable physical effects (cache misses, bus contention, thermal noise in clock circuits). The least significant bits of high-resolution timestamps carry genuine randomness. Modern Linux uses interrupt timing as a primary entropy source.

**CPU hardware RNG**: Modern Intel and AMD CPUs include RDRAND and RDSEED instructions. RDRAND outputs from an on-chip AES-based DRBG reseeded by a thermal noise source. RDSEED outputs raw conditioned entropy. Both instructions return a success flag; software must check it since the hardware can fail.

**Disk seek times**: Traditional hard disk seek times are influenced by vibration, air turbulence, spindle motor jitter, and manufacturing variation. SSDs do not have this source. This was historically important but is less relevant now.

**Camera noise**: Pixels from a camera in a dark environment are dominated by shot noise (photon counting statistics), which is fundamentally quantum-mechanical and truly random. Smartphone cameras are used as entropy sources in some implementations.

**Network packet timing**: Arrival times of network packets carry entropy from network jitter and remote host scheduling variations.

### Entropy Estimation

Min-entropy is the most conservative entropy measure:

```
H_inf(X) = -log_2(max_x P(X = x))
```

For a fair coin, H_inf = 1 bit. For a biased coin with P(heads) = 0.9, H_inf = -log_2(0.9) = 0.152 bits. Min-entropy gives the security against a best-guess attack.

Entropy pools mix samples together using a hash function. Even if individual samples have low entropy, the accumulated pool has entropy equal to the sum of the individual min-entropies (roughly), because each sample is independent and the hash function preserves entropy.

---

## 25. /dev/random and /dev/urandom on Linux

### Historical Distinction (pre-kernel 5.4)

`/dev/random` blocked until enough entropy was estimated in the pool. This caused problems: servers would hang on boot waiting for entropy, headless systems (no keyboard or mouse) might stall indefinitely.

`/dev/urandom` never blocked. Once initially seeded, it generated output from the CSPRNG without pausing. The concern was that if the pool was not yet seeded, very early output might be predictable.

### Modern Linux (kernel 5.4+, 2019 onwards)

The distinction is largely eliminated. Both use the same ChaCha20-based CSPRNG, and /dev/random only blocks before the CSPRNG is first seeded (which happens quickly on most systems from hardware events at boot).

The architecture:

```
Hardware events (interrupts, RDRAND, etc.)
    |
    v
Entropy pool (mixed via BLAKE2 hash)
    |
    v
ChaCha20 CSPRNG (re-seeded periodically)
    |
    +-> /dev/urandom  (never blocks after init)
    +-> /dev/random   (blocks only before first seed)
    +-> getrandom()   (preferred syscall interface)
```

The `getrandom()` system call (Linux 3.17+) is the correct modern interface. It blocks only until the CSPRNG is initialized, is immune to TOCTOU races with file descriptors, and behaves correctly inside containers.

### Virtualization Problem

Two VMs booted from the same disk image at the same time may have nearly identical entropy pools. If the hypervisor does not inject unique entropy, both VMs produce the same supposedly random keys, a serious vulnerability.

Solutions: use RDRAND (hardware-specific), have the hypervisor seed the VM at creation, use virtio-rng, or use a network entropy service like haveged.

---

## 26. The Birthday Problem and Output Collisions

The birthday paradox: if you draw n samples uniformly from a space of size N, the probability of at least one collision (two identical samples) is approximately:

```
P(collision) ≈ 1 - e^(-n^2 / (2N))
```

This exceeds 50% when n ≈ 1.18 * sqrt(N).

### Application to PRNGs

If you generate n values from a PRNG with output space 2^k, you expect the first collision after about 2^(k/2) values.

For a PRNG with period P, if two instances are given the same seed, they produce identical sequences. If the seed space has S possibilities, you expect two instances with the same seed after seeding roughly sqrt(S) instances.

For 32-bit seeds (common in naive implementations): sqrt(2^32) = 2^16 = 65536 instances before expecting a collision. A large web service seeding 65536 sessions could have two sessions with identical key material.

For 256-bit seeds: sqrt(2^256) = 2^128, safely beyond any practical concern.

### ECDSA Nonce Collision

In ECDSA signing, a random nonce k is used per signature. If two signatures on different messages use the same k:

```
s1 = k^{-1} * (h1 + d * r)  mod n
s2 = k^{-1} * (h2 + d * r)  mod n

s1 - s2 = k^{-1} * (h1 - h2)  mod n
k = (h1 - h2) * (s1 - s2)^{-1}  mod n
d = (s1 * k - h1) * r^{-1}  mod n
```

Nonce reuse directly leaks the private key. This happened in the PlayStation 3 (Sony used a constant k), in Bitcoin wallets on Android (poor PRNG seeding), and in various TLS implementations.

---

## 27. Period, State Space, and Why They Matter

The period of a PRNG is the length of its output sequence before it repeats. A PRNG with n bits of state has period at most 2^n.

### Why Period Matters for Simulation

Monte Carlo methods generate many independent samples. If your period is P, then the N-th output and the (N + P)-th output are identical. For any two outputs at positions i and j, they are "truly" independent only if |i - j| is small compared to P.

More precisely: for two variables to be independent in a simulation, they should not be outputs at positions i and j where j - i is near 0 mod P. If you generate more than sqrt(P) total values, there is a reasonable probability of encountering near-repetition effects.

For MT19937 with period 2^19937, this is never a practical concern. For a 32-bit LCG with period 2^32, a simulation generating a billion values per second would cycle in about 4 seconds.

### Why State Size Matters for Security

If an attacker can enumerate all possible states, they can predict output. For a k-bit state that is fully determined by the seed, the attacker tries all 2^k possible seeds. For 32-bit seeds this takes seconds; for 64-bit seeds, a few hundred years at current hardware; for 128-bit seeds, impractical forever.

For CSPRNGs, state size is the security parameter. A 256-bit state means the generator has 256 bits of security (against state-guessing attacks), which is more than sufficient.

---

## 28. Lattice Attacks on LCG

Given a truncated LCG where only the high h bits of each n-bit state are output, can you recover the full state?

### Setup

You observe the high h bits of each state:
```
y_i = floor(X_i / 2^(n-h))
```

And you know X_{i+1} = a * X_i + c mod m. Write X_i = y_i * 2^(n-h) + e_i where e_i is the unknown low (n-h) bits, with 0 <= e_i < 2^(n-h).

The LCG relation gives:
```
y_{i+1} * 2^(n-h) + e_{i+1} = a * (y_i * 2^(n-h) + e_i) + c  (mod m)

e_{i+1} - a * e_i ≡ a * y_i * 2^(n-h) + c - y_{i+1} * 2^(n-h)  (mod m)
```

This is a system of linear equations in the unknowns e_i, which are small relative to m (bounded by 2^(n-h)).

### Lattice Reduction

Define a lattice L whose basis includes vectors encoding these constraints. The unknowns e_i are small, so the solution vector is a short vector in L. The LLL (Lenstra-Lenstra-Lovász) algorithm finds approximately short vectors in a lattice in polynomial time and often finds the exact shortest vector.

For a 48-bit Java LCG with 32-bit output (16 hidden bits), two consecutive outputs are sufficient. The LLL instance has dimension about 3 and runs in milliseconds.

For a 64-bit LCG with 32-bit output (32 hidden bits), about 5-10 consecutive outputs are needed, still running in seconds.

### Practical Demonstrations

This attack was demonstrated against Java's `java.util.Random` in 2010. Given two consecutive calls to `nextInt()`, the full 48-bit state is recovered and all future (and past) output is predicted. The attack requires only basic linear algebra plus LLL, which is in many standard libraries (SageMath, fplll).

---

## 29. Berlekamp-Massey Algorithm and LFSR Reconstruction

Given a binary sequence of length at least 2L that was produced by an unknown LFSR of length L, the Berlekamp-Massey algorithm finds the shortest LFSR that generates that sequence.

### Algorithm

```python
def berlekamp_massey(s):
    n = len(s)
    C = [1]   # current connection polynomial
    B = [1]   # previous connection polynomial
    L = 0     # current LFSR length
    m = 1     # steps since last length change

    for i in range(n):
        # Compute discrepancy: how well C predicts s[i]
        d = s[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= (C[j] & s[i - j])
        d &= 1

        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            # Extend C by adding B shifted right by m positions
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= B[j]
            L = i + 1 - L
            B = T
            m = 1
        else:
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= B[j]
            m += 1

    return C, L
```

### Complexity and Output

The algorithm runs in O(n^2) time over GF(2). With n = 2L input bits, it recovers the unique shortest LFSR of length L. With fewer than 2L bits, it may find a shorter LFSR that matches the observed bits but is not the original.

### What It Means for Security

Any stream cipher whose keystream satisfies a linear recurrence over GF(2) of degree L can be broken using 2L known plaintext bits. Since every finite LFSR sequence satisfies some linear recurrence, this means any purely linear generator is broken.

Modern stream cipher design ensures that the keystream has linear complexity close to 2^(key length), making Berlekamp-Massey require an astronomically long sequence.

---

## 30. Cryptographic Failures from Bad PRNGs

### Debian OpenSSL (2008)

A Debian maintainer removed two lines from OpenSSL's random seed function that added process memory content to the entropy pool, reasoning that they caused Valgrind to report uninitialized memory reads. The result: the only source of entropy was the process ID (PID), which on Linux is at most 32768.

Every RSA key, DSA key, and TLS session key generated on Debian-based systems between September 2006 and May 2008 was one of at most 32768 possibilities. Researchers precomputed all keys and published lookup tables. The private key corresponding to any affected public key was trivially recoverable.

The scope: all Debian and Ubuntu systems, any system using Debian's OpenSSL package. Millions of systems had their SSH host keys, TLS certificates, and OpenPGP keys compromised. The remediation required revoking and regenerating all keys on every affected system.

### Android Bitcoin Wallet (2013)

Android's SecureRandom implementation on certain devices failed to seed the Java SecureRandom from `/dev/urandom`. Instead, only a low-entropy seed was used, resulting in multiple transactions signed with the same ECDSA nonce k.

As shown in the birthday problem section, repeated ECDSA nonces directly expose the private key. Attackers monitored the Bitcoin blockchain for signatures with matching r values (which reveals nonce reuse), recovered private keys using the formula above, and drained affected wallets.

### Netscape SSL (1995)

The first version of Netscape Navigator seeded its PRNG with the time of day in seconds, the process ID, and the parent process ID. Ian Goldberg and David Wagner analyzed this: the seed space was approximately 2^40. Using parallel hardware available at the time, they cracked a live Netscape SSL session in under a minute. This was the first public demonstration that PRNG weakness could break real-world cryptography, and it motivated much of the subsequent work on proper entropy collection.

### Sony PlayStation 3 (2010)

Sony's PlayStation 3 firmware signed game executables using ECDSA. The signature verification was correct, but the signing code used a constant value for the nonce k instead of generating it randomly. When researchers observed two signatures on different messages with the same r value, they immediately recovered Sony's private signing key. This allowed anyone to sign arbitrary code as Sony, breaking the console's security model entirely.

---

## 31. Dual EC DRBG and the NSA Backdoor

Dual EC DRBG (Dual Elliptic Curve Deterministic Random Bit Generator) was standardized by NIST in 2006. Snowden documents revealed in 2013 that the NSA had deliberately inserted a backdoor.

### How It Works

Choose an elliptic curve E over a prime field (specifically P-256). Choose two curve points P and Q specified as constants in the standard. The generator has internal state s (an integer).

```
r_i    = (s_i * P).x         # x-coordinate of s_i * P, mod p
s_{i+1} = (r_i * P).x         # next state
output_i = truncate((r_i * Q).x, to 240 bits)
```

### The Backdoor

If the constants P and Q were chosen such that Q = e * P for some scalar e known to the backdoor inserter, then:

Given 32 bytes (240 bits) of output, guess the remaining 16 possible values of r_i (the truncated bits give 2^16 candidates for the full x-coordinate, and each x-coordinate has 2 possible points on the curve).

For each candidate r_i, compute e * r_i * P = e * s_i * P = s_i * (e * P) = s_i * Q. The x-coordinate of this point is s_{i+1}, the next state. Among the 32 candidates, one will match the next output chunk, revealing the full internal state.

With the backdoor key e, an eavesdropper who sees 32 bytes of any Dual EC output can predict all future output from that generator.

The discrete log problem (finding e given P and Q) is computationally infeasible without knowing e in advance. So only the NSA had the key.

Daniel Shumow and Niels Ferguson pointed out this potential backdoor at Crypto 2007, a year after standardization. The mathematics was unambiguous; the only question was whether it was intentional. The Snowden documents confirmed it was.

The RSA Security company used Dual EC DRBG as the default generator in their BSAFE library, reportedly after receiving 10 million dollars from the NSA. BSAFE was used in many commercial products.

NIST withdrew Dual EC DRBG from SP 800-90A Revision 1 in 2014.

---

## 32. Testing Randomness: NIST, Diehard, TestU01

### NIST SP 800-22

A battery of 15 statistical tests applied to bit strings of length at least 10^6 bits:

1. Frequency: proportion of 1s should be close to 1/2
2. Frequency within blocks: same, within M-bit blocks (M typically 128)
3. Runs: number of uninterrupted runs of 0s or 1s
4. Longest run in a block: longest run of 1s in 8-bit blocks
5. Binary matrix rank: rank distribution of 32x32 binary matrices from the sequence
6. Discrete Fourier transform: no periodic features
7. Non-overlapping template matching: count occurrences of a specific m-bit pattern
8. Overlapping template matching: similar but windows slide by 1 each step
9. Maurer's universal test: tests compressibility (low compressibility = random)
10. Linear complexity: length of the shortest LFSR generating the sequence
11. Serial: frequencies of overlapping m-bit and (m+1)-bit patterns compared
12. Approximate entropy: compare block frequencies for blocks of length m and m+1
13. Cumulative sums (forward and backward)
14. Random excursions: statistics of a random walk derived from the sequence
15. Random excursions variant: 18 additional statistics on the same random walk

The tests produce p-values; a good generator should have p-values uniformly distributed in [0,1] over many independent sequences.

### Diehard Battery (Marsaglia, 1995)

Twelve tests including birthday spacings, overlapping permutations, binary matrix ranks, and monkey tests. It was the standard for a decade but misses failures that are detectable by more sensitive modern tests.

### TestU01 (L'Ecuyer and Simard, 2007)

The modern standard. Contains hundreds of tests organized into batteries:

**SmallCrush**: 10 tests, runs in seconds.
**Crush**: 96 tests, runs in minutes.
**BigCrush**: 106 tests, runs in hours, the gold standard.

BigCrush detects failures that Diehard misses, including linear complexity (which catches MT19937) and higher-dimensional uniformity tests.

Results of interest:

- MT19937 fails 2 tests in BigCrush (the linear complexity and matrix rank tests)
- Xorshift32 fails 11 tests
- Java's LCG (48-bit) fails many tests
- Xoshiro256** passes all BigCrush tests
- KISS99 (a Marsaglia generator) passes all BigCrush tests

**Important caveat**: passing all statistical tests does not imply cryptographic security. MT19937 is completely predictable after 624 outputs despite having only minor BigCrush failures. Statistical tests measure "outputs look uniform"; cryptography requires "outputs are computationally indistinguishable from uniform by a computationally bounded adversary." These are fundamentally different requirements.

---

## 33. Implementation in Code

### Python: LCG

```python
class LCG:
    def __init__(self, seed, a=1664525, c=1013904223, m=2**32):
        self.state = seed
        self.a = a
        self.c = c
        self.m = m

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def next_float(self):
        return self.next() / self.m

lcg = LCG(seed=42)
print([lcg.next() for _ in range(5)])
```

### Python: LFSR

```python
def lfsr_maximal(state, taps, n):
    """
    n-bit LFSR with given tap positions (1-indexed from LSB).
    Returns one bit and updates state.
    taps: list of tap positions, e.g., [1, 4] for x^4 + x + 1
    """
    feedback = 0
    for t in taps:
        feedback ^= (state >> (t - 1)) & 1
    output_bit = state & 1
    state = (state >> 1) | (feedback << (n - 1))
    return output_bit, state

# 4-bit LFSR, polynomial x^4 + x + 1, taps at 1 and 4
state = 0b1101  # initial state
sequence = []
for _ in range(20):
    bit, state = lfsr_maximal(state, taps=[1, 4], n=4)
    sequence.append(bit)
print("LFSR output:", sequence)
# First 15 bits should be a de Bruijn-like maximal sequence
```

```python
def galois_lfsr(state, poly_mask):
    """
    Galois LFSR implementation.
    poly_mask: bitmask of feedback taps (excluding the implicit x^n term).
    """
    lsb = state & 1
    state >>= 1
    if lsb:
        state ^= poly_mask
    return lsb, state

# 16-bit LFSR: x^16 + x^14 + x^13 + x^11 + 1
# poly_mask = bit positions 14, 13, 11 (0-indexed): (1<<13)|(1<<12)|(1<<10)
poly = (1 << 13) | (1 << 12) | (1 << 10)
state = 0xACE1
bits = []
for _ in range(32):
    bit, state = galois_lfsr(state, poly)
    bits.append(bit)
print("Galois LFSR bits:", bits[:16])
```

### Python: Xorshift64

```python
def xorshift64(state):
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= (state >> 7)
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state

state = 123456789
for _ in range(5):
    state = xorshift64(state)
    print(state)
```

### Python: MT19937 State Recovery

```python
def untemper(y):
    # Invert each tempering operation in reverse order
    # Invert: y ^= y >> 18
    y ^= y >> 18
    # Invert: y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # Invert: y ^= (y << 7) & 0x9D2C5680  (iterative because of overlap)
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp
    # Invert: y ^= y >> 11  (iterative)
    tmp = y
    for _ in range(2):
        tmp = y ^ (tmp >> 11)
    return tmp & 0xFFFFFFFF

import random

rng = random.Random(seed=999)
outputs = [rng.getrandbits(32) for _ in range(624)]

# Recover internal state
recovered_state = [untemper(y) for y in outputs]
recovered_state.append(624)  # append the index

# Clone
clone = random.Random()
clone.setstate((3, tuple(recovered_state), None))

# Verify
for i in range(20):
    real = rng.getrandbits(32)
    predicted = clone.getrandbits(32)
    assert real == predicted
print("All 20 future outputs correctly predicted from MT state recovery.")
```

### Python: Berlekamp-Massey

```python
def berlekamp_massey(s):
    """Find shortest LFSR over GF(2) generating binary sequence s."""
    n = len(s)
    C = [1]
    B = [1]
    L = 0
    m = 1

    for i in range(n):
        d = s[i]
        for j in range(1, L + 1):
            if j < len(C):
                d ^= C[j] & s[i - j]
        d &= 1

        if d == 0:
            m += 1
        elif 2 * L <= i:
            T = C[:]
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= B[j]
            L = i + 1 - L
            B = T
            m = 1
        else:
            while len(C) < len(B) + m:
                C.append(0)
            for j in range(len(B)):
                C[j + m] ^= B[j]
            m += 1

    return C, L

# Known sequence from x^4 + x + 1 LFSR
seq = [1,1,0,1,0,0,0,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,1,0,1,0]
poly, length = berlekamp_massey(seq)
print(f"Recovered LFSR length: {length}")
print(f"Connection polynomial coefficients: {poly}")
# Expect: length=4, poly=[1, 0, 0, 1, 1] meaning x^4 + x + 1
# (C[k] is the coefficient of x^k, C[0]=1 always)
```

### C: LCG and Galois LFSR

```c
#include <stdint.h>
#include <stdio.h>

/* LCG: 64-bit state, returns upper 32 bits */
typedef struct { uint64_t state; } LCG;

uint32_t lcg_next(LCG *lcg) {
    lcg->state = 6364136223846793005ULL * lcg->state
                 + 1442695040888963407ULL;
    return (uint32_t)(lcg->state >> 33);
}

/* Galois LFSR: 32-bit */
typedef struct { uint32_t state; } GLFSR;

uint32_t glfsr_next_bit(GLFSR *g) {
    uint32_t lsb = g->state & 1;
    g->state >>= 1;
    /* Primitive polynomial x^32 + x^22 + x^2 + x + 1 */
    if (lsb) g->state ^= 0x80200003u;
    return lsb;
}

int main(void) {
    LCG lcg = { .state = 42 };
    for (int i = 0; i < 5; i++)
        printf("LCG: %u\n", lcg_next(&lcg));

    GLFSR lfsr = { .state = 0xACE1u };
    for (int i = 0; i < 16; i++)
        printf("LFSR bit: %u\n", glfsr_next_bit(&lfsr));

    return 0;
}
```

### Using Cryptographic Randomness (Python)

```python
import secrets
import os

# 32 cryptographically random bytes
b = secrets.token_bytes(32)
print(b.hex())

# Random integer in [0, n)
n = secrets.randbelow(2**128)

# URL-safe token (for session tokens, CSRF tokens, etc.)
token = secrets.token_urlsafe(32)  # 43 base64url characters

# From OS directly
raw = os.urandom(32)

# Constant-time comparison (important for authentication tokens)
a = secrets.token_bytes(16)
b_copy = a
if secrets.compare_digest(a, b_copy):
    print("Match (safe from timing attacks)")
```

---

## 34. Summary Table

| Generator       | State bits | Period              | Cryptographic | Notes                                    |
|-----------------|-----------|---------------------|---------------|------------------------------------------|
| LCG (32-bit)    | 32        | up to 2^32          | No            | 2-3 outputs reconstruct state            |
| LCG (48-bit)    | 48        | up to 2^48          | No            | Java Random; lattice attack from 2 outputs|
| Lehmer (MINSTD) | 31        | 2^31 - 2            | No            | Output = state                           |
| LFG             | k words   | ~2^(k*word_bits)    | No            | Good period, poor seeding sensitivity    |
| Xorshift32      | 32        | 2^32 - 1            | No            | Linear over GF(2); Berlekamp-Massey      |
| Xorshift64      | 64        | 2^64 - 1            | No            | Linear over GF(2)                        |
| Xoshiro256**    | 256       | 2^256 - 1           | No            | Passes BigCrush; not secure              |
| MT19937         | 19937     | 2^19937 - 1         | No            | 624 outputs reconstruct state            |
| LFSR (n-bit)    | n         | 2^n - 1             | No            | 2n bits + BM algorithm breaks it         |
| RC4             | 2064      | ~2^1700             | Broken        | Initial byte bias; statistical biases    |
| ChaCha20        | 512       | 2^70 bytes/key      | Yes           | TLS 1.3, Linux CSPRNG                    |
| BBS             | log2(n)   | large               | Yes (slow)    | Reduction to factoring; impractical      |
| Hash-DRBG       | seedlen   | unlimited w/ reseed | Yes           | NIST SP 800-90A                          |
| HMAC-DRBG       | key+V     | unlimited w/ reseed | Yes           | NIST SP 800-90A; clean security proof    |
| CTR-DRBG        | key+ctr   | unlimited w/ reseed | Yes           | NIST SP 800-90A; fast with AES           |
| Fortuna         | varies    | unlimited w/ reseed | Yes           | macOS, FreeBSD; 32 pools                 |

---

## Further Reading

Knuth, "The Art of Computer Programming, Volume 2: Seminumerical Algorithms" - the definitive treatment of LCG theory, the spectral test, and the Hull-Dobell theorem.

Schneier, Ferguson, Kohno, "Cryptography Engineering" - practical CSPRNG design including full specification of Fortuna.

Goldreich, "Foundations of Cryptography" - formal definitions of pseudorandomness, the next-bit test, and Yao's theorem.

Matsumoto and Nishimura, "Mersenne Twister: A 623-Dimensionally Equidistributed Uniform Pseudo-Random Number Generator" (1998).

Marsaglia, "Xorshift RNGs" (2003) - original xorshift paper with the GF(2) analysis.

Blackman and Vigna, "Scrambled Linear Pseudorandom Number Generators" (2021) - the xoshiro/xoroshiro family with jump functions.

L'Ecuyer and Simard, "TestU01: A C Library for Empirical Testing of Random Number Generators" (2007).

NIST SP 800-90A Revision 1 (2015) - the DRBG standard, post-Dual EC.

Shumow and Ferguson, "On the Possibility of a Back Door in the NIST SP800-90 Dual EC PRNG" (2007).

Bernstein, "ChaCha, a variant of Salsa20" (2008).

Siegenthaler, "Correlation-Immunity of Nonlinear Combining Functions for Cryptographic Applications" (1984) - the theorem on the tradeoff between correlation immunity and algebraic degree.

Flajolet and Odlyzko, "Random Mapping Statistics" (1990) - rigorous analysis of period and tail length in random functions.
