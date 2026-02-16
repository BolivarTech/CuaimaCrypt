# CuaimaCrypt: Quantum Resilience Analysis

**Date:** 2026-02-16
**Applies to:** CuaimaCrypt v1.1.x (Java BTCrypto v3.1.0 / Rust cuaimacrypt crate)
**Author:** Julian Bolivar, BolivarTech

---

## 1. Executive Summary

CuaimaCrypt is **not formally quantum-resistant** in the post-quantum cryptography
(PQC) sense. However, its symmetric hybrid design provides inherent resilience
against known quantum attacks that significantly exceeds that of asymmetric
ciphers. This document analyzes why.

---

## 2. Quantum Attack Landscape

### 2.1 Shor's Algorithm — Does Not Apply

Shor's algorithm provides exponential speedup for factoring integers and computing
discrete logarithms. It breaks:

- **RSA** (integer factorization)
- **ECC / ECDSA** (elliptic curve discrete logarithm)
- **Diffie-Hellman** (discrete logarithm)
- **DSA** (discrete logarithm)

CuaimaCrypt is a **symmetric cipher**. It does not rely on factorization or
discrete logarithm problems. **Shor's algorithm has no effect on CuaimaCrypt.**

### 2.2 Grover's Algorithm — Quadratic Speedup Only

Grover's algorithm provides a quadratic speedup for unstructured search problems.
For a symmetric cipher with an N-bit key, Grover reduces the effective security
from 2^N to 2^(N/2) operations.

| Classical Security | Post-Grover Security |
|-------------------|---------------------|
| 128 bits          | 64 bits             |
| 256 bits          | 128 bits            |
| 512 bits          | 256 bits            |

The standard mitigation is to **double the key size**. AES-256, for example,
provides 128 bits of post-quantum security, which is considered sufficient by
NIST and the broader cryptographic community.

---

## 3. CuaimaCrypt Properties Relevant to Quantum Attacks

### 3.1 Massive Internal State

With the default configuration (9 RakeCodecs), CuaimaCrypt maintains:

- **36 ShiftCodecs** (4 per RakeCodec × 9 RakeCodecs)
- Each ShiftCodec has a **64-bit shift register** plus derived parameters
  (seed, pos_up, pos_down, win_a, win_b, shift_leap)
- **8 CrossByte permutation selectors** (between the 9 RakeCodecs)
- **36-element SeedHopping permutation sequence**
- **1 Walsh code selector** (128 possible codes)

The total internal state spans **thousands of bits**. A Grover search must
explore this entire state space, not just a single key.

### 3.2 Non-Linearity and State Dependence

Each block encryption operation **modifies the internal state** through:

1. **ShiftCodec advance** — non-linear feedback shift register (NLFSR) with
   cross-chain XOR from upchain and downchain neighbors
2. **SeedHopping** — permutation of ShiftCodec states across the entire system

This means there is no static function to invert. The cipher's behavior at
block N depends on the **entire history** of blocks 0 through N-1. Constructing
an efficient quantum oracle for Grover's algorithm requires modeling this
sequential state evolution, which dramatically increases the oracle's complexity
and circuit depth.

### 3.3 Scalable Security

CuaimaCrypt supports **2 to 1,024 RakeCodecs**. Increasing the count:

| RakeCodecs | ShiftCodecs | State Size (approx.) |
|-----------|-------------|---------------------|
| 2         | 8           | ~512 bits           |
| 9 (default) | 36       | ~2,304 bits         |
| 16        | 64          | ~4,096 bits         |
| 32        | 128         | ~8,192 bits         |
| 1024      | 4,096       | ~262,144 bits       |

Even with Grover's quadratic reduction, the effective post-quantum security
with higher rake counts remains well beyond practical attack thresholds.

### 3.4 Hybrid Block/Stream Design

Unlike pure block ciphers (AES, DES) that process each block independently
with the same key state, CuaimaCrypt's stream cipher property means:

- **Same plaintext, different ciphertext** — encrypting identical blocks
  at different positions produces different output
- **No codebook attacks** — frequency analysis on ciphertext blocks is
  infeasible
- **Sequential dependency** — an attacker cannot parallelize the attack
  across blocks without first solving the sequential state evolution

This sequential dependency is particularly problematic for quantum computers,
which benefit most from problems with high parallelism.

---

## 4. Comparison with AES-256

| Property | AES-256 | CuaimaCrypt (9 rakes) |
|----------|---------|----------------------|
| Type | Block cipher | Hybrid block/stream |
| Key size | 256 bits | Password-derived (thousands of state bits) |
| Block size | 128 bits | 128 bits |
| Internal state | 256 bits (key schedule) | ~2,304 bits |
| State evolution | Static (same key per block) | Dynamic (state advances per block) |
| Post-Grover security | 128 bits | Significantly higher (exact analysis pending) |
| NIST PQC status | Considered quantum-safe | Not formally analyzed |
| Formal cryptanalysis | Extensive | Limited |

---

## 5. Limitations and Caveats

CuaimaCrypt **cannot be classified as post-quantum** for the following reasons:

1. **No formal security proofs** — There is no reduction to a known
   quantum-hard computational problem.

2. **No NIST PQC evaluation** — CuaimaCrypt has not been submitted to or
   evaluated by the NIST Post-Quantum Cryptography standardization process.

3. **No peer-reviewed cryptanalysis** — The cipher has not undergone extensive
   public cryptanalysis by the academic cryptographic community.

4. **No concrete post-quantum security estimate** — While the internal state
   is large, the effective post-quantum security in bits has not been formally
   calculated.

5. **Key derivation considerations** — The password-based key derivation
   (PasswordSparker + KAOSrand) may have a smaller effective key space than
   the internal state suggests, depending on password entropy.

---

## 6. Conclusion

CuaimaCrypt's symmetric hybrid design places it in a fundamentally different
category than the asymmetric ciphers that Shor's algorithm destroys. Its
massive internal state, non-linear feedback, sequential state dependence,
and scalable security make it significantly more resilient to quantum attacks
than most conventional ciphers.

However, **resilience is not the same as proven resistance**. Until formal
cryptanalysis and quantum security proofs are completed, CuaimaCrypt should
be considered **quantum-resilient** (resistant to known quantum attacks by
design properties) rather than **quantum-resistant** (formally proven secure
against quantum adversaries).

For applications requiring certified post-quantum security today, CuaimaCrypt
should be used alongside NIST-standardized PQC algorithms (such as CRYSTALS-Kyber
for key exchange or CRYSTALS-Dilithium for signatures) in a hybrid configuration.

---

*This analysis is based on the current understanding of quantum computing
capabilities and known quantum algorithms as of 2026. The field of quantum
cryptanalysis is actively evolving.*
