# CuaimaCrypt

[![Crates.io](https://img.shields.io/crates/v/cuaimacrypt.svg)](https://crates.io/crates/cuaimacrypt)
[![Documentation](https://docs.rs/cuaimacrypt/badge.svg)](https://docs.rs/cuaimacrypt)
[![License](https://img.shields.io/crates/l/cuaimacrypt.svg)](LICENSE-MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/BolivarTech/CuaimaCrypt/ci.yml?branch=main)](https://github.com/BolivarTech/CuaimaCrypt/actions)

A symmetric hybrid cipher engine combining block cipher and stream cipher techniques, operating on 128-bit blocks. Security is scalable through the addition of processing blocks (RakeCodecs).

Byte-for-byte compatible with the original Java implementation in [BTCrypto](https://github.com/BolivarTech/BTCrypto) — data encrypted with Java can be decrypted by this crate and vice versa.

## Features

- **128-bit block encryption** with hybrid block/stream cipher design
- **Scalable security** — configure 2 to 1,024 RakeCodecs per instance
- **Stream cipher properties** — encrypting the same plaintext twice yields different ciphertext
- **Cross-platform interoperability** — certified compatible with Java BTCrypto v3.1.0
- **Secure memory zeroization** — all cryptographic state is cleared on drop
- **Zero external dependencies** — self-contained, no runtime deps
- **Zero `unsafe` code**

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
cuaimacrypt = "1.2"
```

### Encrypt and Decrypt

CuaimaCrypt operates on **128-bit blocks** represented as `[i64; 2]`. Each call to
`codec()` encrypts one block in-place and advances the internal state, so
encrypting the same plaintext twice produces **different ciphertext** (stream
cipher property). Encoder and decoder must process blocks in the same sequential
order.

```rust
use cuaimacrypt::CuaimaCrypt;

// Create separate encoder and decoder with the same password.
// Both instances derive identical initial state from the password.
let mut encoder = CuaimaCrypt::new();
encoder.password("my_secret_password").unwrap();

let mut decoder = CuaimaCrypt::new();
decoder.password("my_secret_password").unwrap();

// --- Single-block roundtrip ---
let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64,
                           0xFEDCBA9876543210_u64 as i64];
let mut block = original;

encoder.codec(&mut block);    // encrypt in-place
assert_ne!(block, original);  // ciphertext differs from plaintext

decoder.decodec(&mut block);  // decrypt in-place
assert_eq!(block, original);  // plaintext recovered

// --- Stream cipher property: same plaintext → different ciphertext ---
let mut block_a = original;
let mut block_b = original;

encoder.reset();  // rewind encoder state to initial position
encoder.codec(&mut block_a);  // encrypt block #1
encoder.codec(&mut block_b);  // encrypt block #2 (same plaintext)
assert_ne!(block_a, block_b); // ciphertext differs because state evolves

// --- Multi-block sequential encryption ---
encoder.reset();
decoder.reset();  // both must reset to stay synchronized

let data: [[i64; 2]; 3] = [[1, 2], [3, 4], [5, 6]];
let mut encrypted = data;

for blk in encrypted.iter_mut() {
    encoder.codec(blk);  // each call advances the cipher state
}

for blk in encrypted.iter_mut() {
    decoder.decodec(blk);  // decoder tracks the same state sequence
}

assert_eq!(encrypted, data);  // all blocks recovered
```

### Custom Security Level

Increase the number of RakeCodecs for higher security at the cost of throughput:

```rust
use cuaimacrypt::CuaimaCrypt;

let mut cc = CuaimaCrypt::with_num_rakes(16).unwrap(); // 2..=1024
cc.password("my_secret_password").unwrap();

let mut block: [i64; 2] = [1, 2];
cc.codec(&mut block);
```

## Architecture

```text
ShiftCodec   (atomic unit — 64-bit shift register with non-linear feedback)
    ↕ chained in ring topology (upchain / downchain)
RakeCodec    (groups 4 ShiftCodecs — processes one 128-bit block)
    ↕ N blocks in cascade with CrossByte permutations between them
CuaimaCrypt  (orchestrator — Walsh + Interleaving + N RakeCodecs + SeedHopping)
```

Each `CuaimaCrypt` instance contains **N RakeCodec blocks** (default 9) arranged in cascade. The encryption pipeline applies:

1. **Walsh spread-spectrum XOR** — diffusion via Walsh code
2. **Interleaving** — 8x8 matrix transposition mixing both block halves
3. **RakeCodec cascade** — N stages of non-linear block transformation with CrossByte permutations between stages
4. **ShiftCodec advance** — all shift registers advance with non-linear feedback
5. **SeedHopping** — state permutation across all ShiftCodecs (stream cipher property)

Decryption reverses the pipeline in exact inverse order.

## Java Interoperability

This crate produces **identical output** to the Java `CuaimaCrypt` class in BTCrypto v3.1.0. The interoperability test suite validates:

- Identical seed derivation from the same password
- Identical ciphertext for sequential block encryption
- Bidirectional decrypt: Java ciphertext decrypts in Rust and vice versa
- Multi-block sequential state evolution matches exactly
- Coverage across multiple passwords, rake counts, and Unicode

Run the interoperability tests:

```bash
cargo test --test interop_certification
cargo test --test cross_compat
```

See [`INTEROP_CERTIFICATION.md`](INTEROP_CERTIFICATION.md) for the full certification report.

## Quantum Resilience

CuaimaCrypt's symmetric hybrid design is inherently resilient against known quantum attacks. Shor's algorithm does not apply (symmetric cipher), and Grover's quadratic speedup is mitigated by the massive internal state (thousands of bits across 36+ ShiftCodecs) and non-linear sequential state evolution.

See [`QUANTUM_RESILIENCE.md`](QUANTUM_RESILIENCE.md) for the full technical analysis.

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test                              # all tests (195 tests)
cargo test --lib                        # unit tests only
cargo test --test cross_compat          # cross-compatibility vectors
cargo test --test interop_certification # full interop certification
cargo test --test regression_public_api # public API regression tests
```

## Benchmarks

```bash
cargo bench
```

Benchmarks measure password initialization, single-block codec/decodec throughput, and throughput scaling across rake counts (2, 9, 16).

## Minimum Supported Rust Version

Rust 2021 edition (1.56+).

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Copyright (c) 2024 Julian Bolivar, [BolivarTech](https://www.bolivartech.com)
