# CuaimaCrypt

[![Crates.io](https://img.shields.io/crates/v/cuaimacrypt.svg)](https://crates.io/crates/cuaimacrypt)
[![Documentation](https://docs.rs/cuaimacrypt/badge.svg)](https://docs.rs/cuaimacrypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Build Status](https://img.shields.io/github/actions/workflow/status/BolivarTech/CuaimaCrypt/ci.yml?branch=main)](https://github.com/BolivarTech/CuaimaCrypt/actions)

A symmetric hybrid cipher engine combining block cipher and stream cipher techniques, operating on 128-bit blocks. Security is scalable through the addition of processing blocks (RakeCodecs).

Byte-for-byte compatible with the original Java implementation in [BTCrypto](https://github.com/BolivarTech/BTCrypto) — data encrypted with Java can be decrypted by this crate and vice versa.

## Features

- **128-bit block encryption** with hybrid block/stream cipher design
- **Scalable security** — configure 2 to 1,024 RakeCodecs per instance
- **Stream cipher properties** — encrypting the same plaintext twice yields different ciphertext
- **Cross-platform interoperability** — certified compatible with Java BTCrypto v3.1.0
- **Zero external dependencies** — self-contained, no runtime deps
- **Zero `unsafe` code**

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
cuaimacrypt = "0.1"
```

### Encrypt and Decrypt

```rust
use cuaimacrypt::CuaimaCrypt;

// Encoder
let mut encoder = CuaimaCrypt::new();
encoder.password("my_secret_password").unwrap();

// Decoder (separate instance, same password)
let mut decoder = CuaimaCrypt::new();
decoder.password("my_secret_password").unwrap();

let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64,
                           0xFEDCBA9876543210_u64 as i64];
let mut block = original;

encoder.codec(&mut block);    // encrypt
assert_ne!(block, original);

decoder.decodec(&mut block);  // decrypt
assert_eq!(block, original);
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

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test                              # all tests (132 tests)
cargo test --lib                        # unit tests only
cargo test --test cross_compat          # cross-compatibility vectors
cargo test --test interop_certification # full interop certification
```

## Benchmarks

```bash
cargo bench
```

Benchmarks measure password initialization, single-block codec/decodec throughput, and throughput scaling across rake counts (2, 9, 16).

## Minimum Supported Rust Version

Rust 2021 edition (1.56+).

## License

[MIT](LICENSE.md) — Julian Bolivar, [BolivarTech](https://www.bolivartech.com)
