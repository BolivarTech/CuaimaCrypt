# CuaimaCrypt

A symmetric hybrid cipher engine combining block cipher and stream cipher
techniques, operating on 128-bit blocks. Security is scalable through the
addition of processing blocks (RakeCodecs).

This Rust crate is a byte-for-byte compatible port of the original Java
implementation in [BTCrypto](https://github.com/BolivarTech/BTCrypto).
Data encrypted with the Java version can be decrypted by this crate and
vice versa.

## Architecture

```text
ShiftCodec  (atomic unit - 64-bit shift register with non-linear feedback)
    | chained (upchain / downchain)
RakeCodec   (groups 4 ShiftCodecs - processes 128 bits)
    | N blocks in cascade with CrossByte between them
CuaimaCrypt (orchestrator - Walsh + Interleaving + N RakeCodecs + SeedHopping)
```

Each `CuaimaCrypt` instance contains N `RakeCodec` blocks (default 9) arranged
in cascade. Between each pair of RakeCodecs, a CrossByte permutation mixes the
block halves. Before and after the cascade, Walsh spread-spectrum XOR and
Interleaving/DeInterleaving add diffusion. After each block operation, all
ShiftCodec states advance and a SeedHopping permutation swaps states across the
entire system, giving the cipher stream-cipher properties.

## Usage

```rust
use cuaimacrypt::CuaimaCrypt;

// Encrypt
let mut encoder = CuaimaCrypt::new();
encoder.password("my_secret_password").unwrap();

let mut block: [i64; 2] = [0x0123456789ABCDEF_u64 as i64,
                            0xFEDCBA9876543210_u64 as i64];
encoder.codec(&mut block);
// block now contains ciphertext

// Decrypt (separate instance, same password)
let mut decoder = CuaimaCrypt::new();
decoder.password("my_secret_password").unwrap();

decoder.decodec(&mut block);
// block is restored to original plaintext
```

### Custom Security Level

Increase the number of RakeCodecs for higher security at the cost of throughput:

```rust
use cuaimacrypt::CuaimaCrypt;

let mut cc = CuaimaCrypt::with_num_rakes(16).unwrap(); // 2..=1024
cc.password("my_secret_password").unwrap();
```

## Cross-Compatibility with Java

This crate produces identical output to the Java `CuaimaCrypt` class in BTCrypto
v3.1.0. The cross-compatibility test suite validates:

- Identical seed derivation from the same password
- Identical ciphertext for sequential block encryption
- Rust can decrypt ciphertext produced by Java
- Multi-block sequential behavior matches exactly

Run the cross-compatibility tests:

```bash
cargo test --test cross_compat
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test           # all tests
cargo test --lib     # unit tests only
cargo test --test cross_compat  # cross-compatibility tests
```

## Benchmarks

```bash
cargo bench
```

## License

[CC-BY-SA-4.0](LICENSE.md) - Julian Bolivar, BolivarTech
