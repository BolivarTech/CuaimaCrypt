//! CuaimaCrypt symmetric hybrid cipher engine.
//!
//! CuaimaCrypt is a symmetric cipher that combines block cipher
//! and stream cipher techniques, operating on 128-bit blocks (two `i64` values).
//! Security is scalable through the addition of processing blocks (RakeCodecs).
//!
//! This crate provides the core encryption engine, compatible byte-for-byte
//! with the original Java implementation in BTCrypto.
//!
//! # Architecture
//!
//! ```text
//! ShiftCodec  (atomic unit — 64-bit shift register with non-linear feedback)
//!     ↕ chained (upchain / downchain)
//! RakeCodec   (groups 4 ShiftCodecs — processes 128 bits)
//!     ↕ N blocks in cascade with CrossByte between them
//! CuaimaCrypt (orchestrator — Walsh + Interleaving + N RakeCodecs + SeedHopping)
//! ```
//!
//! # Examples
//!
//! Encrypt and decrypt a 128-bit block:
//!
//! ```
//! use cuaimacrypt::CuaimaCrypt;
//!
//! let mut encoder = CuaimaCrypt::new();
//! encoder.password("my_secret_password").unwrap();
//!
//! let mut decoder = CuaimaCrypt::new();
//! decoder.password("my_secret_password").unwrap();
//!
//! let original: [i64; 2] = [42, 84];
//! let mut block = original;
//!
//! encoder.codec(&mut block);
//! assert_ne!(block, original);
//!
//! decoder.decodec(&mut block);
//! assert_eq!(block, original);
//! ```
//!
//! Use a custom number of RakeCodecs for higher security:
//!
//! ```
//! use cuaimacrypt::CuaimaCrypt;
//!
//! let mut cc = CuaimaCrypt::with_num_rakes(16).unwrap();
//! cc.password("my_secret_password").unwrap();
//!
//! let mut block: [i64; 2] = [1, 2];
//! cc.codec(&mut block);
//! ```

#![deny(clippy::all)]

pub mod error;

mod cuaimacrypt;
pub(crate) mod rake_codec;
pub(crate) mod random;
pub(crate) mod shift_codec;
pub(crate) mod utils;
pub(crate) mod walsh;

pub use cuaimacrypt::CuaimaCrypt;
