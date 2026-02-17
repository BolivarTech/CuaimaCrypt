//! Random number generation subsystem for CuaimaCrypt.
//!
//! Provides the chaotic PRNG infrastructure based on Lorenz attractors
//! that drives CuaimaCrypt's key derivation function.

pub mod kaos_rand;
pub mod lorenz;
pub mod mersenne_twister;
pub mod password_sparker;
pub mod sparker;
