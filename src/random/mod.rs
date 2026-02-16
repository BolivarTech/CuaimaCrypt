//! Random number generation subsystem for CuaimaCrypt.
//!
//! Provides the chaotic PRNG infrastructure based on Lorenz attractors
//! that drives CuaimaCrypt's key derivation function.

pub(crate) mod kaos_rand;
pub(crate) mod lorenz;
pub(crate) mod mersenne_twister;
pub(crate) mod password_sparker;
pub(crate) mod sparker;
