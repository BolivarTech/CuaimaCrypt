//! Sparker trait for seed generation.
//!
//! Defines the interface for seed generators used to initialize the
//! KAOSrand PRNG. Implementations must generate deterministic sequences
//! of spark values from a given input (e.g., a password).

/// Trait for seed generators used to initialize random number algorithms.
///
/// Implementations produce deterministic sequences of typed "spark" values
/// that are consumed by [`KaosRand`](crate::random::kaos_rand::KaosRand)
/// during initialization. A valid sparker must provide at least 60
/// independent double sparks and 1 short spark greater than 0.
pub trait Sparker {
    /// Returns the next double-precision spark value.
    fn get_double_spark(&mut self) -> f64;

    /// Returns the next single-precision spark value.
    fn get_float_spark(&mut self) -> f32;

    /// Returns the next 64-bit integer spark value.
    fn get_long_spark(&mut self) -> i64;

    /// Returns the next 32-bit integer spark value.
    fn get_integer_spark(&mut self) -> i32;

    /// Returns the next 16-bit integer spark value.
    fn get_short_spark(&mut self) -> i16;

    /// Returns the next byte spark value.
    fn get_byte_spark(&mut self) -> u8;
}
