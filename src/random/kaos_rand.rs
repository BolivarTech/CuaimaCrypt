//! KAOSrand: Chaotic PRNG using 20 Lorenz attractors.
//!
//! Produces non-periodic pseudorandom sequences by combining the outputs
//! of 20 independent Lorenz attractor systems, replicating the Java
//! `KAOSrand` from BTUtils.
//!
//! When initialized via a [`Sparker`], the attractor initial points are
//! deterministic, enabling reproducible output for key derivation.

use super::lorenz::{Attractor, LorenzAttractor};
use super::mersenne_twister::MersenneTwisterPlus;
use super::sparker::Sparker;

/// Number of Lorenz attractors used in the system.
const NUM_ATTRACTORS: usize = 20;

/// Maximum jump value (limits attractor iterations per sample).
const LIMIT: i32 = 25;

/// Mask for 63-bit positive values.
const MASK: i64 = 0x7FFFFFFFFFFFFFFF_u64 as i64;

/// Chaotic PRNG using 20 Lorenz attractors.
///
/// Produces non-periodic pseudorandom sequences by combining the coordinate
/// outputs of 20 independent Lorenz attractor systems. The attractor states
/// are XOR-combined using their IEEE-754 mantissa bits.
///
/// # Initialization
///
/// When constructed with a [`Sparker`] (via [`from_sparker`](Self::from_sparker)),
/// the initial points and jump count are derived deterministically from the
/// sparker, enabling reproducible sequences for cryptographic key derivation.
pub struct KaosRand {
    attractors: Vec<LorenzAttractor>,
    rnd: MersenneTwisterPlus,
    jump: i32,
}

impl KaosRand {
    /// Creates a new KaosRand initialized from a Sparker.
    ///
    /// Reads 1 ShortSpark for the jump count, then 60 DoubleSparks
    /// (20 attractors x 3 coordinates) from the sparker. Each attractor
    /// is assigned its predefined type (0..19) and advanced by `jump` steps.
    ///
    /// # Parameters
    /// - `sparker`: A Sparker providing deterministic seed values.
    pub fn from_sparker(sparker: &mut dyn Sparker) -> Self {
        let rnd = MersenneTwisterPlus::new();
        let mut attractors = Vec::with_capacity(NUM_ATTRACTORS);

        // Create 20 attractors with predefined types
        for i in 0..NUM_ATTRACTORS {
            let mut attractor = LorenzAttractor::default();
            attractor.set_attractor_type(i);
            attractors.push(attractor);
        }

        // Read jump from sparker (modulo LIMIT)
        // BUG-001 fix: ensure jump >= 1 so attractors always advance deterministically.
        // When raw_spark % LIMIT == 0 (~4% of passwords), derive jump from the quotient.
        let raw_spark = sparker.get_short_spark() as i32;
        let mut jump = raw_spark % LIMIT;
        if jump <= 0 {
            jump = (raw_spark / LIMIT) % (LIMIT - 1) + 1;
        }

        // Initialize each attractor with coordinates from sparker
        for attractor in attractors.iter_mut() {
            let xo = 255.0 * sparker.get_double_spark();
            let yo = 255.0 * sparker.get_double_spark();
            let zo = 255.0 * sparker.get_double_spark();
            attractor.set_initial_point(xo, yo, zo);

            // Advance each attractor by jump steps
            for _ in 0..jump {
                attractor.next_point();
            }
        }

        KaosRand {
            attractors,
            rnd,
            jump,
        }
    }

    /// Generates the next pseudorandom double in range [0, 1).
    ///
    /// For each of the 20 attractors:
    /// 1. Advances by `jump` steps (or random steps if not sparkerized).
    /// 2. Extracts X, Y, Z coordinates.
    /// 3. Takes the absolute fractional part of each coordinate.
    /// 4. Extracts the 52-bit IEEE-754 mantissa.
    /// 5. XOR-accumulates with 12-bit left shifts.
    ///
    /// Finally masks to 53 bits and normalizes to [0, 1).
    pub fn next_double(&mut self) -> f64 {
        let k = 3; // 3 coordinates per attractor
        let total_coords = k * self.attractors.len();
        let mut coordenada = vec![0.0f64; total_coords];

        // Advance attractors and collect coordinates
        for i in 0..self.attractors.len() {
            if self.jump <= 0 {
                // Random mode: advance by random amount
                let steps = (self.rnd.next_short() as i32) % LIMIT;
                for _ in 0..steps {
                    self.attractors[i].next_point();
                }
            } else {
                // Sparkerized mode: advance by fixed jump
                for _ in 0..self.jump {
                    self.attractors[i].next_point();
                }
            }

            coordenada[k * i] = self.attractors[i].x();
            coordenada[k * i + 1] = self.attractors[i].y();
            coordenada[k * i + 2] = self.attractors[i].z();
        }

        // Extract fractional parts (absolute value)
        for coord in coordenada.iter_mut() {
            if *coord < 0.0 {
                *coord *= -1.0;
            }
            *coord -= (*coord as i64) as f64;
        }

        // XOR-accumulate mantissa bits with 12-bit shifts
        let mut aleatorios: i64 = 0;
        for coord in &coordenada {
            aleatorios <<= 12;
            aleatorios ^= (f64::to_bits(*coord) as i64) & 0x000F_FFFF_FFFF_FFFF;
        }

        // Mask to 53 bits and normalize to [0, 1)
        aleatorios &= 0x001F_FFFF_FFFF_FFFF;
        aleatorios as f64 * (1.0 / 9007199254740991.0)
    }

    /// Generates a pseudorandom long in range [0, 2^63-1].
    ///
    /// Matches Java: `(long)(Mask * nextDouble())`
    pub fn next_long(&mut self) -> i64 {
        (MASK as f64 * self.next_double()) as i64
    }

    /// Generates a 31-bit non-negative pseudorandom integer.
    ///
    /// Matches Java: `(int)((Mask >>> 33) * nextDouble())`
    fn next_int_31(&mut self) -> i32 {
        let mask_shifted = ((MASK as u64) >> 33) as i64;
        (mask_shifted as f64 * self.next_double()) as i32
    }

    /// Generates a bounded pseudorandom integer in range [0, n).
    ///
    /// Uses the same rejection sampling as Java `KAOSrand.nextInt(int n)`.
    ///
    /// # Parameters
    /// - `n`: The exclusive upper bound (must be positive).
    pub fn next_int_bounded(&mut self, n: i32) -> i32 {
        if n <= 0 {
            return 0;
        }
        // Power of 2 optimization
        if (n & n.wrapping_neg()) == n {
            return (((n as i64) * (self.next_int_31() as i64)) >> 31) as i32;
        }
        // Rejection sampling
        loop {
            let bits = self.next_int_31();
            let val = bits % n;
            if bits - val + (n - 1) >= 0 {
                return val;
            }
        }
    }
}

impl Drop for KaosRand {
    /// Securely clears all internal state on drop.
    ///
    /// Clears the jump counter explicitly. The `attractors` vector and `rnd`
    /// field are cleared by their own `Drop` implementations when this
    /// struct is dropped.
    fn drop(&mut self) {
        self.jump = 0;
        // LorenzAttractor::drop clears each attractor's coordinates and parameters.
        // MersenneTwisterPlus::drop clears the PRNG state vector and seed.
        // Both are invoked automatically by Rust's drop glue after this block.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::password_sparker::PasswordSparker;

    #[test]
    fn test_from_sparker_creates_valid_instance() {
        let mut sparker = PasswordSparker::new("TestPassword");
        let kaos = KaosRand::from_sparker(&mut sparker);
        assert_eq!(kaos.attractors.len(), NUM_ATTRACTORS);
    }

    #[test]
    fn test_next_double_range() {
        let mut sparker = PasswordSparker::new("TestPassword");
        let mut kaos = KaosRand::from_sparker(&mut sparker);
        for _ in 0..100 {
            let val = kaos.next_double();
            assert!(
                (0.0..1.0).contains(&val),
                "next_double out of range: {}",
                val
            );
        }
    }

    #[test]
    fn test_next_int_bounded_range() {
        let mut sparker = PasswordSparker::new("TestPassword");
        let mut kaos = KaosRand::from_sparker(&mut sparker);
        for _ in 0..100 {
            let val = kaos.next_int_bounded(10);
            assert!(
                (0..10).contains(&val),
                "next_int_bounded out of range: {}",
                val
            );
        }
    }

    #[test]
    fn test_next_int_bounded_power_of_two() {
        let mut sparker = PasswordSparker::new("TestPassword");
        let mut kaos = KaosRand::from_sparker(&mut sparker);
        for _ in 0..100 {
            let val = kaos.next_int_bounded(32);
            assert!(
                (0..32).contains(&val),
                "bounded power-of-2 out of range: {}",
                val
            );
        }
    }

    #[test]
    fn test_next_long_non_negative() {
        let mut sparker = PasswordSparker::new("TestPassword");
        let mut kaos = KaosRand::from_sparker(&mut sparker);
        for _ in 0..100 {
            let val = kaos.next_long();
            assert!(val >= 0, "next_long returned negative: {}", val);
        }
    }

    #[test]
    fn test_deterministic_output() {
        let mut sparker1 = PasswordSparker::new("TestPassword");
        let mut kaos1 = KaosRand::from_sparker(&mut sparker1);

        let mut sparker2 = PasswordSparker::new("TestPassword");
        let mut kaos2 = KaosRand::from_sparker(&mut sparker2);

        for _ in 0..20 {
            assert_eq!(kaos1.next_double(), kaos2.next_double());
        }
    }

    #[test]
    fn test_different_passwords_different_output() {
        let mut sparker1 = PasswordSparker::new("Password1");
        let mut kaos1 = KaosRand::from_sparker(&mut sparker1);

        let mut sparker2 = PasswordSparker::new("Password2");
        let mut kaos2 = KaosRand::from_sparker(&mut sparker2);

        // At least one of the first 5 doubles should differ
        let mut all_same = true;
        for _ in 0..5 {
            if kaos1.next_double() != kaos2.next_double() {
                all_same = false;
                break;
            }
        }
        assert!(
            !all_same,
            "Different passwords should produce different output"
        );
    }

    // ── BUG-001 regression tests ──────────────────────────────────────

    /// Verifies that `jump` is always >= 1 after `from_sparker`, even for
    /// passwords whose first `get_short_spark() % 25 == 0`.
    /// BUG-001: jump == 0 causes non-deterministic attractor advancement.
    #[test]
    fn test_jump_minimum_one_for_zero_spark_passwords() {
        // These passwords produce get_short_spark() values divisible by 25
        let bad_passwords = ["SizeSweep_4", "Pow2Sweep_512", "Pow2Sweep_2048"];
        for password in bad_passwords {
            let mut sparker = PasswordSparker::new(password);
            let kaos = KaosRand::from_sparker(&mut sparker);
            assert!(
                kaos.jump >= 1,
                "jump must be >= 1 for password '{}', got {}",
                password,
                kaos.jump
            );
        }
    }

    /// Verifies that two KaosRand instances initialized with a zero-jump
    /// password produce identical `next_double()` sequences.
    /// BUG-001: system-time-seeded MT causes divergence when jump == 0.
    ///
    /// Captures all values from each first instance before creating the
    /// second, ensuring a time gap that exposes the system-time seed bug.
    #[test]
    fn test_deterministic_output_zero_jump_password() {
        let bad_passwords = ["SizeSweep_4", "Pow2Sweep_512", "Pow2Sweep_2048"];

        // Phase 1: create all first instances and capture their outputs
        let all_expected: Vec<(&str, Vec<f64>)> = bad_passwords
            .iter()
            .map(|&pw| {
                let mut sparker = PasswordSparker::new(pw);
                let mut kaos = KaosRand::from_sparker(&mut sparker);
                let values: Vec<f64> = (0..50).map(|_| kaos.next_double()).collect();
                (pw, values)
            })
            .collect();

        // Phase 2: create second instances and verify (time gap from Phase 1)
        for (password, expected) in &all_expected {
            let mut sparker = PasswordSparker::new(password);
            let mut kaos = KaosRand::from_sparker(&mut sparker);

            for (step, &exp) in expected.iter().enumerate() {
                assert_eq!(
                    kaos.next_double(),
                    exp,
                    "next_double() diverged at step {} for password '{}'",
                    step,
                    password
                );
            }
        }
    }

    /// Verifies that `next_long()` and `next_int_bounded()` are also
    /// deterministic for zero-jump passwords.
    /// BUG-001: all KaosRand output methods depend on the same attractor state.
    ///
    /// Captures all values from the first instance, waits 2ms to guarantee
    /// a different system-time seed, then creates the second instance.
    #[test]
    fn test_deterministic_next_long_zero_jump_password() {
        let bad_passwords = ["SizeSweep_4", "Pow2Sweep_512", "Pow2Sweep_2048"];

        // Phase 1: capture next_long values for all bad passwords
        let expected_longs: Vec<(&str, Vec<i64>)> = bad_passwords
            .iter()
            .map(|&pw| {
                let mut sparker = PasswordSparker::new(pw);
                let mut kaos = KaosRand::from_sparker(&mut sparker);
                let values: Vec<i64> = (0..30).map(|_| kaos.next_long()).collect();
                (pw, values)
            })
            .collect();

        // Guarantee a different system-time millisecond for Phase 2
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Phase 2: verify second instances produce the same values
        for (password, expected) in &expected_longs {
            let mut sparker = PasswordSparker::new(password);
            let mut kaos = KaosRand::from_sparker(&mut sparker);

            for (step, &exp) in expected.iter().enumerate() {
                assert_eq!(
                    kaos.next_long(),
                    exp,
                    "next_long() diverged at step {} for password '{}'",
                    step,
                    password
                );
            }
        }

        // Phase 3: capture next_int_bounded values
        let expected_bounded: Vec<(&str, Vec<i32>)> = bad_passwords
            .iter()
            .map(|&pw| {
                let mut sparker = PasswordSparker::new(pw);
                let mut kaos = KaosRand::from_sparker(&mut sparker);
                let values: Vec<i32> = (0..30).map(|_| kaos.next_int_bounded(100)).collect();
                (pw, values)
            })
            .collect();

        std::thread::sleep(std::time::Duration::from_millis(2));

        // Phase 4: verify
        for (password, expected) in &expected_bounded {
            let mut sparker = PasswordSparker::new(password);
            let mut kaos = KaosRand::from_sparker(&mut sparker);

            for (step, &exp) in expected.iter().enumerate() {
                assert_eq!(
                    kaos.next_int_bounded(100),
                    exp,
                    "next_int_bounded(100) diverged at step {} for password '{}'",
                    step,
                    password
                );
            }
        }
    }
}
