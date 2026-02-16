//! 64-bit Mersenne Twister PRNG (MT19937-64) with enhanced seeding.
//!
//! Implements the MersenneTwisterPlus algorithm from the Java BTUtils library,
//! providing a high-period (2^19937 - 1) pseudorandom number generator with
//! deterministic output for fixed seeds.

// TODO: Full implementation in Fase 1.4

/// 64-bit Mersenne Twister PRNG with period 2^19937-1.
///
/// When constructed with a fixed seed via [`with_seed`](Self::with_seed),
/// the output sequence is deterministic and matches the Java implementation
/// exactly. This deterministic mode is used by CuaimaCrypt during
/// password-based key derivation.
pub(crate) struct MersenneTwisterPlus {
    mt: [i64; 312],
    mti: usize,
    seed: i64,
    fixed_seed: bool,
    max_ciclo: i32,
    ciclo: i32,
}

impl MersenneTwisterPlus {
    /// Creates a new PRNG with a seed derived from system time.
    pub(crate) fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(5489);
        Self::with_seed(seed)
    }

    /// Creates a new PRNG with a fixed, deterministic seed.
    ///
    /// # Parameters
    /// - `seed`: The seed value for deterministic output.
    pub(crate) fn with_seed(seed: i64) -> Self {
        let mut mt = MersenneTwisterPlus {
            mt: [0i64; 312],
            mti: 313,
            seed,
            fixed_seed: true,
            max_ciclo: 0,
            ciclo: 0,
        };
        mt.init_genrand64();
        mt
    }

    /// Initializes the state vector from the seed.
    fn init_genrand64(&mut self) {
        self.mt[0] = self.seed;
        for i in 1..312 {
            let prev = self.mt[i - 1] as u64;
            let val = 6364136223846793005u64
                .wrapping_mul(prev ^ (prev >> 62))
                .wrapping_add(i as u64);
            self.mt[i] = val as i64;
        }
        self.mti = 312;

        // Calculate max_ciclo from seed
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        let damm_val = Self::calculate_damm(self.seed.unsigned_abs() as i64);
        if self.fixed_seed {
            self.max_ciclo = i32::MAX;
        } else {
            self.max_ciclo = ((self.seed.unsigned_abs() % 1000) as i32)
                + ((nano.unsigned_abs() % 1000) as i32)
                + damm_val;
        }
        self.ciclo = 0;
    }

    /// Generates the next 64-bit pseudorandom value.
    pub(crate) fn next_long(&mut self) -> i64 {
        const NN: usize = 312;
        const MM: usize = 156;
        const MATRIX_A: u64 = 0xB5026F5AA96619E9;
        const UM: u64 = 0xFFFFFFFF80000000; // upper 33 bits
        const LM: u64 = 0x7FFFFFFF; // lower 31 bits

        let mag01: [u64; 2] = [0, MATRIX_A];

        if self.mti >= NN {
            for i in 0..(NN - MM) {
                let x = ((self.mt[i] as u64) & UM) | ((self.mt[i + 1] as u64) & LM);
                self.mt[i] = (self.mt[i + MM] as u64 ^ (x >> 1) ^ mag01[(x & 1) as usize]) as i64;
            }
            for i in (NN - MM)..(NN - 1) {
                let x = ((self.mt[i] as u64) & UM) | ((self.mt[i + 1] as u64) & LM);
                self.mt[i] =
                    (self.mt[i + MM - NN] as u64 ^ (x >> 1) ^ mag01[(x & 1) as usize]) as i64;
            }
            let x = ((self.mt[NN - 1] as u64) & UM) | ((self.mt[0] as u64) & LM);
            self.mt[NN - 1] = (self.mt[MM - 1] as u64 ^ (x >> 1) ^ mag01[(x & 1) as usize]) as i64;
            self.mti = 0;
        }

        let mut x = self.mt[self.mti] as u64;
        self.mti += 1;

        // Tempering
        x ^= (x >> 29) & 0x5555555555555555;
        x ^= (x << 17) & 0x71D67FFFEDA60000;
        x ^= (x << 37) & 0xFFF7EEE000000000;
        x ^= x >> 43;

        self.ciclo += 1;
        if !self.fixed_seed && self.ciclo >= self.max_ciclo {
            self.seed = Self::gen_seed();
            self.init_genrand64();
        }

        x as i64
    }

    /// Generates a 63-bit non-negative pseudorandom value.
    pub(crate) fn next_long_63(&mut self) -> i64 {
        ((self.next_long() as u64) >> 1) as i64
    }

    /// Generates a bounded pseudorandom long in range [0, n).
    pub(crate) fn next_long_bounded(&mut self, n: i64) -> i64 {
        if n <= 0 {
            return 0;
        }
        let n_u = n as u64;
        // Power of 2 optimization
        if n_u & (n_u.wrapping_sub(1)) == 0 {
            return (n_u.wrapping_mul((self.next_long() as u64) >> 1) >> 63) as i64;
        }
        loop {
            let bits = ((self.next_long() as u64) >> 1) as i64;
            let val = bits % n;
            if bits - val + (n - 1) >= 0 {
                return val;
            }
        }
    }

    /// Generates a 32-bit pseudorandom integer.
    pub(crate) fn next_int(&mut self) -> i32 {
        ((self.next_long() as u64) >> 32) as i32
    }

    /// Generates a 31-bit non-negative pseudorandom integer.
    ///
    /// Equivalent to Java's `nextInt31()`: `(int)(nextLong() >>> 33)`.
    pub(crate) fn next_int_31(&mut self) -> i32 {
        ((self.next_long() as u64) >> 33) as i32
    }

    /// Generates a bounded pseudorandom integer in range [0, n).
    ///
    /// Uses rejection sampling to ensure uniform distribution.
    /// Matches Java `MersenneTwisterPlus.nextInt(int n)` exactly.
    pub(crate) fn next_int_bounded(&mut self, n: i32) -> i32 {
        if n <= 0 {
            return 0;
        }
        // Power of 2 optimization
        if (n & (n.wrapping_neg())) == n {
            return (((n as i64) * (self.next_int_31() as i64)) >> 31) as i32;
        }
        loop {
            let bits = self.next_int_31();
            let val = bits % n;
            if bits - val + (n - 1) >= 0 {
                return val;
            }
        }
    }

    /// Generates a pseudorandom double in range [0, 1).
    pub(crate) fn next_double(&mut self) -> f64 {
        ((self.next_long() as u64) >> 11) as f64 * (1.0 / 9007199254740991.0)
    }

    /// Generates a pseudorandom byte.
    pub(crate) fn next_byte(&mut self) -> u8 {
        ((self.next_long() as u64) >> 56) as u8
    }

    /// Generates a pseudorandom short.
    pub(crate) fn next_short(&mut self) -> i16 {
        ((self.next_long() as u64) >> 48) as i16
    }

    /// Fills a byte slice with pseudorandom values.
    pub(crate) fn next_bytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte = self.next_byte();
        }
    }

    /// Generates a seed from system time.
    fn gen_seed() -> i64 {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(5489);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0);
        millis ^ nanos
    }

    /// Computes the Damm check digit for a number.
    ///
    /// Uses the 10x10 anti-symmetric quasigroup matrix.
    fn calculate_damm(number: i64) -> i32 {
        #[rustfmt::skip]
        let antisymmetric: [[i32; 10]; 10] = [
            [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
            [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
            [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
            [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
            [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
            [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
            [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
            [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
            [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
            [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
        ];

        let abs_num = number.unsigned_abs();
        let digits = abs_num.to_string();
        let mut interim = 0usize;
        for ch in digits.chars() {
            let digit = ch as usize - '0' as usize;
            interim = antisymmetric[interim][digit] as usize;
        }
        interim as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_seed() {
        let mut mt1 = MersenneTwisterPlus::with_seed(12345);
        let mut mt2 = MersenneTwisterPlus::with_seed(12345);
        for _ in 0..100 {
            assert_eq!(mt1.next_long(), mt2.next_long());
        }
    }

    #[test]
    fn test_next_double_range() {
        let mut mt = MersenneTwisterPlus::with_seed(42);
        for _ in 0..1000 {
            let val = mt.next_double();
            assert!(val >= 0.0 && val < 1.0, "next_double out of range: {}", val);
        }
    }

    #[test]
    fn test_next_int_bounded() {
        let mut mt = MersenneTwisterPlus::with_seed(42);
        for _ in 0..1000 {
            let val = mt.next_int_bounded(10);
            assert!(
                val >= 0 && val < 10,
                "next_int_bounded out of range: {}",
                val
            );
        }
    }

    #[test]
    fn test_next_int_bounded_power_of_two() {
        let mut mt = MersenneTwisterPlus::with_seed(42);
        for _ in 0..1000 {
            let val = mt.next_int_bounded(16);
            assert!(
                val >= 0 && val < 16,
                "bounded power-of-2 out of range: {}",
                val
            );
        }
    }

    #[test]
    fn test_calculate_damm() {
        assert_eq!(MersenneTwisterPlus::calculate_damm(572), 4);
    }

    #[test]
    fn test_different_seeds_different_output() {
        let mut mt1 = MersenneTwisterPlus::with_seed(1);
        let mut mt2 = MersenneTwisterPlus::with_seed(2);
        let v1 = mt1.next_long();
        let v2 = mt2.next_long();
        assert_ne!(v1, v2);
    }
}
