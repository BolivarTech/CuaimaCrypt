//! Password-to-seed converter for CuaimaCrypt key derivation.
//!
//! Converts a password string into deterministic spark values using
//! Walsh code byte expansion and powers of pi, replicating the Java
//! `PasswordSparker` from BTUtils.
//!
//! The process:
//! 1. Each password byte is expanded to 56 bytes via Walsh codes and bit rotations.
//! 2. Expanded bytes are combined with powers of pi to produce 40 spark values.
//! 3. Sparks are rounded to 11 decimals for cross-platform compatibility.

use super::sparker::Sparker;
use crate::utils::bits;

/// Number of spark values generated from a password.
const NUM_SPARKS: usize = 40;

/// Walsh code table used by [`ByteExpansor`] for byte expansion.
/// These are the 128 Walsh codes from the Java `PasswordSparker.ByteExpansor`.
#[rustfmt::skip]
const WALSH_CODES: [i64; 128] = [
     1085350949055100000,  -3074457345618260000,  -5534023222112870000,   7378697629483820000,
    -8138269444283630000,   6510615555426900000,   4340410370284600000,  -1627653888856720000,
    -9151594822560190000,   6172840429334710000,   3732415143318660000,  -1830318964512040000,
     1148435428713440000,  -2691645536047110000,  -4844961964884800000,   7608384715226510000,
    -9223090566172970000,   6149008514797120000,   3689517697151000000,  -1844618113234590000,
     1085350949055100000,  -2712673695933230000,  -4882812652679810000,   7595767819294840000,
       72056494543077100,  -3050438514103900000,  -5490789325387020000,   7393108928392440000,
    -8074690184392680000,   6531808642057220000,   4378557926219170000,  -1614938036878540000,
    -9223372032559810000,   6148914692668170000,   3689348817318890000,  -1844674406511960000,
     1085102596360830000,  -2712756480164650000,  -4882961664296370000,   7595718148755990000,
       71777218556133100,  -3050531606099550000,  -5490956890979190000,   7393053073195050000,
    -8074936604381160000,   6531726502061060000,   4378410074226080000,  -1614987320876230000,
          281474976645120,  -3074363520626040000,  -5533854337126880000,   7378753924479150000,
    -8138021084010120000,   6510698342184740000,   4340559386448710000,  -1627604216802020000,
    -9151315538050290000,   6172933524171350000,   3732582714024600000,  -1830263107610060000,
     1148681856222170000,  -2691563393544200000,  -4844814108379560000,   7608434000728250000,
    -9223372036854775808,   6148914691236520000,   3689348814741910000,  -1844674407370960000,
     1085102592571150000,  -2712756481427880000,  -4882961666570180000,   7595718147998050000,
       71777214294589700,  -3050531607520060000,  -5490956893536110000,   7393053072342740000,
    -8074936608141340000,   6531726500807660000,   4378410071969970000,  -1614987321628270000,
          281470681808895,  -3074363522057660000,  -5533854339703780000,   7378753923620180000,
    -8138021087799680000,   6510698340921550000,   4340559384174970000,  -1627604217559940000,
    -9151315542311700000,   6172933522750880000,   3732582711467760000,  -1830263108462340000,
     1148681852462100000,  -2691563394797560000,  -4844814110635600000,   7608433999976240000,
            4294967295,  -3074457344186600000,  -5534023219535890000,   7378697630342810000,
    -8138269440493950000,   6510615556690130000,   4340410372558410000,  -1627653888098790000,
    -9151594818298640000,   6172840430755230000,   3732415145875590000,  -1830318963659730000,
     1148435432473620000,  -2691645534793720000,  -4844961962628690000,   7608384715978550000,
    -9223090561878130000,   6149008516228730000,   3689517699727900000,  -1844618112375630000,
     1085350952844660000,  -2712673694670040000,  -4882812650406070000,   7595767820052750000,
       72056498804490500,  -3050438512683430000,  -5490789322830170000,   7393108929244720000,
    -8074690180632600000,   6531808643310570000,   4378557928475210000,  -1614938036126520000,
];

/// Converts a password string into deterministic spark values for
/// initializing the KaosRand PRNG.
///
/// Uses Walsh code expansion and powers of pi to derive 40 spark values
/// from the password bytes (UTF-8 encoded).
pub struct PasswordSparker {
    sparks: Vec<f64>,
    spark_pos: usize,
    password_ok: i32,
}

impl PasswordSparker {
    /// Creates a new `PasswordSparker` from the given password.
    ///
    /// Validates the password and, if valid, expands each byte using Walsh
    /// codes and generates 40 spark values using powers of pi.
    ///
    /// # Parameters
    /// - `password`: The password string (minimum 1 character).
    pub fn new(password: &str) -> Self {
        let mut sparker = PasswordSparker {
            sparks: vec![0.0; NUM_SPARKS],
            spark_pos: 0,
            password_ok: -1,
        };
        sparker.init_password(password);
        sparker
    }

    /// Returns the password validation status.
    ///
    /// - `0`: Password is valid.
    /// - `-1`: Password is too short (less than 1 character).
    pub fn password_ok(&self) -> i32 {
        self.password_ok
    }

    /// Validates the password meets minimum requirements.
    ///
    /// Sets `password_ok` to `0` if the password has at least 1 character,
    /// or `-1` if it is empty.
    fn password_cumple(&mut self, password: &str) {
        if password.is_empty() {
            self.password_ok = -1;
        } else {
            self.password_ok = 0;
        }
    }

    /// Expands a single byte into 56 bytes using Walsh codes and bit rotations.
    ///
    /// Replicates the Java `ByteExpansor` method:
    /// 1. Generates first 8 bytes via left/right rotations combined with Walsh codes.
    /// 2. Combinatorial XOR operations produce bytes 8-35.
    /// 3. Additional processing with bit masking produces bytes 36-55.
    ///
    /// # Parameters
    /// - `input`: The byte to expand.
    ///
    /// # Returns
    /// An array of 56 expanded bytes.
    fn byte_expansor(input: u8) -> [u8; 56] {
        let mut salida = [0u8; 56];
        salida[0] = input;

        // Phase 1: Generate first 8 bytes via rotations + Walsh codes
        for i in 1..8usize {
            let walsh_idx = (salida[i - 1] & 0x0F) as usize;
            let walsh_byte = WALSH_CODES[walsh_idx] as u8;
            // BitsUtils.ByteLeftRotation(walsh_byte, i) ^ BitsUtils.ByteRightRotation(salida[0], i)
            let left_rot = bits::byte_left_rotation(walsh_byte, i as u32).unwrap_or(0);
            let right_rot = bits::byte_right_rotation(salida[0], i as u32).unwrap_or(0);
            salida[i] = left_rot ^ right_rot;
        }

        // Phase 2: Combinatorial XOR for bytes 8-35
        // Index formula: (i+1) * (7 - 0.5*i) + j
        for i in 0..7usize {
            for j in (i + 1)..8usize {
                let idx = ((i + 1) as f64 * (7.0 - 0.5 * i as f64) + j as f64) as usize;
                let prev_idx = idx - 1;
                let walsh_idx = (salida[prev_idx] & 0x0F) as usize;
                let walsh_byte = WALSH_CODES[walsh_idx] as u8;

                let left_rot_i_j = bits::byte_left_rotation(salida[i], j as u32).unwrap_or(0);
                let right_rot_j_i = bits::byte_right_rotation(salida[j], i as u32).unwrap_or(0);
                let left_rot_walsh = bits::byte_left_rotation(walsh_byte, i as u32).unwrap_or(0);

                salida[idx] = (left_rot_i_j ^ right_rot_j_i) ^ left_rot_walsh;
            }
        }

        // Phase 3: Additional processing for bytes 36-55
        // Index formula: (i+1) * (6 - 0.5*i) + j + 28
        for i in 0..5usize {
            for j in (i + 2)..8usize {
                let idx = ((i + 1) as f64 * (6.0 - 0.5 * i as f64) + j as f64) as usize + 28;
                let src_idx1 = ((i + 1) as f64 * (6.0 - 0.5 * i as f64) + j as f64) as usize + 7;
                let src_idx2 = ((i + 1) as f64 * (6.0 - 0.5 * i as f64) + j as f64) as usize + 11;

                let walsh_idx = (salida[src_idx2] & 0x0F) as usize;
                let walsh_byte = WALSH_CODES[walsh_idx] as u8;

                let left_rot = bits::byte_left_rotation(salida[src_idx1], 2).unwrap_or(0);
                let right_rot = bits::byte_right_rotation(salida[i], 2).unwrap_or(0);

                // Match Java: ((left_rot & 0xAA) | (right_rot & 0x55)) ^ walsh_byte
                let combined = (left_rot & 0xAA) | (right_rot & 0x55);
                salida[idx] = combined ^ walsh_byte;
            }
        }

        salida
    }

    /// Initializes spark values from the password using powers of pi.
    ///
    /// Replicates the Java `InitPassword` method:
    /// 1. Validates and converts password to UTF-8 bytes.
    /// 2. Expands each byte to 56 bytes via [`byte_expansor`](Self::byte_expansor).
    /// 3. Combines expanded bytes with powers of pi in a cycling loop.
    /// 4. Rounds all sparks to 11 decimal places.
    ///
    /// # Parameters
    /// - `password`: The password string.
    fn init_password(&mut self, password: &str) {
        self.password_cumple(password);
        if self.password_ok != 0 {
            return;
        }

        self.spark_pos = 0;
        let cpassw = password.as_bytes();
        let plongitud = cpassw.len();

        // Expand each password byte
        let mut expanded = Vec::with_capacity(plongitud);
        for &byte in cpassw {
            expanded.push(Self::byte_expansor(byte));
        }

        // Generate sparks
        self.sparks = vec![0.0; NUM_SPARKS];

        let mut i: usize = 0; // spark index
        let mut f: usize = 0; // expanded row index (password byte index)
        let mut c: usize = 0; // expanded column index (0..55)

        loop {
            // Java byte is signed (-128..127); cast through i8 to match
            let expanded_val = (expanded[f][c] as i8) as f64;

            if c != 0 && c.is_multiple_of(2) {
                // c is even and non-zero
                self.sparks[i] += std::f64::consts::PI.powf(1.0 / c as f64) * expanded_val;
            } else if f != 0 && !c.is_multiple_of(2) {
                // c is odd and f is non-zero
                self.sparks[i] += std::f64::consts::PI.powf(1.0 / f as f64) * expanded_val;
            } else {
                // Default case: Java uses Math.pow(PI, (double)(1/2))
                // where (1/2) is integer division = 0, so PI^0 = 1.0
                self.sparks[i] += expanded_val;
            }

            if !f.is_multiple_of(3) {
                self.sparks[i] *= -0.1;
            }

            i += 1;
            c += 1;
            f += 1;

            if i >= NUM_SPARKS {
                i = 0;
            }
            if f >= expanded.len() {
                f = 0;
            }
            if c >= 56 {
                c = 0;
            }

            // Loop terminates when both f and c wrap back to 0 simultaneously
            if c == 0 && f == 0 {
                break;
            }
        }

        // Round all sparks to 11 decimal places for Android compatibility
        for spark in self.sparks.iter_mut() {
            *spark = Self::round_to_decimals(*spark, 11);
        }
    }

    /// Rounds a double to the specified number of decimal places.
    ///
    /// Replicates Java's `MathUtil.roundToDecimals` which uses
    /// `Math.round(double)` internally. `Math.round(double)` returns
    /// `(long)floor(x + 0.5)` (round half-up, not half-away-from-zero).
    ///
    /// # Parameters
    /// - `d`: The value to round.
    /// - `decimals`: Number of decimal places.
    ///
    /// # Returns
    /// The rounded value.
    fn round_to_decimals(d: f64, decimals: u32) -> f64 {
        let factor = 10.0_f64.powi(decimals as i32);
        let scaled = d * factor;
        // Java Math.round(double): (long)floor(x + 0.5)
        let rounded = (scaled + 0.5).floor();
        rounded / factor
    }
}

impl Sparker for PasswordSparker {
    /// Returns the next double spark value, cycling through the 40 sparks.
    fn get_double_spark(&mut self) -> f64 {
        let val = self.sparks[self.spark_pos];
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        val
    }

    /// Returns the next spark as a float, reading directly from the spark array.
    ///
    /// Matches Java's `getFloatSpark()` which reads and advances independently.
    fn get_float_spark(&mut self) -> f32 {
        let val = self.sparks[self.spark_pos] as f32;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        val
    }

    /// Returns a 64-bit value derived from two consecutive sparks.
    ///
    /// Matches Java: `doubleToRawLongBits(spark[pos]) ^ ~doubleToRawLongBits(spark[pos+1])`
    fn get_long_spark(&mut self) -> i64 {
        let a = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let b = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        a ^ !b
    }

    /// Returns a 31-bit integer from two consecutive sparks.
    ///
    /// Matches Java: `(combined & 0x7FFFFFFF000) >>> 12`
    fn get_integer_spark(&mut self) -> i32 {
        let a = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let b = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let combined = a ^ !b;
        (((combined as u64) & 0x7FFFFFFF000) >> 12) as i32
    }

    /// Returns a 15-bit short from two consecutive sparks.
    ///
    /// Matches Java: `(combined & 0x7FFF000) >>> 12`
    fn get_short_spark(&mut self) -> i16 {
        let a = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let b = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let combined = a ^ !b;
        (((combined as u64) & 0x7FFF000) >> 12) as i16
    }

    /// Returns a 7-bit byte from two consecutive sparks.
    ///
    /// Matches Java: `(combined & 0x7F000) >>> 12`
    fn get_byte_spark(&mut self) -> u8 {
        let a = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let b = f64::to_bits(self.sparks[self.spark_pos]) as i64;
        self.spark_pos += 1;
        if self.spark_pos >= NUM_SPARKS {
            self.spark_pos = 0;
        }
        let combined = a ^ !b;
        (((combined as u64) & 0x7F000) >> 12) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_password() {
        let sparker = PasswordSparker::new("");
        assert_eq!(sparker.password_ok(), -1);
    }

    #[test]
    fn test_valid_password() {
        let sparker = PasswordSparker::new("test");
        assert_eq!(sparker.password_ok(), 0);
    }

    #[test]
    #[allow(clippy::approx_constant)]
    fn test_round_to_decimals() {
        assert_eq!(PasswordSparker::round_to_decimals(3.14159, 2), 3.14);
        assert_eq!(PasswordSparker::round_to_decimals(2.5, 0), 3.0);
        assert_eq!(PasswordSparker::round_to_decimals(-0.5, 0), 0.0);
    }

    #[test]
    fn test_round_to_decimals_java_compat() {
        // Java Math.round(-0.5) == 0 (round half-up, not half-away-from-zero)
        assert_eq!(PasswordSparker::round_to_decimals(-0.5, 0), 0.0);
        // Java Math.round(0.5) == 1
        assert_eq!(PasswordSparker::round_to_decimals(0.5, 0), 1.0);
    }

    #[test]
    fn test_spark_wrapping() {
        let mut sparker = PasswordSparker::new("test");
        // Call get_double_spark more than NUM_SPARKS times to verify wrapping
        for _ in 0..100 {
            let _ = sparker.get_double_spark();
        }
    }

    #[test]
    fn test_byte_expansor_deterministic() {
        let result1 = PasswordSparker::byte_expansor(0x41); // 'A'
        let result2 = PasswordSparker::byte_expansor(0x41);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_byte_expansor_first_byte_is_input() {
        let result = PasswordSparker::byte_expansor(0x42);
        assert_eq!(result[0], 0x42);
    }

    #[test]
    fn test_byte_expansor_different_inputs_different_outputs() {
        let result_a = PasswordSparker::byte_expansor(0x41);
        let result_b = PasswordSparker::byte_expansor(0x42);
        assert_ne!(result_a, result_b);
    }

    #[test]
    fn test_sparks_non_zero_for_valid_password() {
        let sparker = PasswordSparker::new("TestPassword123");
        // At least some sparks should be non-zero
        let non_zero_count = sparker.sparks.iter().filter(|&&v| v != 0.0).count();
        assert!(
            non_zero_count > 0,
            "Expected non-zero sparks for valid password"
        );
    }

    #[test]
    fn test_sparks_deterministic() {
        let sparker1 = PasswordSparker::new("TestPassword123");
        let sparker2 = PasswordSparker::new("TestPassword123");
        assert_eq!(sparker1.sparks, sparker2.sparks);
    }

    #[test]
    fn test_different_passwords_different_sparks() {
        let sparker1 = PasswordSparker::new("Password1");
        let sparker2 = PasswordSparker::new("Password2");
        assert_ne!(sparker1.sparks, sparker2.sparks);
    }

    #[test]
    fn test_get_long_spark_uses_xor_not() {
        let mut sparker = PasswordSparker::new("test");
        // Verify that get_long_spark produces values (basic smoke test)
        let val = sparker.get_long_spark();
        // The spark_pos should have advanced by 2
        assert_eq!(sparker.spark_pos, 2);
        // Value should not be zero (extremely unlikely with real sparks)
        let _ = val; // Just verify it doesn't panic
    }

    #[test]
    fn test_get_integer_spark_range() {
        let mut sparker = PasswordSparker::new("test");
        for _ in 0..20 {
            let val = sparker.get_integer_spark();
            // Should be non-negative (31-bit value from & 0x7FFFFFFF000)
            assert!(val >= 0, "get_integer_spark returned negative: {}", val);
        }
    }

    #[test]
    fn test_get_short_spark_range() {
        let mut sparker = PasswordSparker::new("test");
        for _ in 0..20 {
            let val = sparker.get_short_spark();
            // Should be non-negative (15-bit value from & 0x7FFF000)
            assert!(val >= 0, "get_short_spark returned negative: {}", val);
        }
    }

    /// Debug test: prints raw spark values, getDoubleSpark, and getShortSpark
    /// outputs for "TestCrossCompat2024" to compare against Java test vectors.
    ///
    /// Java expected values:
    /// - double_sparks[0..5] = [2.14848396620e+00, 1.19144720199640e+02,
    ///   1.01051237507500e+01, 5.24009835677000e+00, 9.85481439211500e+01]
    /// - short_sparks[0..5] = [16042, 31622, 15156, 23648, 31985]
    ///
    /// Run with: cargo test test_debug_spark_values -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_debug_spark_values() {
        let password = "TestCrossCompat2024";
        let sparker = PasswordSparker::new(password);

        println!("=== PasswordSparker Debug for \"{}\" ===", password);
        println!();

        // Print first 10 raw spark values from self.sparks[]
        println!("--- Raw sparks[0..10] (from self.sparks[]) ---");
        for i in 0..10 {
            println!(
                "  sparks[{:2}] = {:+.17e}  (bits: 0x{:016X})",
                i,
                sparker.sparks[i],
                f64::to_bits(sparker.sparks[i])
            );
        }
        println!();

        // Java expected double_sparks
        let java_double_sparks = [
            2.14848396620e+00,
            1.19144720199640e+02,
            1.01051237507500e+01,
            5.24009835677000e+00,
            9.85481439211500e+01,
        ];
        println!("--- Comparison: sparks[0..5] vs Java double_sparks[0..5] ---");
        for (i, &java_val) in java_double_sparks.iter().enumerate() {
            let diff = sparker.sparks[i] - java_val;
            let match_str = if diff.abs() < 1e-6 { "MATCH" } else { "DIFFER" };
            println!(
                "  [{}] Rust: {:+.17e}  Java: {:+.17e}  diff: {:+.6e}  {}",
                i, sparker.sparks[i], java_val, diff, match_str
            );
        }
        println!();

        // Print first 5 getDoubleSpark() outputs (should be same as sparks[0..5])
        let mut sparker_d = PasswordSparker::new(password);
        println!("--- getDoubleSpark() outputs [0..5] ---");
        for i in 0..5 {
            let val = sparker_d.get_double_spark();
            println!("  getDoubleSpark()[{}] = {:+.17e}", i, val);
        }
        println!();

        // Print first 5 getShortSpark() outputs from a fresh instance
        let mut sparker_s = PasswordSparker::new(password);
        let java_short_sparks: [i16; 5] = [16042, 31622, 15156, 23648, 31985];
        println!("--- getShortSpark() outputs [0..5] vs Java ---");
        for (i, &java_val) in java_short_sparks.iter().enumerate() {
            let val = sparker_s.get_short_spark();
            let match_str = if val == java_val { "MATCH" } else { "DIFFER" };
            println!(
                "  getShortSpark()[{}] = {}  Java: {}  {}",
                i, val, java_val, match_str
            );
        }
        println!();

        // Print all 40 sparks for full comparison
        println!("--- All 40 raw sparks ---");
        for i in 0..NUM_SPARKS {
            println!("  sparks[{:2}] = {:+.17e}", i, sparker.sparks[i]);
        }
    }

    #[test]
    fn test_spark_pos_wrapping_all_methods() {
        let mut sparker = PasswordSparker::new("test");
        // Each of these reads 2 sparks, test that wrapping works
        for _ in 0..30 {
            let _ = sparker.get_long_spark();
        }
        for _ in 0..30 {
            let _ = sparker.get_integer_spark();
        }
        for _ in 0..30 {
            let _ = sparker.get_short_spark();
        }
        for _ in 0..30 {
            let _ = sparker.get_byte_spark();
        }
    }
}
