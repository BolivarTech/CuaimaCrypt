//! Bit rotation utilities for byte and 64-bit integer values.
//!
//! Provides circular bit rotation operations that replicate the behavior
//! of `BitsUtils` from the Java BTUtils library, ensuring cross-platform
//! compatibility with the Java CuaimaCrypt implementation.

use crate::error::CuaimaCryptError;

/// Rotates a byte left by `shift` bit positions (circular).
///
/// # Parameters
/// - `value`: The byte to rotate.
/// - `shift`: Number of bit positions to rotate (0..=8).
///
/// # Returns
/// The rotated byte value.
///
/// # Errors
/// Returns [`CuaimaCryptError::ShiftOutOfRange`] if `shift > 8`.
pub(crate) fn byte_left_rotation(value: u8, shift: u32) -> Result<u8, CuaimaCryptError> {
    let num_bits: u32 = 8;
    if shift > num_bits {
        return Err(CuaimaCryptError::ShiftOutOfRange);
    }
    let tvalue = value as u32;
    Ok(((tvalue << shift) | (tvalue >> (num_bits - shift))) as u8)
}

/// Rotates a byte right by `shift` bit positions (circular).
///
/// # Parameters
/// - `value`: The byte to rotate.
/// - `shift`: Number of bit positions to rotate (0..=8).
///
/// # Returns
/// The rotated byte value.
///
/// # Errors
/// Returns [`CuaimaCryptError::ShiftOutOfRange`] if `shift > 8`.
pub(crate) fn byte_right_rotation(value: u8, shift: u32) -> Result<u8, CuaimaCryptError> {
    let num_bits: u32 = 8;
    if shift > num_bits {
        return Err(CuaimaCryptError::ShiftOutOfRange);
    }
    let tvalue = value as u32;
    Ok(((tvalue >> shift) | (tvalue << (num_bits - shift))) as u8)
}

/// Rotates a 64-bit signed integer left by `shift` bit positions (circular).
///
/// # Parameters
/// - `value`: The 64-bit value to rotate.
/// - `shift`: Number of bit positions to rotate (0..=64).
///
/// # Returns
/// The rotated 64-bit value.
///
/// # Errors
/// Returns [`CuaimaCryptError::ShiftOutOfRange`] if `shift > 64`.
pub(crate) fn long_left_rotation(value: i64, shift: u32) -> Result<i64, CuaimaCryptError> {
    let num_bits: u32 = 64;
    if shift > num_bits {
        return Err(CuaimaCryptError::ShiftOutOfRange);
    }
    if shift == 0 || shift == num_bits {
        return Ok(value);
    }
    let uval = value as u64;
    Ok(((uval << shift) | (uval >> (num_bits - shift))) as i64)
}

/// Rotates a 64-bit signed integer right by `shift` bit positions (circular).
///
/// # Parameters
/// - `value`: The 64-bit value to rotate.
/// - `shift`: Number of bit positions to rotate (0..=64).
///
/// # Returns
/// The rotated 64-bit value.
///
/// # Errors
/// Returns [`CuaimaCryptError::ShiftOutOfRange`] if `shift > 64`.
pub(crate) fn long_right_rotation(value: i64, shift: u32) -> Result<i64, CuaimaCryptError> {
    let num_bits: u32 = 64;
    if shift > num_bits {
        return Err(CuaimaCryptError::ShiftOutOfRange);
    }
    if shift == 0 || shift == num_bits {
        return Ok(value);
    }
    let uval = value as u64;
    Ok(((uval >> shift) | (uval << (num_bits - shift))) as i64)
}

/// Returns the number of bits required to represent the given number.
///
/// # Parameters
/// - `num`: The number to analyze.
///
/// # Returns
/// The number of significant bits.
pub(crate) fn bits_required(num: i64) -> i32 {
    let mut y = num;
    let mut shifted = num;
    let mut n: i32 = 0;
    loop {
        if shifted < 0 {
            return 64 - n;
        }
        if y == 0 {
            return n;
        }
        n += 1;
        shifted <<= 1;
        y >>= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_left_rotation_basic() {
        // 0b10110001 rotated left by 3 -> 0b10001101
        let result = byte_left_rotation(0b1011_0001, 3).unwrap();
        assert_eq!(result, 0b1000_1101);
    }

    #[test]
    fn test_byte_left_rotation_zero_shift() {
        let result = byte_left_rotation(0xAB, 0).unwrap();
        assert_eq!(result, 0xAB);
    }

    #[test]
    fn test_byte_left_rotation_full_shift() {
        let result = byte_left_rotation(0xAB, 8).unwrap();
        assert_eq!(result, 0xAB);
    }

    #[test]
    fn test_byte_left_rotation_out_of_range() {
        let result = byte_left_rotation(0xAB, 9);
        assert_eq!(result, Err(CuaimaCryptError::ShiftOutOfRange));
    }

    #[test]
    fn test_byte_right_rotation_basic() {
        // 0b10110001 rotated right by 3 -> 0b00110110
        let result = byte_right_rotation(0b1011_0001, 3).unwrap();
        assert_eq!(result, 0b0011_0110);
    }

    #[test]
    fn test_byte_rotation_roundtrip() {
        let original: u8 = 0xC7;
        for shift in 0..=8 {
            let rotated = byte_left_rotation(original, shift).unwrap();
            let restored = byte_right_rotation(rotated, shift).unwrap();
            assert_eq!(restored, original, "roundtrip failed for shift={}", shift);
        }
    }

    #[test]
    fn test_long_left_rotation_basic() {
        let value: i64 = 0x0123_4567_89AB_CDEFu64 as i64;
        let result = long_left_rotation(value, 16).unwrap();
        let expected = 0x4567_89AB_CDEF_0123u64 as i64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_long_right_rotation_basic() {
        let value: i64 = 0x0123_4567_89AB_CDEFu64 as i64;
        let result = long_right_rotation(value, 16).unwrap();
        let expected = 0xCDEF_0123_4567_89ABu64 as i64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_long_rotation_roundtrip() {
        let original: i64 = 0x0123_4567_89AB_CDEFu64 as i64;
        for shift in 0..=64 {
            let rotated = long_left_rotation(original, shift).unwrap();
            let restored = long_right_rotation(rotated, shift).unwrap();
            assert_eq!(restored, original, "roundtrip failed for shift={}", shift);
        }
    }

    #[test]
    fn test_long_rotation_out_of_range() {
        assert_eq!(
            long_left_rotation(0, 65),
            Err(CuaimaCryptError::ShiftOutOfRange)
        );
        assert_eq!(
            long_right_rotation(0, 65),
            Err(CuaimaCryptError::ShiftOutOfRange)
        );
    }

    #[test]
    fn test_bits_required() {
        assert_eq!(bits_required(0), 0);
        assert_eq!(bits_required(1), 1);
        assert_eq!(bits_required(2), 2);
        assert_eq!(bits_required(3), 2);
        assert_eq!(bits_required(255), 8);
        assert_eq!(bits_required(256), 9);
        assert_eq!(bits_required(-1), 64);
    }
}
