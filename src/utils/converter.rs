//! Byte-to-primitive type conversion utilities.
//!
//! Provides conversion between byte arrays and `i64` arrays using big-endian
//! byte ordering, replicating the behavior of `Converter` from the Java
//! BTUtils library.

use crate::error::CuaimaCryptError;

/// Converts a byte slice to a `Vec<i64>` using big-endian byte ordering.
///
/// Each group of 8 bytes is combined into a single `i64` value where the
/// first byte occupies the most significant position.
///
/// # Parameters
/// - `input`: Byte slice whose length must be a multiple of 8.
///
/// # Returns
/// A `Vec<i64>` containing `input.len() / 8` elements.
///
/// # Errors
/// Returns [`CuaimaCryptError::InvalidByteArrayLength`] if `input.len() % 8 != 0`.
pub fn byte_to_long(input: &[u8]) -> Result<Vec<i64>, CuaimaCryptError> {
    if !input.len().is_multiple_of(8) {
        return Err(CuaimaCryptError::InvalidByteArrayLength);
    }
    let num_longs = input.len() / 8;
    let mut output = Vec::with_capacity(num_longs);
    for i in 0..num_longs {
        let mut value: i64 = 0;
        for j in 0..8 {
            // Replicate Java's zero-extension: temp << 56; temp >>> 56
            let temp = (input[i * 8 + j] as i64) << 56;
            let temp = ((temp as u64) >> 56) as i64;
            let temp = temp << (56 - 8 * j as i64);
            value |= temp;
        }
        output.push(value);
    }
    Ok(output)
}

/// Converts a slice of `i64` values to a `Vec<u8>` using big-endian byte ordering.
///
/// Each `i64` is decomposed into 8 bytes where the most significant byte
/// comes first in the output.
///
/// # Parameters
/// - `input`: Slice of `i64` values.
///
/// # Returns
/// A `Vec<u8>` containing `input.len() * 8` bytes.
pub fn long_to_byte(input: &[i64]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() * 8);
    for &value in input {
        for j in 0..8 {
            let temp = value << (8 * j);
            let byte_val = ((temp as u64) >> 56) as u8;
            output.push(byte_val);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_to_long_basic() {
        let bytes: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let result = byte_to_long(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0x0123_4567_89AB_CDEFu64 as i64);
    }

    #[test]
    fn test_long_to_byte_basic() {
        let longs: [i64; 1] = [0x0123_4567_89AB_CDEFu64 as i64];
        let result = long_to_byte(&longs);
        assert_eq!(result, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_roundtrip() {
        let original: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let longs = byte_to_long(&original).unwrap();
        let bytes = long_to_byte(&longs);
        assert_eq!(bytes, original);
    }

    #[test]
    fn test_byte_to_long_invalid_length() {
        let bytes = [0u8; 7];
        assert_eq!(
            byte_to_long(&bytes),
            Err(CuaimaCryptError::InvalidByteArrayLength)
        );
    }

    #[test]
    fn test_byte_to_long_empty() {
        let result = byte_to_long(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_long_to_byte_empty() {
        let result = long_to_byte(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_all_zeros() {
        let bytes = [0u8; 8];
        let longs = byte_to_long(&bytes).unwrap();
        assert_eq!(longs[0], 0i64);
        let back = long_to_byte(&longs);
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_all_ones() {
        let bytes = [0xFFu8; 8];
        let longs = byte_to_long(&bytes).unwrap();
        assert_eq!(longs[0], -1i64);
        let back = long_to_byte(&longs);
        assert_eq!(back, bytes);
    }

    #[test]
    fn test_negative_value_roundtrip() {
        let longs: [i64; 1] = [-3074457345618260000i64];
        let bytes = long_to_byte(&longs);
        let restored = byte_to_long(&bytes).unwrap();
        assert_eq!(restored[0], longs[0]);
    }
}
