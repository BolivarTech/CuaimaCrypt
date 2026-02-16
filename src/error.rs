//! Error types for the CuaimaCrypt library.

use std::fmt;

/// Errors produced by the CuaimaCrypt library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CuaimaCryptError {
    /// Password length is less than 1 character.
    PasswordTooShort,
    /// Password does not meet character requirements.
    PasswordInvalidChars,
    /// Bit shift value is outside the valid range.
    ShiftOutOfRange,
    /// Bit position is outside the valid range.
    BitPositionOutOfRange,
    /// Byte array length is not a multiple of the required value.
    InvalidByteArrayLength,
    /// Number of RakeCodecs is outside the valid range [2, 1024].
    InvalidNumRakeCodecs,
}

impl fmt::Display for CuaimaCryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CuaimaCryptError::PasswordTooShort => {
                write!(f, "Password must be at least 1 character long")
            }
            CuaimaCryptError::PasswordInvalidChars => {
                write!(f, "Password does not meet character requirements")
            }
            CuaimaCryptError::ShiftOutOfRange => {
                write!(f, "Shift value is outside the valid range")
            }
            CuaimaCryptError::BitPositionOutOfRange => {
                write!(f, "Bit position is outside the valid range")
            }
            CuaimaCryptError::InvalidByteArrayLength => {
                write!(
                    f,
                    "Byte array length is not a multiple of the required value"
                )
            }
            CuaimaCryptError::InvalidNumRakeCodecs => {
                write!(f, "Number of RakeCodecs must be between 2 and 1024")
            }
        }
    }
}

impl std::error::Error for CuaimaCryptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_password_too_short() {
        let err = CuaimaCryptError::PasswordTooShort;
        assert_eq!(
            format!("{}", err),
            "Password must be at least 1 character long"
        );
    }

    #[test]
    fn test_display_shift_out_of_range() {
        let err = CuaimaCryptError::ShiftOutOfRange;
        assert_eq!(format!("{}", err), "Shift value is outside the valid range");
    }

    #[test]
    fn test_display_invalid_byte_array() {
        let err = CuaimaCryptError::InvalidByteArrayLength;
        assert_eq!(
            format!("{}", err),
            "Byte array length is not a multiple of the required value"
        );
    }

    #[test]
    fn test_display_invalid_num_rake_codecs() {
        let err = CuaimaCryptError::InvalidNumRakeCodecs;
        assert_eq!(
            format!("{}", err),
            "Number of RakeCodecs must be between 2 and 1024"
        );
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(
            CuaimaCryptError::PasswordTooShort,
            CuaimaCryptError::PasswordTooShort
        );
        assert_ne!(
            CuaimaCryptError::PasswordTooShort,
            CuaimaCryptError::ShiftOutOfRange
        );
    }

    #[test]
    fn test_error_clone() {
        let err = CuaimaCryptError::PasswordInvalidChars;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}
