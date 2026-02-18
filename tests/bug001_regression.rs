// Author: Julian Bolivar
// Version: 1.0.0
// Date: 2026-02-17

//! Regression tests for BUG-001: Non-deterministic codec/decodec for ~4% of
//! passwords.
//!
//! These tests verify that passwords whose first `get_short_spark() % 25 == 0`
//! produce deterministic and reversible encryption. All tests are expected to
//! FAIL before the fix and PASS after.

use cuaimacrypt::random::password_sparker::PasswordSparker;
use cuaimacrypt::random::sparker::Sparker;
use cuaimacrypt::CuaimaCrypt;

/// Known-bad passwords that produce `get_short_spark() % 25 == 0`,
/// triggering BUG-001.
const BAD_PASSWORDS: [&str; 3] = ["SizeSweep_4", "Pow2Sweep_512", "Pow2Sweep_2048"];

/// Plaintext vectors used across multiple tests.
const PLAINTEXTS: [[i64; 2]; 5] = [
    [0x0102030405060708, 0x090A0B0C0D0E0F10],
    [0, 0],
    [-1, -1],
    [i64::MAX, i64::MIN],
    [42, 84],
];

// ═══════════════════════════════════════════════════════════════════════
// Core regression: roundtrip correctness for known-bad passwords
// ═══════════════════════════════════════════════════════════════════════

/// Verifies codec/decodec roundtrip for each known-bad password across
/// multiple plaintext values.
///
/// BUG-001: encoder and decoder diverge because KaosRand's internal
/// MersenneTwister is seeded with system time when jump == 0.
#[test]
fn bug001_roundtrip_known_bad_passwords() {
    for password in BAD_PASSWORDS {
        for (i, &plaintext) in PLAINTEXTS.iter().enumerate() {
            let mut encoder = CuaimaCrypt::new();
            encoder.password(password).unwrap();
            let mut block = plaintext;
            encoder.codec(&mut block);

            let mut decoder = CuaimaCrypt::new();
            decoder.password(password).unwrap();
            decoder.decodec(&mut block);

            assert_eq!(
                block, plaintext,
                "Roundtrip failed for password '{}', plaintext[{}]",
                password, i
            );
        }
    }
}

/// Verifies that two independent encoder instances initialized with the
/// same bad password produce identical ciphertext.
///
/// BUG-001: each instance seeds MersenneTwister with a different system
/// time, causing completely different cipher states.
#[test]
fn bug001_deterministic_ciphertext_known_bad_passwords() {
    for password in BAD_PASSWORDS {
        let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];

        let mut enc1 = CuaimaCrypt::new();
        enc1.password(password).unwrap();
        let mut block1 = plaintext;
        enc1.codec(&mut block1);

        let mut enc2 = CuaimaCrypt::new();
        enc2.password(password).unwrap();
        let mut block2 = plaintext;
        enc2.codec(&mut block2);

        assert_eq!(
            block1, block2,
            "Ciphertext diverged for password '{}'",
            password
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Sequential multi-block roundtrip
// ═══════════════════════════════════════════════════════════════════════

/// Verifies that multiple consecutive blocks round-trip correctly with
/// bad passwords. SeedHopping permutes state after each block, so if
/// the first block is wrong, all subsequent blocks are also wrong.
#[test]
fn bug001_multi_block_sequential_roundtrip() {
    for password in BAD_PASSWORDS {
        let mut encoder = CuaimaCrypt::new();
        encoder.password(password).unwrap();

        let mut decoder = CuaimaCrypt::new();
        decoder.password(password).unwrap();

        for block_idx in 0..10u64 {
            let plaintext: [i64; 2] = [block_idx as i64, !(block_idx as i64)];
            let mut block = plaintext;
            encoder.codec(&mut block);
            decoder.decodec(&mut block);
            assert_eq!(
                block, plaintext,
                "Multi-block roundtrip failed for password '{}', block {}",
                password, block_idx
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Custom rake counts with bad passwords
// ═══════════════════════════════════════════════════════════════════════

/// Verifies roundtrip for bad passwords with various rake counts.
///
/// The bug is in KaosRand initialization (shared across all rake counts),
/// so any rake count that uses `KaosRand::from_sparker` is affected.
#[test]
fn bug001_bad_passwords_with_custom_rake_counts() {
    let rake_counts = [2, 5, 16];
    for password in BAD_PASSWORDS {
        for &rakes in &rake_counts {
            let mut encoder = CuaimaCrypt::with_num_rakes(rakes).unwrap();
            encoder.password(password).unwrap();

            let mut decoder = CuaimaCrypt::with_num_rakes(rakes).unwrap();
            decoder.password(password).unwrap();

            let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];
            let mut block = plaintext;
            encoder.codec(&mut block);
            decoder.decodec(&mut block);

            assert_eq!(
                block, plaintext,
                "Roundtrip failed for password '{}', rakes={}",
                password, rakes
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Statistical: zero roundtrip failures across many passwords
// ═══════════════════════════════════════════════════════════════════════

/// Fuzzes 1000 passwords and verifies 0% roundtrip failure rate.
///
/// Before the fix, approximately 4% (~40 out of 1000) fail silently.
/// After the fix, all must pass.
///
/// Uses multiple password formats to ensure diverse spark distributions,
/// including known-bad passwords. The two-phase approach (batch-encode
/// then batch-decode) ensures a time gap between encoder and decoder
/// creation, preventing accidental same-millisecond system-time seeds.
#[test]
fn bug001_roundtrip_zero_failure_rate_fuzz() {
    let plaintext: [i64; 2] = [0x0102030405060708, 0x090A0B0C0D0E0F10];

    // Build password set: known bad + diverse formats that produce zero-jump hits
    let mut passwords: Vec<String> = Vec::with_capacity(1050);
    passwords.extend(BAD_PASSWORDS.iter().map(|s| s.to_string()));
    for i in 0..500 {
        passwords.push(format!("TestPassword_{}", i));
    }
    for i in 0..500 {
        passwords.push(format!("Pwd{}_check", i));
    }
    let num_passwords = passwords.len();

    // Phase 1: encode all blocks
    let ciphertexts: Vec<[i64; 2]> = passwords
        .iter()
        .map(|pw| {
            let mut encoder = CuaimaCrypt::new();
            encoder.password(pw).unwrap();
            let mut block = plaintext;
            encoder.codec(&mut block);
            block
        })
        .collect();

    // Phase 2: decode all blocks (time gap from Phase 1)
    let mut failures = Vec::new();
    for (i, pw) in passwords.iter().enumerate() {
        let mut decoder = CuaimaCrypt::new();
        decoder.password(pw).unwrap();
        let mut block = ciphertexts[i];
        decoder.decodec(&mut block);

        if block != plaintext {
            failures.push(pw.clone());
        }
    }

    assert!(
        failures.is_empty(),
        "Roundtrip failed for {} out of {} passwords ({:.1}%): {:?}",
        failures.len(),
        num_passwords,
        failures.len() as f64 / num_passwords as f64 * 100.0,
        &failures[..failures.len().min(10)]
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Confirm hypothesis: bad passwords have short_spark divisible by 25
// ═══════════════════════════════════════════════════════════════════════

/// Confirms the BUG-001 root cause: all known-bad passwords produce a
/// `get_short_spark()` value where `value % 25 == 0`.
///
/// This test documents the diagnosis and will continue to PASS both
/// before and after the fix (the sparker output is unchanged).
#[test]
fn bug001_confirm_root_cause_short_spark_divisible_by_25() {
    for password in BAD_PASSWORDS {
        let mut sparker = PasswordSparker::new(password);
        let short_val = sparker.get_short_spark();
        assert_eq!(
            (short_val as i32) % 25,
            0,
            "Expected short_spark % 25 == 0 for '{}', got short_spark={} (% 25 = {})",
            password,
            short_val,
            (short_val as i32) % 25
        );
    }
}
