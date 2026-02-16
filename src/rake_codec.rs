//! RakeCodec: 128-bit processor grouping 4 ShiftCodecs.
//!
//! A RakeCodec contains 4 ShiftCodecs connected in a ring topology.
//! It processes 128-bit blocks (two `i64` values) by splitting each
//! `i64` into two 32-bit halves and encoding each half with a
//! separate ShiftCodec.

use crate::shift_codec::{ShiftCodecArena, ShiftCodecId};

/// Number of ShiftCodecs in a single RakeCodec.
const RAKE_TEETHS: usize = 4;

/// 128-bit block processor grouping 4 ShiftCodecs in a ring topology.
///
/// The ring connects: `rake[0] → rake[1] → rake[2] → rake[3] → rake[0]` (upchain)
/// and the reverse for downchain.
pub(crate) struct RakeCodec {
    rake: [ShiftCodecId; RAKE_TEETHS],
}

impl RakeCodec {
    /// Creates a new RakeCodec with 4 ShiftCodecs chained in a ring.
    ///
    /// The ShiftCodecs are created with random seeds in the arena and
    /// connected in a circular ring topology.
    ///
    /// # Parameters
    /// - `arena`: The ShiftCodec arena to allocate in.
    ///
    /// # Returns
    /// A new RakeCodec with its 4 ShiftCodecIds.
    pub(crate) fn new(arena: &mut ShiftCodecArena) -> Self {
        let mut rake = [ShiftCodecId(0); RAKE_TEETHS];

        // Create 4 ShiftCodecs with seed 0 (will be set by CuaimaCrypt.password())
        for item in rake.iter_mut() {
            *item = arena.new_codec(0);
        }

        // Chain in a ring
        for i in 0..RAKE_TEETHS {
            let up = if i < RAKE_TEETHS - 1 {
                rake[i + 1]
            } else {
                rake[0]
            };
            let down = if i > 0 {
                rake[i - 1]
            } else {
                rake[RAKE_TEETHS - 1]
            };
            arena.set_chain(rake[i], up, down);
        }

        RakeCodec { rake }
    }

    /// Returns the ShiftCodecId at the given position.
    ///
    /// # Parameters
    /// - `index`: Position in the rake (0..3).
    pub(crate) fn get_shift_codec(&self, index: usize) -> ShiftCodecId {
        self.rake[index]
    }

    /// Returns the number of ShiftCodecs (always 4).
    pub(crate) fn num_shift_codecs(&self) -> usize {
        RAKE_TEETHS
    }

    /// Encodes a 128-bit block (two `i64` values) in place.
    ///
    /// Each `i64` is split into two 32-bit halves. The low 32 bits are
    /// encoded by `rake[2*j]` and the high 32 bits by `rake[2*j+1]`,
    /// then reassembled.
    ///
    /// # Parameters
    /// - `arena`: The ShiftCodec arena.
    /// - `block`: The 128-bit block to encode (modified in place).
    pub(crate) fn codec(&self, arena: &mut ShiftCodecArena, block: &mut [i64; 2]) {
        // Hardcoded raketeeths=2, numentradas=2 (matching Java for performance)
        let raketeeths = 2;
        let numentradas = 2;

        for (j, block_item) in block.iter_mut().enumerate().take(numentradas) {
            let mut salida: i64 = 0;
            for i in 0..raketeeths {
                // Extract 32-bit portion: (entrada[j] >>> i*32) truncated to i32
                let bit_ent = (((*block_item) as u64) >> (i * 32)) as i32;
                // Encode with the corresponding ShiftCodec
                let bit_sal = arena.bits_codec(self.rake[raketeeths * j + i], bit_ent) as i64;
                // Reassemble: shift encoded value to position, clear high bits of salida, OR
                let bit_sal_shifted = bit_sal << (i * 32);
                salida = ((salida as u64) << (i * 32)) as i64;
                salida = ((salida as u64) >> (i * 32)) as i64;
                salida |= bit_sal_shifted;
            }
            *block_item = salida;
        }
    }

    /// Decodes a 128-bit block (two `i64` values) in place.
    ///
    /// Symmetric to [`codec`](Self::codec) — uses `bits_decodec` instead
    /// of `bits_codec`.
    ///
    /// # Parameters
    /// - `arena`: The ShiftCodec arena.
    /// - `block`: The 128-bit block to decode (modified in place).
    pub(crate) fn decodec(&self, arena: &mut ShiftCodecArena, block: &mut [i64; 2]) {
        let raketeeths = 2;
        let numentradas = 2;

        for (j, block_item) in block.iter_mut().enumerate().take(numentradas) {
            let mut salida: i64 = 0;
            for i in 0..raketeeths {
                let bit_ent = (((*block_item) as u64) >> (i * 32)) as i32;
                let bit_sal = arena.bits_decodec(self.rake[raketeeths * j + i], bit_ent) as i64;
                let bit_sal_shifted = bit_sal << (i * 32);
                salida = ((salida as u64) << (i * 32)) as i64;
                salida = ((salida as u64) >> (i * 32)) as i64;
                salida |= bit_sal_shifted;
            }
            *block_item = salida;
        }
    }

    /// Advances all 4 ShiftCodecs for encoding.
    ///
    /// Called after encoding a block to update the shift register states.
    pub(crate) fn shift_codec(&self, arena: &mut ShiftCodecArena) {
        for i in 0..RAKE_TEETHS {
            arena.shift_cdec(self.rake[i]);
        }
    }

    /// Advances all 4 ShiftCodecs for decoding.
    ///
    /// Called after decoding a block to update the shift register states.
    pub(crate) fn shift_decodec(&self, arena: &mut ShiftCodecArena) {
        for i in 0..RAKE_TEETHS {
            arena.shift_dcdec(self.rake[i]);
        }
    }

    /// Resets all 4 ShiftCodecs to their seed states.
    pub(crate) fn reset(&self, arena: &mut ShiftCodecArena) {
        for i in 0..RAKE_TEETHS {
            arena.reset(self.rake[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rake_codec_creation() {
        let mut arena = ShiftCodecArena::new();
        let rake = RakeCodec::new(&mut arena);
        assert_eq!(rake.num_shift_codecs(), 4);
        assert_eq!(arena.len(), 4);
    }

    #[test]
    fn test_codec_decodec_roundtrip() {
        let mut arena = ShiftCodecArena::new();
        let rake = RakeCodec::new(&mut arena);

        // Set known seeds
        for i in 0..4 {
            arena.set_seed(rake.get_shift_codec(i), (i as i64 + 1) * 12345);
        }

        let original: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
        let mut block = original;

        // Encode
        rake.codec(&mut arena, &mut block);
        assert_ne!(block, original, "Encoded block should differ from original");

        // Reset to same state for decoding
        rake.reset(&mut arena);

        // Decode
        rake.decodec(&mut arena, &mut block);
        assert_eq!(block, original, "Decoded block should match original");
    }

    #[test]
    fn test_codec_deterministic() {
        let mut arena1 = ShiftCodecArena::new();
        let rake1 = RakeCodec::new(&mut arena1);
        for i in 0..4 {
            arena1.set_seed(rake1.get_shift_codec(i), (i as i64 + 1) * 100);
        }

        let mut arena2 = ShiftCodecArena::new();
        let rake2 = RakeCodec::new(&mut arena2);
        for i in 0..4 {
            arena2.set_seed(rake2.get_shift_codec(i), (i as i64 + 1) * 100);
        }

        let mut block1: [i64; 2] = [42, 84];
        let mut block2: [i64; 2] = [42, 84];

        rake1.codec(&mut arena1, &mut block1);
        rake2.codec(&mut arena2, &mut block2);

        assert_eq!(block1, block2);
    }

    #[test]
    fn test_shift_codec_changes_state() {
        let mut arena = ShiftCodecArena::new();
        let rake = RakeCodec::new(&mut arena);
        for i in 0..4 {
            arena.set_seed(rake.get_shift_codec(i), (i as i64 + 1) * 999);
        }

        let mut block: [i64; 2] = [0xDEADBEEF, 0xCAFEBABE];
        rake.codec(&mut arena, &mut block);

        let state_before = arena.get_state(rake.get_shift_codec(0));
        rake.shift_codec(&mut arena);
        let state_after = arena.get_state(rake.get_shift_codec(0));

        assert_ne!(state_before, state_after, "State should change after shift");
    }

    #[test]
    fn test_multi_block_encoding() {
        let mut arena = ShiftCodecArena::new();
        let rake = RakeCodec::new(&mut arena);
        for i in 0..4 {
            arena.set_seed(rake.get_shift_codec(i), (i as i64 + 1) * 777);
        }

        let mut block1: [i64; 2] = [1, 2];
        let mut block2: [i64; 2] = [1, 2];

        // First block
        rake.codec(&mut arena, &mut block1);
        rake.shift_codec(&mut arena);

        // Second identical plaintext block — should produce different ciphertext
        rake.codec(&mut arena, &mut block2);

        assert_ne!(
            block1, block2,
            "Same plaintext should produce different ciphertext after state advance"
        );
    }
}
