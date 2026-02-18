//! ShiftCodec: 64-bit non-linear feedback shift register (NLFSR).
//!
//! Implements the atomic cryptographic unit of CuaimaCrypt. Each ShiftCodec
//! maintains a 64-bit shift register with non-linear feedback driven by
//! bidirectional chain connections to other ShiftCodecs.
//!
//! Uses an arena-based design to avoid cyclic references. All ShiftCodecs
//! are stored in a [`ShiftCodecArena`] and referenced by [`ShiftCodecId`].

/// Unique identifier for a ShiftCodec within an arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShiftCodecId(pub usize);

/// Internal state of a single ShiftCodec.
///
/// Contains the 64-bit shift register, chain connections, and all
/// configuration parameters that control the NLFSR behavior.
pub(crate) struct ShiftCodecData {
    seed: i64,
    shift_register: i64,
    pos_up: i32,
    pos_down: i32,
    shift_leap: i32,
    win_a: i32,
    win_b: i32,
    entrada: i32,
    salida: i32,
    upchain: Option<ShiftCodecId>,
    downchain: Option<ShiftCodecId>,
}

/// Arena for managing ShiftCodec instances with bidirectional chain references.
///
/// Stores all ShiftCodecs in a contiguous `Vec` and resolves chain references
/// by index, avoiding `Rc<RefCell<>>` or `unsafe` code.
pub(crate) struct ShiftCodecArena {
    codecs: Vec<ShiftCodecData>,
}

impl ShiftCodecArena {
    /// Creates a new empty arena.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        ShiftCodecArena { codecs: Vec::new() }
    }

    /// Creates a new empty arena with the specified capacity.
    ///
    /// # Parameters
    /// - `capacity`: Number of ShiftCodecs to pre-allocate.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        ShiftCodecArena {
            codecs: Vec::with_capacity(capacity),
        }
    }

    /// Creates a new ShiftCodec with the given seed and adds it to the arena.
    ///
    /// The shift register is initialized to the seed value. Default parameters:
    /// - `pos_up = 5`, `pos_down = 15`
    /// - `win_a = 9`, `win_b = 27`
    /// - `shift_leap = 1`
    ///
    /// # Parameters
    /// - `seed`: Initial seed value for the shift register.
    ///
    /// # Returns
    /// The [`ShiftCodecId`] of the new ShiftCodec.
    pub(crate) fn new_codec(&mut self, seed: i64) -> ShiftCodecId {
        let id = ShiftCodecId(self.codecs.len());
        self.codecs.push(ShiftCodecData {
            seed,
            shift_register: seed,
            pos_up: 5,
            pos_down: 15,
            shift_leap: 1,
            win_a: 9,
            win_b: 27,
            entrada: 0,
            salida: 0,
            upchain: None,
            downchain: None,
        });
        id
    }

    /// Returns the number of ShiftCodecs in the arena.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.codecs.len()
    }

    /// Extracts a 32-bit window from the shift register at the given position.
    ///
    /// Replicates Java's `GetBits(int pos)`: performs unsigned right shift
    /// of the shift register by `pos` bits and truncates to 32 bits.
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to read from.
    /// - `pos`: Bit position (0..31). Returns -1 if out of range.
    ///
    /// # Returns
    /// 32-bit window value, or -1 if position is invalid.
    pub(crate) fn get_bits(&self, id: ShiftCodecId, pos: i32) -> i32 {
        if (0..32).contains(&pos) {
            let sr = self.codecs[id.0].shift_register;
            ((sr as u64) >> (pos as u32)) as i32
        } else {
            -1
        }
    }

    /// Encodes a 32-bit input value by XOR with the low 32 bits of the shift register.
    ///
    /// Stores `input` as `entrada` and the XOR result as `salida`.
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to use.
    /// - `input`: The 32-bit value to encode.
    ///
    /// # Returns
    /// The encoded value (`input ^ shift_register_low32`).
    pub(crate) fn bits_codec(&mut self, id: ShiftCodecId, input: i32) -> i32 {
        let codec = &mut self.codecs[id.0];
        codec.entrada = input;
        codec.salida = input ^ (codec.shift_register as i32);
        codec.salida
    }

    /// Decodes a 32-bit input value by XOR with the low 32 bits of the shift register.
    ///
    /// Symmetric operation — identical to [`bits_codec`](Self::bits_codec) since
    /// XOR is its own inverse.
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to use.
    /// - `input`: The 32-bit value to decode.
    ///
    /// # Returns
    /// The decoded value (`input ^ shift_register_low32`).
    pub(crate) fn bits_decodec(&mut self, id: ShiftCodecId, input: i32) -> i32 {
        let codec = &mut self.codecs[id.0];
        codec.entrada = input;
        codec.salida = input ^ (codec.shift_register as i32);
        codec.salida
    }

    /// Shared shift register advancement logic for encoding and decoding.
    ///
    /// Replicates Java's `ShiftCdec()`/`ShiftDcdec()`:
    /// 1. XOR window bits from self and chains.
    /// 2. XOR with `feedback` (entrada for encoding, salida for decoding).
    /// 3. Shift register right by `shift_leap` bits.
    /// 4. XOR new bits into position 31.
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to advance.
    /// - `feedback`: The feedback value (`entrada` for encoding, `salida` for decoding).
    ///
    /// # Panics
    /// Panics if upchain or downchain is not set.
    fn shift_common(&mut self, id: ShiftCodecId, feedback: i32) {
        let codec = &self.codecs[id.0];
        let win_a = codec.win_a;
        let win_b = codec.win_b;
        let pos_up = codec.pos_up;
        let pos_down = codec.pos_down;
        let shift_leap = codec.shift_leap;
        let upchain = codec.upchain.expect("upchain not set");
        let downchain = codec.downchain.expect("downchain not set");

        let mut a = self.get_bits(id, win_a) ^ self.get_bits(upchain, pos_up);
        let b = self.get_bits(id, win_b) ^ self.get_bits(downchain, pos_down);
        a ^= b;
        let b = a ^ feedback;
        let sr = (b as i64) << 31;
        let codec = &mut self.codecs[id.0];
        codec.shift_register = ((codec.shift_register as u64) >> (shift_leap as u32)) as i64;
        codec.shift_register ^= sr;
    }

    /// Advances the shift register for encoding (uses `entrada` as feedback).
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to advance.
    ///
    /// # Panics
    /// Panics if upchain or downchain is not set.
    pub(crate) fn shift_cdec(&mut self, id: ShiftCodecId) {
        let feedback = self.codecs[id.0].entrada;
        self.shift_common(id, feedback);
    }

    /// Advances the shift register for decoding (uses `salida` as feedback).
    ///
    /// # Parameters
    /// - `id`: The ShiftCodec to advance.
    ///
    /// # Panics
    /// Panics if upchain or downchain is not set.
    pub(crate) fn shift_dcdec(&mut self, id: ShiftCodecId) {
        let feedback = self.codecs[id.0].salida;
        self.shift_common(id, feedback);
    }

    // --- Getters and Setters ---

    /// Returns the seed of the specified ShiftCodec.
    pub(crate) fn get_seed(&self, id: ShiftCodecId) -> i64 {
        self.codecs[id.0].seed
    }

    /// Sets the seed and resets the shift register to the new seed.
    pub(crate) fn set_seed(&mut self, id: ShiftCodecId, seed: i64) {
        let codec = &mut self.codecs[id.0];
        codec.seed = seed;
        codec.shift_register = seed;
    }

    /// Returns the current shift register state.
    #[allow(dead_code)]
    pub(crate) fn get_state(&self, id: ShiftCodecId) -> i64 {
        self.codecs[id.0].shift_register
    }

    /// Sets the shift register state directly (without changing the seed).
    #[allow(dead_code)]
    pub(crate) fn set_state(&mut self, id: ShiftCodecId, state: i64) {
        self.codecs[id.0].shift_register = state;
    }

    /// Resets the shift register to the seed value.
    pub(crate) fn reset(&mut self, id: ShiftCodecId) {
        let codec = &mut self.codecs[id.0];
        codec.shift_register = codec.seed;
    }

    /// Sets the upchain position (0..31). Out of range defaults to 29.
    pub(crate) fn set_pos_up(&mut self, id: ShiftCodecId, pos: i32) {
        if (0..32).contains(&pos) {
            self.codecs[id.0].pos_up = pos;
        } else {
            self.codecs[id.0].pos_up = 29;
        }
    }

    /// Returns the upchain bit position.
    #[allow(dead_code)]
    pub(crate) fn get_pos_up(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].pos_up
    }

    /// Sets the downchain position (0..31). Out of range defaults to 9.
    pub(crate) fn set_pos_down(&mut self, id: ShiftCodecId, pos: i32) {
        if (0..32).contains(&pos) {
            self.codecs[id.0].pos_down = pos;
        } else {
            self.codecs[id.0].pos_down = 9;
        }
    }

    /// Returns the downchain bit position.
    #[allow(dead_code)]
    pub(crate) fn get_pos_down(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].pos_down
    }

    /// Sets the shift leap (1..14). Out of range defaults to 7.
    pub(crate) fn set_shift_leap(&mut self, id: ShiftCodecId, leap: i32) {
        if (1..15).contains(&leap) {
            self.codecs[id.0].shift_leap = leap;
        } else {
            self.codecs[id.0].shift_leap = 7;
        }
    }

    /// Returns the shift leap value.
    #[allow(dead_code)]
    pub(crate) fn get_shift_leap(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].shift_leap
    }

    /// Sets window A position (0..31). Ignored if out of range.
    pub(crate) fn set_win_a(&mut self, id: ShiftCodecId, pos: i32) {
        if (0..32).contains(&pos) {
            self.codecs[id.0].win_a = pos;
        }
    }

    /// Returns window A position.
    #[allow(dead_code)]
    pub(crate) fn get_win_a(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].win_a
    }

    /// Sets window B position (0..31). Ignored if out of range.
    pub(crate) fn set_win_b(&mut self, id: ShiftCodecId, pos: i32) {
        if (0..32).contains(&pos) {
            self.codecs[id.0].win_b = pos;
        }
    }

    /// Returns window B position.
    #[allow(dead_code)]
    pub(crate) fn get_win_b(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].win_b
    }

    /// Sets the upchain reference.
    pub(crate) fn set_upchain(&mut self, id: ShiftCodecId, up: ShiftCodecId) {
        self.codecs[id.0].upchain = Some(up);
    }

    /// Sets the downchain reference.
    pub(crate) fn set_downchain(&mut self, id: ShiftCodecId, down: ShiftCodecId) {
        self.codecs[id.0].downchain = Some(down);
    }

    /// Sets both chain references.
    pub(crate) fn set_chain(&mut self, id: ShiftCodecId, up: ShiftCodecId, down: ShiftCodecId) {
        self.codecs[id.0].upchain = Some(up);
        self.codecs[id.0].downchain = Some(down);
    }

    /// Returns the entrada (last input) value.
    #[allow(dead_code)]
    pub(crate) fn get_entrada(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].entrada
    }

    /// Returns the salida (last output) value.
    #[allow(dead_code)]
    pub(crate) fn get_salida(&self, id: ShiftCodecId) -> i32 {
        self.codecs[id.0].salida
    }

    /// Swaps the shift register states of two ShiftCodecs.
    ///
    /// Used by the SeedHopping mechanism to permute states
    /// between ShiftCodecs after each block operation.
    pub(crate) fn swap_states(&mut self, a: ShiftCodecId, b: ShiftCodecId) {
        let state_a = self.codecs[a.0].shift_register;
        let state_b = self.codecs[b.0].shift_register;
        self.codecs[a.0].shift_register = state_b;
        self.codecs[b.0].shift_register = state_a;
    }
}

impl Drop for ShiftCodecArena {
    /// Securely clears all shift register states and seeds on drop.
    fn drop(&mut self) {
        for codec in self.codecs.iter_mut() {
            codec.seed = 0;
            codec.shift_register = 0;
            codec.entrada = 0;
            codec.salida = 0;
            codec.pos_up = 0;
            codec.pos_down = 0;
            codec.shift_leap = 0;
            codec.win_a = 0;
            codec.win_b = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_codec_default_values() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0x1234567890ABCDEF_u64 as i64);
        assert_eq!(arena.get_seed(id), 0x1234567890ABCDEF_u64 as i64);
        assert_eq!(arena.get_state(id), 0x1234567890ABCDEF_u64 as i64);
        assert_eq!(arena.get_pos_up(id), 5);
        assert_eq!(arena.get_pos_down(id), 15);
        assert_eq!(arena.get_shift_leap(id), 1);
        assert_eq!(arena.get_win_a(id), 9);
        assert_eq!(arena.get_win_b(id), 27);
    }

    #[test]
    fn test_set_seed_resets_register() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(100);
        arena.set_state(id, 999);
        assert_eq!(arena.get_state(id), 999);
        arena.set_seed(id, 200);
        assert_eq!(arena.get_seed(id), 200);
        assert_eq!(arena.get_state(id), 200);
    }

    #[test]
    fn test_reset() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(42);
        arena.set_state(id, 999);
        arena.reset(id);
        assert_eq!(arena.get_state(id), 42);
    }

    #[test]
    fn test_get_bits_valid() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0x0000_0000_FFFF_FFFF_u64 as i64);
        // At position 0, should return the low 32 bits
        let bits = arena.get_bits(id, 0);
        assert_eq!(bits, -1); // 0xFFFFFFFF as i32 = -1
    }

    #[test]
    fn test_get_bits_shifted() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0xAAAABBBBCCCCDDDD_u64 as i64);
        let bits_0 = arena.get_bits(id, 0);
        let bits_16 = arena.get_bits(id, 16);
        // At pos 0: (0xAAAABBBBCCCCDDDD >>> 0) truncated to i32 = 0xCCCCDDDD
        assert_eq!(bits_0, 0xCCCCDDDDu32 as i32);
        // At pos 16: (0xAAAABBBBCCCCDDDD >>> 16) truncated to i32 = 0xBBBBCCCC
        assert_eq!(bits_16, 0xBBBBCCCCu32 as i32);
    }

    #[test]
    fn test_get_bits_invalid_position() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0);
        assert_eq!(arena.get_bits(id, -1), -1);
        assert_eq!(arena.get_bits(id, 32), -1);
    }

    #[test]
    fn test_bits_codec_xor() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0x0000_0000_1234_5678_u64 as i64);
        let encoded = arena.bits_codec(id, 0x0000_FFFF);
        assert_eq!(encoded, 0x0000_FFFF ^ 0x1234_5678u32 as i32);
    }

    #[test]
    fn test_bits_codec_decodec_roundtrip() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0xDEADBEEF_CAFEBABE_u64 as i64);
        let original = 0x12345678;
        let encoded = arena.bits_codec(id, original);
        // Reset state so decodec uses same register value
        arena.reset(id);
        let decoded = arena.bits_decodec(id, encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_shift_cdec_deterministic() {
        // Create a ring of 4 codecs
        let mut arena = ShiftCodecArena::new();
        let c0 = arena.new_codec(100);
        let c1 = arena.new_codec(200);
        let c2 = arena.new_codec(300);
        let c3 = arena.new_codec(400);

        // Ring: 0->1->2->3->0 (upchain), 0->3->2->1->0 (downchain)
        arena.set_chain(c0, c1, c3);
        arena.set_chain(c1, c2, c0);
        arena.set_chain(c2, c3, c1);
        arena.set_chain(c3, c0, c2);

        // Encode something first to set entrada
        arena.bits_codec(c0, 42);
        arena.bits_codec(c1, 84);
        arena.bits_codec(c2, 126);
        arena.bits_codec(c3, 168);

        // Capture states
        let s0_before = arena.get_state(c0);

        // Advance
        arena.shift_cdec(c0);

        let s0_after = arena.get_state(c0);
        assert_ne!(s0_before, s0_after, "State should change after shift");

        // Second instance with same setup should produce same result
        let mut arena2 = ShiftCodecArena::new();
        let d0 = arena2.new_codec(100);
        let d1 = arena2.new_codec(200);
        let d2 = arena2.new_codec(300);
        let d3 = arena2.new_codec(400);
        arena2.set_chain(d0, d1, d3);
        arena2.set_chain(d1, d2, d0);
        arena2.set_chain(d2, d3, d1);
        arena2.set_chain(d3, d0, d2);
        arena2.bits_codec(d0, 42);
        arena2.bits_codec(d1, 84);
        arena2.bits_codec(d2, 126);
        arena2.bits_codec(d3, 168);
        arena2.shift_cdec(d0);

        assert_eq!(arena.get_state(c0), arena2.get_state(d0));
    }

    #[test]
    fn test_set_pos_up_validation() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0);
        arena.set_pos_up(id, 31);
        assert_eq!(arena.get_pos_up(id), 31);
        arena.set_pos_up(id, 32); // out of range
        assert_eq!(arena.get_pos_up(id), 29); // default
        arena.set_pos_up(id, -1); // negative
        assert_eq!(arena.get_pos_up(id), 29); // default
    }

    #[test]
    fn test_set_shift_leap_validation() {
        let mut arena = ShiftCodecArena::new();
        let id = arena.new_codec(0);
        arena.set_shift_leap(id, 7);
        assert_eq!(arena.get_shift_leap(id), 7);
        arena.set_shift_leap(id, 0); // out of range
        assert_eq!(arena.get_shift_leap(id), 7); // default
        arena.set_shift_leap(id, 15); // out of range
        assert_eq!(arena.get_shift_leap(id), 7); // default
        arena.set_shift_leap(id, 14); // max valid
        assert_eq!(arena.get_shift_leap(id), 14);
    }

    #[test]
    fn test_swap_states() {
        let mut arena = ShiftCodecArena::new();
        let a = arena.new_codec(111);
        let b = arena.new_codec(222);
        arena.swap_states(a, b);
        assert_eq!(arena.get_state(a), 222);
        assert_eq!(arena.get_state(b), 111);
    }

    #[test]
    fn test_arena_len() {
        let mut arena = ShiftCodecArena::new();
        assert_eq!(arena.len(), 0);
        arena.new_codec(1);
        assert_eq!(arena.len(), 1);
        arena.new_codec(2);
        assert_eq!(arena.len(), 2);
    }
}
